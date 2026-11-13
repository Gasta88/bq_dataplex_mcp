"""BigQuery client for metadata discovery and read-only SQL execution.

Wraps `google.cloud.bigquery.Client` with the tool-facing methods
`list_datasets`, `list_tables`, `get_table_metadata`, and `execute_sql`.
`execute_sql` applies a maximum-bytes-billed cap, an optional flat-rate
reservation, and a job timeout, and reports bytes processed plus an
on-demand-equivalent cost estimate.

SQL validation is the caller's responsibility: `app/main.py`'s `execute_sql`
tool runs `validate_sql_query` before delegating here.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from google.cloud import bigquery

from app.config import settings
from app.pricing import estimate_cost_usd
from app.validation import redact_credentials_from_text, sanitize_error_message

# 100 GiB -- matches the reference implementation's `DEFAULT_MAX_BYTES_BILLED =
# '107374182400'` exactly. The Python SDK's `maximum_bytes_billed` setter
# takes an `int`, unlike the reference client library's `string`-typed REST field.
_DEFAULT_MAX_BYTES_BILLED = 107_374_182_400

# 2 minutes -- matches the reference implementation's `DEFAULT_JOB_TIMEOUT_MS` exactly.
_DEFAULT_JOB_TIMEOUT_MS = 120_000


def _reraise_sanitized(exc: Exception) -> None:
    """Rewrite `exc`'s message in place (credentials-file-path redaction),
    then re-raise the *same* exception object/type via a bare `raise` at the
    call site -- preserves the original GCP SDK exception class (e.g.
    `google.api_core.exceptions.NotFound`) so callers can still catch it
    specifically, per the "re-raise ... rather than swallowing or reshaping
    them" requirement.

    `google.api_core.exceptions.GoogleAPICallError` subclasses build their
    `__str__` from `self.message`, not `self.args`; plain-Python exceptions
    (e.g. a bare `ValueError`) use `self.args`. Both are rewritten here so
    `str(exc)` reflects the sanitized text either way.

    For GoogleAPICallError subclasses, sanitize `exc.message` directly
    (not via `str(exc)`) to avoid double-prefixing the error code, since
    `__str__` prepends `self.code` to `self.message` each time it's called.
    For plain exceptions without `.message`, sanitize `str(exc)` as before
    since they don't have the double-prefix problem.
    """
    if hasattr(exc, "message"):
        # GoogleAPICallError and similar: sanitize message directly.
        exc.message = redact_credentials_from_text(exc.message)  # type: ignore[attr-defined]
    # For all exceptions (with or without .message), also update args for completeness.
    sanitized = sanitize_error_message(exc)
    exc.args = (sanitized, *exc.args[1:])


def _format_js_iso(dt: datetime) -> str:
    """Format a UTC-aware `datetime` to match JS `Date.prototype.toISOString()`:
    millisecond-precision, trailing `Z` (not `+00:00`).
    """
    from datetime import timezone

    dt_utc = dt.astimezone(timezone.utc)
    return dt_utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt_utc.microsecond // 1000:03d}Z"


class BigQueryClient:
    """Thin wrapper around `google.cloud.bigquery.Client` for read-only
    BigQuery metadata calls. Instantiating this class builds a real
    `bigquery.Client` immediately -- callers (i.e. `app/main.py`'s
    `_get_bq_client()`) are responsible for deferring construction until
    first use so module import never triggers ADC resolution.
    """

    def __init__(self, project_id: str, location: str, reservation: str) -> None:
        try:
            self._client = bigquery.Client(project=project_id or None, location=location or None)
        except Exception as exc:
            _reraise_sanitized(exc)
            raise
        self.project_id = project_id
        self.location = location
        self.reservation = reservation

    def list_datasets(self) -> list[str]:
        try:
            return [dataset.dataset_id for dataset in self._client.list_datasets()]
        except Exception as exc:
            _reraise_sanitized(exc)
            raise

    def list_tables(self, dataset_id: str) -> list[str]:
        try:
            return [table.table_id for table in self._client.list_tables(dataset_id)]
        except Exception as exc:
            _reraise_sanitized(exc)
            raise

    def get_table_metadata(self, dataset_id: str, table_id: str) -> dict[str, Any]:
        try:
            table = self._client.get_table(f"{self._client.project}.{dataset_id}.{table_id}")
        except Exception as exc:
            _reraise_sanitized(exc)
            raise

        time_partitioning = table.time_partitioning
        range_partitioning = table.range_partitioning

        if time_partitioning is not None:
            partitioning_type = time_partitioning.type_
        elif range_partitioning is not None:
            partitioning_type = "RANGE"
        else:
            partitioning_type = None

        if time_partitioning is not None and time_partitioning.field:
            partitioning_field = time_partitioning.field
        elif range_partitioning is not None and range_partitioning.field:
            partitioning_field = range_partitioning.field
        else:
            partitioning_field = None

        schema_fields = [
            {
                "name": field.name,
                "type": field.field_type,
                "mode": field.mode or "NULLABLE",
                "description": field.description or None,
            }
            for field in (table.schema or [])
        ]

        return {
            "tableId": table_id,
            "datasetId": dataset_id,
            "projectId": self._client.project,
            "description": table.description or None,
            "schema": {"fields": schema_fields},
            "clustering": {"fields": table.clustering_fields or None},
            "partitioning": {
                "type": partitioning_type,
                "field": partitioning_field,
                "requirePartitionFilter": bool(table.require_partition_filter),
            },
            "labels": table.labels or {},
            "numRows": str(table.num_rows if table.num_rows is not None else 0),
            "numBytes": str(table.num_bytes if table.num_bytes is not None else 0),
            "creationTime": _format_js_iso(table.created),
            "lastModifiedTime": _format_js_iso(table.modified),
        }

    def execute_sql(
        self,
        query: str,
        max_rows: int | None = None,
        max_bytes_billed: str | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Run a read-only SQL query (or estimate its cost via `dry_run`).

        Does not itself call `validate_sql_query` -- see module docstring.
        Mirrors the reference implementation's `BigQueryClient.executeSql` field-for-field
        `maximum_bytes_billed` cap (always applied), reservation
        routing (only when `self.reservation` is truthy), and a
        `QueryResult`/`DryRunResult`-shaped return value.
        """
        try:
            # Parse max_bytes_billed inside try/except so parsing errors are sanitized.
            max_bytes_billed_int = (
                int(max_bytes_billed) if max_bytes_billed is not None else _DEFAULT_MAX_BYTES_BILLED
            )

            job_config = bigquery.QueryJobConfig(
                use_legacy_sql=False,
                dry_run=dry_run,
                maximum_bytes_billed=max_bytes_billed_int,
                job_timeout_ms=_DEFAULT_JOB_TIMEOUT_MS,
            )
            if self.reservation:
                job_config.reservation = self.reservation

            job = self._client.query(query, job_config=job_config, location=self.location or None)

            if dry_run:
                total_bytes_processed = (
                    job.total_bytes_processed if job.total_bytes_processed is not None else 0
                )
                return {
                    "dryRun": True,
                    "totalBytesProcessed": str(total_bytes_processed),
                    "estimatedGiB": total_bytes_processed / 1024**3,
                    "estimatedCostUsd": estimate_cost_usd(
                        total_bytes_processed, settings.bq_price_per_tib_usd
                    ),
                }

            result = job.result(max_results=max_rows or 1000)
            rows = [dict(row) for row in result]
            schema = [
                {"name": field.name, "type": field.field_type, "mode": field.mode or "NULLABLE"}
                for field in result.schema
            ]
        except Exception as exc:
            _reraise_sanitized(exc)
            raise

        total_bytes_processed = (
            job.total_bytes_processed if job.total_bytes_processed is not None else 0
        )

        return {
            "rows": rows,
            "rowCount": len(rows),
            "schema": schema,
            "totalBytesProcessed": str(total_bytes_processed),
            "cacheHit": bool(job.cache_hit),
            "jobId": job.job_id,
            "estimatedCostUsd": estimate_cost_usd(
                total_bytes_processed, settings.bq_price_per_tib_usd
            ),
        }
