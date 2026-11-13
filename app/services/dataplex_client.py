"""Dataplex client for data-quality scan results.

Exposes only `get_data_quality_results`, backed by
`google.cloud.dataplex_v1.DataScanServiceClient`. Catalog-search methods
(`search_entries`, `lookup_entry`, `search_aspect_types`) are intentionally out
of scope.
"""

from __future__ import annotations

from typing import Any

from google.api_core.exceptions import NotFound
from google.cloud import dataplex_v1

# Matches the reference implementation's `constructor(projectId, location = 'us-central1')`
# default exactly.
_DEFAULT_LOCATION = "us-central1"

# the reference implementation's exact error message text for the gRPC-code-5 branch -- the
# source's own comment reads "Please ensure Dataplex API is enabled" even
# though gRPC code 5 is NOT_FOUND, not PERMISSION_DENIED(7)/UNIMPLEMENTED(12)
# (which would more naturally mean "API not enabled"). Ported exactly as
# written, comment/code mismatch included -- see the design notes'
# Requirements step 13 / Risks table.
_DATA_SCAN_API_ERROR_MESSAGE = (
    "Data Scan API error. Please ensure Dataplex API is enabled and "
    "the service account has appropriate permissions."
)


class DataplexClient:
    """Thin wrapper around `google.cloud.dataplex_v1.DataScanServiceClient`
    for BigQuery table data-quality scan-result lookups. Instantiating this
    class builds a real `DataScanServiceClient` immediately (resolves ADC
    synchronously) -- callers (`app/main.py`'s `_get_dataplex_client()`) are
    responsible for deferring construction until first use, mirroring
    `BigQueryClient`/`LineageClient`'s existing pattern.
    """

    def __init__(self, project_id: str, location: str = _DEFAULT_LOCATION) -> None:
        self._client = dataplex_v1.DataScanServiceClient()
        self.project_id = project_id
        self.location = location

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_data_quality_results(
        self, dataset_id: str, table_id: str
    ) -> dict[str, Any] | None:
        """Returns a `DataQualityResult`-shaped dict (`scanName`, `tableId`,
        `datasetId`, `executionTime`, `passed`, `dimensions`, `rowCount`) for
        the given BigQuery table's latest data-quality scan, or `None` if no
        DataScan is configured for the table, or a matching scan exists but
        has no `data_quality_result` yet.

        Raises a domain error with the reference implementation's exact "Data Scan API
        error..." message when the underlying calls fail with a `NotFound`
        (gRPC code 5); any other exception re-raises unchanged, matching the
        the reference implementation's own `throw error;` fallthrough.
        """
        try:
            parent = f"projects/{self.project_id}/locations/{self.location}"
            # `list_data_scans` returns a `ListDataScansPager` -- iterating it
            # (via the generator expression below) auto-paginates across all
            # pages, matching the reference implementation's own default-autopaginate
            # behavior (it does not pass `{ autoPaginate: false }` here,
            # unlike `searchEntries`/`searchAspectTypes` elsewhere in the same
            # reference file).
            data_scans = self._client.list_data_scans(parent=parent)

            table_resource = (
                f"//bigquery.googleapis.com/projects/{self.project_id}"
                f"/datasets/{dataset_id}/tables/{table_id}"
            )
            # First-match-wins, not filtered by scan type -- see module
            # docstring's field-mapping rules and the risks section.
            matching_scan = next(
                (scan for scan in data_scans if scan.data.resource == table_resource),
                None,
            )

            if matching_scan is None:
                return None  # No scan configured for this table.

            # Results live only on the full `DataScan` resource, not on
            # individual `DataScanJob`s -- re-fetch at `FULL` view (the
            # client library's own default is `BASIC`, which would not
            # populate `data_quality_result`).
            #
            # NOTE: `get_data_scan`'s generated method signature only
            # flattens `name` as a keyword argument (confirmed live via
            # `inspect.signature` against the installed 2.20.0 client --
            # `view` is *not* a flattened kwarg, unlike `list_data_scans`'s
            # `parent`); passing `view=` directly raises `TypeError:
            # got an unexpected keyword argument 'view'`. A full
            # `GetDataScanRequest` must be built and passed as `request=`.
            scan_name = matching_scan.name
            full_scan = self._client.get_data_scan(
                request=dataplex_v1.GetDataScanRequest(
                    name=scan_name,
                    view=dataplex_v1.GetDataScanRequest.DataScanView.FULL,
                )
            )

            # `data_quality_result` is a proto oneof (`result`) member --
            # presence must be checked via `in`, not truthiness/`is None`
            # (see module docstring).
            if "data_quality_result" not in full_scan:
                return None  # No data quality results available yet.

            result = full_scan.data_quality_result

            dimensions = [
                {
                    # `"dimension" in dim` mirrors the same oneof/message-
                    # presence idiom as `data_quality_result` above --
                    # `dim.dimension` is a `DataQualityDimension` message
                    # (`{name: str}`), so the real dimension name lives at
                    # `dim.dimension.name` (see module docstring's 
                    # section for why this replaced the prior "[object
                    # Object]" literal).
                    "dimension": dim.dimension.name if "dimension" in dim else "Unknown",
                    "passed": dim.passed or False,
                    "score": dim.score or 0,
                }
                for dim in result.dimensions
            ]

            # `execution_status` is itself a proto message/oneof-adjacent
            # field -- a bare `DataScan()` does not have it set at all, so
            # presence must be checked via `in`, not truthiness, mirroring
            # the `"data_quality_result" in full_scan` idiom above.
            # `latest_job_end_time` resolves to `None` (not a zero-value
            # `Timestamp`) when unset within a present `execution_status`
            # -- both sub-cases
            # fall through to the same "Unknown" fallback.
            execution_time = "Unknown"
            if "execution_status" in full_scan:
                latest_job_end_time = full_scan.execution_status.latest_job_end_time
                if latest_job_end_time is not None:
                    execution_time = latest_job_end_time.rfc3339()

            return {
                "scanName": matching_scan.display_name or scan_name,
                "tableId": table_id,
                "datasetId": dataset_id,
                "executionTime": execution_time,
                "passed": result.passed or False,
                "dimensions": dimensions,
                # Plain int64 field, no protobufjs Long/string conversion
                # needed (the installed Python client already returns a
                # native Python int) -- only the same `or 0` fallback is kept
                # for symmetry with the reference implementation's `Number(...) || 0`.
                "rowCount": int(result.row_count) or 0,
            }
        except Exception as exc:
            if isinstance(exc, NotFound):
                raise RuntimeError(_DATA_SCAN_API_ERROR_MESSAGE) from exc
            raise
