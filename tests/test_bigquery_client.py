"""Tests for app/services/cache_service.py (CacheService) and
app/services/bigquery_client.py (BigQueryClient). `google.cloud.bigquery.Client`
is mocked throughout -- no live GCP calls, no credentials needed.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from google.api_core.exceptions import InternalServerError, NotFound

from app.config import settings
from app.services.bigquery_client import BigQueryClient
from app.services.cache_service import CacheService

# ---------------------------------------------------------------------------
# CacheService
# ---------------------------------------------------------------------------


def test_cache_service_get_set_has_clear_when_enabled():
    cache = CacheService(enabled=True)

    assert cache.get("k") is None
    assert cache.has("k") is False

    cache.set("k", [1, 2, 3])
    assert cache.get("k") == [1, 2, 3]
    assert cache.has("k") is True

    cache.clear()
    assert cache.get("k") is None
    assert cache.has("k") is False


def test_cache_service_is_a_no_op_when_disabled():
    cache = CacheService(enabled=False)

    cache.set("k", "value")

    assert cache.get("k") is None
    assert cache.has("k") is False


def test_cache_service_clear_always_clears_regardless_of_enabled_flag():
    # Mirrors the reference implementation's clear(), which has no `enabled` guard.
    cache = CacheService(enabled=True)
    cache.set("k", "v")
    cache._enabled = False  # simulate a disabled cache with pre-existing data
    cache.clear()
    cache._enabled = True
    assert cache.get("k") is None


def test_cache_service_generate_key_single_part():
    cache = CacheService()
    assert cache.generate_key("datasets") == "datasets"


def test_cache_service_generate_key_multiple_parts():
    cache = CacheService()
    assert cache.generate_key("tables", "analytics") == "tables:analytics"


# ---------------------------------------------------------------------------
# BigQueryClient
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_bq_client():
    with patch("app.services.bigquery_client.bigquery.Client") as mock_ctor:
        yield mock_ctor.return_value


def _make_client(
    mock_bq_client,
    project_id: str = "example-project",
    reservation: str = "",
) -> BigQueryClient:
    mock_bq_client.project = project_id
    return BigQueryClient(project_id, "us-central1", reservation)


def test_list_datasets_returns_ids_in_api_order(mock_bq_client):
    ds1 = MagicMock(dataset_id="analytics")
    ds2 = MagicMock(dataset_id="raw_events")
    mock_bq_client.list_datasets.return_value = [ds1, ds2]

    client = _make_client(mock_bq_client)

    assert client.list_datasets() == ["analytics", "raw_events"]


def test_list_datasets_returns_empty_list_when_project_has_no_datasets(mock_bq_client):
    mock_bq_client.list_datasets.return_value = []

    client = _make_client(mock_bq_client)

    assert client.list_datasets() == []


def test_list_tables_returns_ids_in_api_order(mock_bq_client):
    t1 = MagicMock(table_id="daily_active_users")
    t2 = MagicMock(table_id="revenue_by_country")
    mock_bq_client.list_tables.return_value = [t1, t2]

    client = _make_client(mock_bq_client)

    assert client.list_tables("analytics") == ["daily_active_users", "revenue_by_country"]


def test_list_tables_returns_empty_list_for_dataset_with_zero_tables(mock_bq_client):
    mock_bq_client.list_tables.return_value = []

    client = _make_client(mock_bq_client)

    assert client.list_tables("empty_dataset") == []


def test_list_datasets_propagates_permission_denied(mock_bq_client):
    from google.api_core.exceptions import PermissionDenied

    mock_bq_client.list_datasets.side_effect = PermissionDenied("no access to project")

    client = _make_client(mock_bq_client)

    with pytest.raises(PermissionDenied):
        client.list_datasets()


def test_get_table_metadata_propagates_not_found_for_nonexistent_table(mock_bq_client):
    mock_bq_client.get_table.side_effect = NotFound("table bogus not found")

    client = _make_client(mock_bq_client)

    with pytest.raises(NotFound):
        client.get_table_metadata("ds", "bogus")


def test_list_tables_propagates_not_found_for_nonexistent_dataset(mock_bq_client):
    mock_bq_client.list_tables.side_effect = NotFound("dataset bogus not found")

    client = _make_client(mock_bq_client)

    with pytest.raises(NotFound):
        client.list_tables("bogus")


def test_list_tables_sanitizes_credentials_path_in_reraised_exception(mock_bq_client):
    mock_bq_client.list_tables.side_effect = NotFound(
        "dataset bogus not found, see /Users/foo/creds.json"
    )

    client = _make_client(mock_bq_client)

    with pytest.raises(NotFound) as exc_info:
        client.list_tables("bogus")

    assert "[credentials file]" in str(exc_info.value)
    assert "creds.json" not in str(exc_info.value)


def test_list_tables_does_not_double_prefix_error_code_after_sanitization(mock_bq_client):
    """Regression test: GoogleAPICallError's __str__ prepends self.code to
    self.message each time it's called. Ensure sanitization applies directly
    to exc.message (not str(exc)) to avoid code duplication like "404 404 ...".
    """
    mock_bq_client.list_tables.side_effect = NotFound(
        "dataset bogus not found, see /Users/foo/creds.json"
    )

    client = _make_client(mock_bq_client)

    with pytest.raises(NotFound) as exc_info:
        client.list_tables("bogus")

    error_str = str(exc_info.value)
    # The error code should appear exactly once, not twice like "404 404 ...".
    assert error_str.count("404") == 1, f"Error code appears {error_str.count('404')} times in: {error_str}"


def _fake_table(
    *,
    schema=None,
    description=None,
    clustering_fields=None,
    time_partitioning=None,
    range_partitioning=None,
    require_partition_filter=False,
    labels=None,
    num_rows=None,
    num_bytes=None,
    created=None,
    modified=None,
):
    table = MagicMock()
    table.schema = schema or []
    table.description = description
    table.clustering_fields = clustering_fields
    table.time_partitioning = time_partitioning
    table.range_partitioning = range_partitioning
    table.require_partition_filter = require_partition_filter
    table.labels = labels
    table.num_rows = num_rows
    table.num_bytes = num_bytes
    table.created = created or datetime(2026, 1, 1, tzinfo=timezone.utc)
    table.modified = modified or datetime(2026, 1, 1, tzinfo=timezone.utc)
    return table


def _fake_field(name, field_type, mode=None, description=None):
    field = MagicMock()
    field.name = name
    field.field_type = field_type
    field.mode = mode
    field.description = description
    return field


def test_get_table_metadata_matches_api_contracts_example(mock_bq_client):
    time_partitioning = MagicMock(type_="DAY", field="date")
    table = _fake_table(
        schema=[
            _fake_field("date", "DATE", mode="REQUIRED"),
            _fake_field("platform", "STRING", mode="NULLABLE", description="ios | android"),
        ],
        description="Daily active user counts by platform",
        clustering_fields=["platform"],
        time_partitioning=time_partitioning,
        require_partition_filter=True,
        labels={"team": "data-engineering"},
        num_rows=1234567,
        num_bytes=98765432,
        created=datetime(2026, 1, 15, 9, 0, 0, 0, tzinfo=timezone.utc),
        modified=datetime(2026, 7, 20, 4, 12, 33, 500000, tzinfo=timezone.utc),
    )
    mock_bq_client.get_table.return_value = table

    client = _make_client(mock_bq_client)
    result = client.get_table_metadata("analytics", "daily_active_users")

    assert result == {
        "tableId": "daily_active_users",
        "datasetId": "analytics",
        "projectId": "example-project",
        "description": "Daily active user counts by platform",
        "schema": {
            "fields": [
                {"name": "date", "type": "DATE", "mode": "REQUIRED", "description": None},
                {
                    "name": "platform",
                    "type": "STRING",
                    "mode": "NULLABLE",
                    "description": "ios | android",
                },
            ]
        },
        "clustering": {"fields": ["platform"]},
        "partitioning": {"type": "DAY", "field": "date", "requirePartitionFilter": True},
        "labels": {"team": "data-engineering"},
        "numRows": "1234567",
        "numBytes": "98765432",
        "creationTime": "2026-01-15T09:00:00.000Z",
        "lastModifiedTime": "2026-07-20T04:12:33.500Z",
    }


def test_get_table_metadata_num_rows_and_num_bytes_are_strings(mock_bq_client):
    table = _fake_table(num_rows=42, num_bytes=1024)
    mock_bq_client.get_table.return_value = table

    client = _make_client(mock_bq_client)
    result = client.get_table_metadata("ds", "tbl")

    assert isinstance(result["numRows"], str)
    assert isinstance(result["numBytes"], str)
    assert result["numRows"] == "42"
    assert result["numBytes"] == "1024"


def test_get_table_metadata_creation_and_modified_time_match_js_iso_format(mock_bq_client):
    table = _fake_table(
        created=datetime(2026, 3, 4, 5, 6, 7, 8000, tzinfo=timezone.utc),
        modified=datetime(2026, 3, 4, 5, 6, 7, 8000, tzinfo=timezone.utc),
    )
    mock_bq_client.get_table.return_value = table

    client = _make_client(mock_bq_client)
    result = client.get_table_metadata("ds", "tbl")

    assert result["creationTime"] == "2026-03-04T05:06:07.008Z"
    assert result["lastModifiedTime"] == "2026-03-04T05:06:07.008Z"
    assert "+00:00" not in result["creationTime"]


def test_get_table_metadata_partitioning_type_is_range_when_only_range_partitioned(
    mock_bq_client,
):
    range_partitioning = MagicMock(field="id")
    table = _fake_table(time_partitioning=None, range_partitioning=range_partitioning)
    mock_bq_client.get_table.return_value = table

    client = _make_client(mock_bq_client)
    result = client.get_table_metadata("ds", "tbl")

    assert result["partitioning"]["type"] == "RANGE"
    assert result["partitioning"]["field"] == "id"


def test_get_table_metadata_partitioning_is_null_when_not_partitioned(mock_bq_client):
    table = _fake_table(time_partitioning=None, range_partitioning=None)
    mock_bq_client.get_table.return_value = table

    client = _make_client(mock_bq_client)
    result = client.get_table_metadata("ds", "tbl")

    assert result["partitioning"] == {
        "type": None,
        "field": None,
        "requirePartitionFilter": False,
    }


def test_get_table_metadata_clustering_fields_is_none_when_not_clustered(mock_bq_client):
    table = _fake_table(clustering_fields=None)
    mock_bq_client.get_table.return_value = table

    client = _make_client(mock_bq_client)
    result = client.get_table_metadata("ds", "tbl")

    assert result["clustering"]["fields"] is None


def test_get_table_metadata_description_and_labels_default_when_unset(mock_bq_client):
    table = _fake_table(description=None, labels=None)
    mock_bq_client.get_table.return_value = table

    client = _make_client(mock_bq_client)
    result = client.get_table_metadata("ds", "tbl")

    assert result["description"] is None
    assert result["labels"] == {}
    assert result["schema"]["fields"] == []


def test_get_table_metadata_schema_field_description_defaults_to_none(mock_bq_client):
    table = _fake_table(schema=[_fake_field("col", "STRING", description=None)])
    mock_bq_client.get_table.return_value = table

    client = _make_client(mock_bq_client)
    result = client.get_table_metadata("ds", "tbl")

    assert result["schema"]["fields"] == [
        {"name": "col", "type": "STRING", "mode": "NULLABLE", "description": None}
    ]


# ---------------------------------------------------------------------------
# BigQueryClient.execute_sql
# ---------------------------------------------------------------------------


def _fake_row_iterator(rows, schema_fields):
    """Builds a fake object mimicking `google.cloud.bigquery.table.RowIterator`
    just enough for `execute_sql`'s field-mapping: iterable of dict-like rows
    plus a `.schema` attribute of fake `SchemaField`-like objects."""
    iterator = MagicMock()
    iterator.__iter__.return_value = iter(rows)
    iterator.schema = [
        _fake_field(name, field_type, mode) for name, field_type, mode in schema_fields
    ]
    return iterator


def _fake_query_job(
    *,
    total_bytes_processed=1000,
    cache_hit=False,
    job_id="bquxjob_1234abcd_98765",
    rows=None,
    schema_fields=None,
):
    job = MagicMock()
    job.total_bytes_processed = total_bytes_processed
    job.cache_hit = cache_hit
    job.job_id = job_id
    job.result.return_value = _fake_row_iterator(rows or [], schema_fields or [])
    return job


def test_execute_sql_dry_run_returns_dry_run_result_shape(mock_bq_client, monkeypatch):
    monkeypatch.setattr(settings, "bq_price_per_tib_usd", 6.25)
    fake_job = _fake_query_job(total_bytes_processed=1_048_576)
    mock_bq_client.query.return_value = fake_job

    client = _make_client(mock_bq_client)
    result = client.execute_sql("SELECT 1", dry_run=True)

    assert result == {
        "dryRun": True,
        "totalBytesProcessed": "1048576",
        "estimatedGiB": 1_048_576 / 1024**3,
        "estimatedCostUsd": pytest.approx(1_048_576 / 1024**4 * 6.25),
    }
    fake_job.result.assert_not_called()


def test_execute_sql_real_run_matches_query_result_shape(mock_bq_client, monkeypatch):
    monkeypatch.setattr(settings, "bq_price_per_tib_usd", 6.25)
    fake_job = _fake_query_job(
        total_bytes_processed=1_048_576,
        cache_hit=False,
        job_id="bquxjob_1234abcd_98765",
        rows=[{"date": "2026-07-20", "platform": "ios"}, {"date": "2026-07-20", "platform": "android"}],
        schema_fields=[("date", "DATE", "NULLABLE"), ("platform", "STRING", "NULLABLE")],
    )
    mock_bq_client.query.return_value = fake_job

    client = _make_client(mock_bq_client)
    result = client.execute_sql("SELECT date, platform FROM t")

    assert result == {
        "rows": [
            {"date": "2026-07-20", "platform": "ios"},
            {"date": "2026-07-20", "platform": "android"},
        ],
        "rowCount": 2,
        "schema": [
            {"name": "date", "type": "DATE", "mode": "NULLABLE"},
            {"name": "platform", "type": "STRING", "mode": "NULLABLE"},
        ],
        "totalBytesProcessed": "1048576",
        "cacheHit": False,
        "jobId": "bquxjob_1234abcd_98765",
        "estimatedCostUsd": pytest.approx(1_048_576 / 1024**4 * 6.25),
    }


def test_execute_sql_dry_run_estimated_cost_usd_uses_configured_price(
    mock_bq_client, monkeypatch
):
    """: estimatedCostUsd scales linearly with the live-configured
    price, not a hardcoded constant (catches a hardcoded-price regression)."""
    fake_job = _fake_query_job(total_bytes_processed=1_048_576)
    mock_bq_client.query.return_value = fake_job
    client = _make_client(mock_bq_client)

    monkeypatch.setattr(settings, "bq_price_per_tib_usd", 6.25)
    result_a = client.execute_sql("SELECT 1", dry_run=True)

    monkeypatch.setattr(settings, "bq_price_per_tib_usd", 12.5)
    result_b = client.execute_sql("SELECT 1", dry_run=True)

    assert result_b["estimatedCostUsd"] == pytest.approx(result_a["estimatedCostUsd"] * 2)


def test_execute_sql_estimated_cost_usd_present_regardless_of_reservation(
    mock_bq_client, monkeypatch
):
    """ FR7: presence/computation of estimatedCostUsd must not vary
    based on whether a reservation is configured -- the interpretation
    caveat lives in the docstring, not a code-level branch."""
    monkeypatch.setattr(settings, "bq_price_per_tib_usd", 6.25)
    fake_job = _fake_query_job(total_bytes_processed=1_048_576)
    mock_bq_client.query.return_value = fake_job

    reservation = "projects/example-project/locations/us-central1/reservations/example-reservation"
    client = _make_client(mock_bq_client, reservation=reservation)
    result = client.execute_sql("SELECT 1", dry_run=True)

    assert result["estimatedCostUsd"] == pytest.approx(1_048_576 / 1024**4 * 6.25)


def test_execute_sql_estimated_cost_usd_zero_bytes_dry_run(mock_bq_client, monkeypatch):
    monkeypatch.setattr(settings, "bq_price_per_tib_usd", 6.25)
    fake_job = _fake_query_job(total_bytes_processed=0)
    mock_bq_client.query.return_value = fake_job

    client = _make_client(mock_bq_client)
    result = client.execute_sql("SELECT 1", dry_run=True)

    assert result["estimatedCostUsd"] == 0.0


def test_execute_sql_never_sets_job_config_reservation_when_client_reservation_is_falsy(
    mock_bq_client,
):
    fake_job = _fake_query_job()
    mock_bq_client.query.return_value = fake_job

    client = _make_client(mock_bq_client, reservation="")
    client.execute_sql("SELECT 1")

    job_config = mock_bq_client.query.call_args.kwargs["job_config"]
    assert job_config.reservation is None


def test_execute_sql_sets_job_config_reservation_to_configured_value(mock_bq_client):
    fake_job = _fake_query_job()
    mock_bq_client.query.return_value = fake_job

    reservation = "projects/example-project/locations/us-central1/reservations/example-reservation"
    client = _make_client(mock_bq_client, reservation=reservation)
    client.execute_sql("SELECT 1")

    job_config = mock_bq_client.query.call_args.kwargs["job_config"]
    assert job_config.reservation == reservation


def test_execute_sql_max_bytes_billed_defaults_to_100_gib_when_omitted(mock_bq_client):
    fake_job = _fake_query_job()
    mock_bq_client.query.return_value = fake_job

    client = _make_client(mock_bq_client)
    client.execute_sql("SELECT 1")

    job_config = mock_bq_client.query.call_args.kwargs["job_config"]
    assert job_config.maximum_bytes_billed == 107_374_182_400


def test_execute_sql_max_bytes_billed_override_is_passed_through_as_int(mock_bq_client):
    fake_job = _fake_query_job()
    mock_bq_client.query.return_value = fake_job

    client = _make_client(mock_bq_client)
    client.execute_sql("SELECT 1", max_bytes_billed="500")

    job_config = mock_bq_client.query.call_args.kwargs["job_config"]
    assert job_config.maximum_bytes_billed == 500


def test_execute_sql_job_timeout_ms_and_use_legacy_sql_are_regression_tested_constants(
    mock_bq_client,
):
    fake_job = _fake_query_job()
    mock_bq_client.query.return_value = fake_job

    client = _make_client(mock_bq_client)

    # Real run. Note: the installed SDK's `QueryJobConfig.job_timeout_ms`
    # getter returns a `str` (the REST API's own wire type), even though the
    # setter/constructor accepts an `int` -- confirmed live this session.
    client.execute_sql("SELECT 1")
    job_config = mock_bq_client.query.call_args.kwargs["job_config"]
    assert int(job_config.job_timeout_ms) == 120_000
    assert job_config.use_legacy_sql is False

    # Dry run.
    client.execute_sql("SELECT 1", dry_run=True)
    job_config = mock_bq_client.query.call_args.kwargs["job_config"]
    assert int(job_config.job_timeout_ms) == 120_000
    assert job_config.use_legacy_sql is False


def test_execute_sql_max_rows_defaults_to_1000_and_is_passed_to_job_result(mock_bq_client):
    fake_job = _fake_query_job()
    mock_bq_client.query.return_value = fake_job

    client = _make_client(mock_bq_client)
    client.execute_sql("SELECT 1")

    fake_job.result.assert_called_once_with(max_results=1000)


def test_execute_sql_max_rows_override_is_passed_to_job_result(mock_bq_client):
    fake_job = _fake_query_job()
    mock_bq_client.query.return_value = fake_job

    client = _make_client(mock_bq_client)
    client.execute_sql("SELECT 1", max_rows=25)

    fake_job.result.assert_called_once_with(max_results=25)


def test_execute_sql_propagates_sanitized_exception_from_client_query(mock_bq_client):
    mock_bq_client.query.side_effect = NotFound(
        "table bogus not found, see /Users/foo/creds.json"
    )

    client = _make_client(mock_bq_client)

    with pytest.raises(NotFound) as exc_info:
        client.execute_sql("SELECT * FROM bogus")

    assert "[credentials file]" in str(exc_info.value)
    assert "creds.json" not in str(exc_info.value)


def test_execute_sql_over_max_bytes_billed_raises_sanitized_internal_server_error(
    mock_bq_client,
):
    """Pins the observed exception class for a query that exceeds
    `maximum_bytes_billed`: `google.api_core.exceptions.InternalServerError`
    (HTTP 500, `reason: bytesBilledLimitExceeded`). `_reraise_sanitized`'s
    catch-all means behavior never depended on this exact class, but pinning
    it catches a future SDK change that narrows or renames the error."""
    mock_bq_client.query.side_effect = InternalServerError(
        "Query exceeded limit for bytes billed: 100. 10485760 or higher "
        "required.; reason: bytesBilledLimitExceeded, message: Query exceeded "
        "limit for bytes billed: 100. 10485760 or higher required.\n\n"
        "Location: us-central1\nJob ID: 24eeb6bb-a843-478c-808e-d942572cf453\n"
    )

    client = _make_client(mock_bq_client)

    with pytest.raises(InternalServerError) as exc_info:
        client.execute_sql("SELECT 1", max_bytes_billed="100")

    assert "bytesBilledLimitExceeded" in str(exc_info.value)
