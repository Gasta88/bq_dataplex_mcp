"""Tests for app/services/dataplex_client.py (DataplexClient).

Mocks the underlying `google.cloud.dataplex_v1.DataScanServiceClient`
(`list_data_scans`/`get_data_scan`), following `tests/test_lineage_client.py`'s
existing GCP-SDK-mock pattern --'s Test
Strategy (Unit Tests)."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from google.api_core.exceptions import NotFound, PermissionDenied
from google.cloud import dataplex_v1
from google.protobuf import timestamp_pb2

from app.services.dataplex_client import DataplexClient

PROJECT_ID = "example-project"
LOCATION = "us-central1"
DATASET_ID = "analytics"
TABLE_ID = "daily_active_users"
TABLE_RESOURCE = (
    f"//bigquery.googleapis.com/projects/{PROJECT_ID}/datasets/{DATASET_ID}/tables/{TABLE_ID}"
)
SCAN_NAME = f"projects/{PROJECT_ID}/locations/{LOCATION}/dataScans/daily-active-users-dq-scan"


@pytest.fixture
def mock_gcp_dataplex_client():
    with patch(
        "app.services.dataplex_client.dataplex_v1.DataScanServiceClient"
    ) as mock_ctor:
        yield mock_ctor.return_value


def _make_client(mock_gcp_dataplex_client) -> DataplexClient:
    return DataplexClient(PROJECT_ID)


def _scan(
    name: str = SCAN_NAME,
    resource: str = TABLE_RESOURCE,
    display_name: str = "",
    scan_type: dataplex_v1.DataScanType = dataplex_v1.DataScanType.DATA_QUALITY,
) -> dataplex_v1.DataScan:
    return dataplex_v1.DataScan(
        name=name,
        display_name=display_name,
        data=dataplex_v1.DataSource(resource=resource),
        type_=scan_type,
    )


def _full_scan_with_result(
    result: dataplex_v1.DataQualityResult | None,
    name: str = SCAN_NAME,
) -> dataplex_v1.DataScan:
    kwargs: dict = {"name": name}
    if result is not None:
        kwargs["data_quality_result"] = result
    return dataplex_v1.DataScan(**kwargs)


# ---------------------------------------------------------------------------
# get_data_quality_results -- happy path / field mapping
# ---------------------------------------------------------------------------


def test_returns_fully_mapped_dict_when_scan_found_and_result_populated(
    mock_gcp_dataplex_client,
):
    client = _make_client(mock_gcp_dataplex_client)
    mock_gcp_dataplex_client.list_data_scans.return_value = [_scan(display_name="DAU DQ Scan")]

    result = dataplex_v1.DataQualityResult(
        passed=True,
        row_count=1523847,
        dimensions=[
            dataplex_v1.DataQualityDimensionResult(
                dimension=dataplex_v1.DataQualityDimension(name="COMPLETENESS"),
                passed=True,
                score=98.5,
            )
        ],
    )
    full_scan = _full_scan_with_result(result)
    end_time = timestamp_pb2.Timestamp()
    end_time.FromJsonString("2026-07-20T00:00:00Z")
    full_scan.execution_status = dataplex_v1.DataScan.ExecutionStatus(
        latest_job_end_time=end_time
    )
    mock_gcp_dataplex_client.get_data_scan.return_value = full_scan

    output = client.get_data_quality_results(DATASET_ID, TABLE_ID)

    assert output == {
        "scanName": "DAU DQ Scan",
        "tableId": TABLE_ID,
        "datasetId": DATASET_ID,
        "executionTime": "2026-07-20T00:00:00.000000Z",
        "passed": True,
        "dimensions": [{"dimension": "COMPLETENESS", "passed": True, "score": 98.5}],
        "rowCount": 1523847,
    }


def test_dimension_mapping_emits_real_dimension_name_when_present(
    mock_gcp_dataplex_client,
):
    # Asserts the fixed  behavior explicitly, not incidentally -- see
    # module docstring.
    client = _make_client(mock_gcp_dataplex_client)
    mock_gcp_dataplex_client.list_data_scans.return_value = [_scan()]

    result = dataplex_v1.DataQualityResult(
        passed=True,
        dimensions=[
            dataplex_v1.DataQualityDimensionResult(
                dimension=dataplex_v1.DataQualityDimension(name="COMPLETENESS"),
                passed=True,
                score=100,
            )
        ],
    )
    mock_gcp_dataplex_client.get_data_scan.return_value = _full_scan_with_result(result)

    output = client.get_data_quality_results(DATASET_ID, TABLE_ID)

    assert output["dimensions"][0]["dimension"] == "COMPLETENESS"


def test_dimension_mapping_emits_unknown_when_dimension_absent(mock_gcp_dataplex_client):
    client = _make_client(mock_gcp_dataplex_client)
    mock_gcp_dataplex_client.list_data_scans.return_value = [_scan()]

    result = dataplex_v1.DataQualityResult(
        passed=True,
        dimensions=[dataplex_v1.DataQualityDimensionResult(passed=False, score=0)],
    )
    mock_gcp_dataplex_client.get_data_scan.return_value = _full_scan_with_result(result)

    output = client.get_data_quality_results(DATASET_ID, TABLE_ID)

    assert output["dimensions"][0]["dimension"] == "Unknown"


def test_execution_time_reflects_latest_job_end_time_when_present(
    mock_gcp_dataplex_client,
):
    # Asserts the fixed  behavior explicitly -- see module docstring.
    client = _make_client(mock_gcp_dataplex_client)
    mock_gcp_dataplex_client.list_data_scans.return_value = [_scan()]

    result = dataplex_v1.DataQualityResult(passed=True)
    full_scan = _full_scan_with_result(result)
    end_time = timestamp_pb2.Timestamp()
    end_time.FromJsonString("2026-07-20T00:00:00Z")
    full_scan.execution_status = dataplex_v1.DataScan.ExecutionStatus(
        latest_job_end_time=end_time
    )
    mock_gcp_dataplex_client.get_data_scan.return_value = full_scan

    output = client.get_data_quality_results(DATASET_ID, TABLE_ID)

    assert output["executionTime"] == "2026-07-20T00:00:00.000000Z"


def test_execution_time_is_unknown_when_execution_status_entirely_absent(
    mock_gcp_dataplex_client,
):
    # `execution_status` not set at all on the `DataScan` (distinct from the
    # next test's "present but latest_job_end_time unset" sub-case) -- both
    # sub-cases fall back to "Unknown".
    client = _make_client(mock_gcp_dataplex_client)
    mock_gcp_dataplex_client.list_data_scans.return_value = [_scan()]

    full_scan = _full_scan_with_result(dataplex_v1.DataQualityResult(passed=True))
    assert "execution_status" not in full_scan
    mock_gcp_dataplex_client.get_data_scan.return_value = full_scan

    output = client.get_data_quality_results(DATASET_ID, TABLE_ID)

    assert output["executionTime"] == "Unknown"


def test_execution_time_is_unknown_when_execution_status_present_but_latest_job_end_time_unset(
    mock_gcp_dataplex_client,
):
    # `execution_status` set (e.g. a scan that has run) but with no
    # `latest_job_end_time` populated within it.
    client = _make_client(mock_gcp_dataplex_client)
    mock_gcp_dataplex_client.list_data_scans.return_value = [_scan()]

    full_scan = _full_scan_with_result(dataplex_v1.DataQualityResult(passed=True))
    full_scan.execution_status = dataplex_v1.DataScan.ExecutionStatus()
    mock_gcp_dataplex_client.get_data_scan.return_value = full_scan

    output = client.get_data_quality_results(DATASET_ID, TABLE_ID)

    assert output["executionTime"] == "Unknown"


# ---------------------------------------------------------------------------
# get_data_quality_results -- None-returning branches
# ---------------------------------------------------------------------------


def test_returns_none_when_no_scan_matches_table_resource(mock_gcp_dataplex_client):
    client = _make_client(mock_gcp_dataplex_client)
    mock_gcp_dataplex_client.list_data_scans.return_value = [
        _scan(resource="//bigquery.googleapis.com/projects/p/datasets/other/tables/other")
    ]

    assert client.get_data_quality_results(DATASET_ID, TABLE_ID) is None
    mock_gcp_dataplex_client.get_data_scan.assert_not_called()


def test_returns_none_when_list_data_scans_returns_empty(mock_gcp_dataplex_client):
    client = _make_client(mock_gcp_dataplex_client)
    mock_gcp_dataplex_client.list_data_scans.return_value = []

    assert client.get_data_quality_results(DATASET_ID, TABLE_ID) is None
    mock_gcp_dataplex_client.get_data_scan.assert_not_called()


def test_returns_none_when_matching_scan_has_no_data_quality_result_yet(
    mock_gcp_dataplex_client,
):
    client = _make_client(mock_gcp_dataplex_client)
    mock_gcp_dataplex_client.list_data_scans.return_value = [_scan()]
    mock_gcp_dataplex_client.get_data_scan.return_value = _full_scan_with_result(None)

    assert client.get_data_quality_results(DATASET_ID, TABLE_ID) is None


# ---------------------------------------------------------------------------
# Matching order / re-fetch call shape
# ---------------------------------------------------------------------------


def test_matching_picks_first_scan_in_list_order_regardless_of_type(mock_gcp_dataplex_client):
    # Documents the Risk table entry with an executable test: a DATA_PROFILE
    # scan sharing the same data.resource, listed first, wins the match over
    # a DATA_QUALITY scan listed second -- ported as-is, not "fixed".
    client = _make_client(mock_gcp_dataplex_client)
    profile_scan = _scan(
        name=f"projects/{PROJECT_ID}/locations/{LOCATION}/dataScans/profile-scan",
        scan_type=dataplex_v1.DataScanType.DATA_PROFILE,
    )
    quality_scan = _scan(
        name=SCAN_NAME,
        scan_type=dataplex_v1.DataScanType.DATA_QUALITY,
    )
    mock_gcp_dataplex_client.list_data_scans.return_value = [profile_scan, quality_scan]
    mock_gcp_dataplex_client.get_data_scan.return_value = _full_scan_with_result(
        dataplex_v1.DataQualityResult(passed=True), name=profile_scan.name
    )

    client.get_data_quality_results(DATASET_ID, TABLE_ID)

    # `get_data_scan`'s generated method signature only flattens `name`, not
    # `view` (confirmed live via `inspect.signature` against the installed
    # client -- see app/services/dataplex_client.py's inline note), so the
    # call must pass a full `GetDataScanRequest` as `request=`.
    mock_gcp_dataplex_client.get_data_scan.assert_called_once_with(
        request=dataplex_v1.GetDataScanRequest(
            name=profile_scan.name, view=dataplex_v1.GetDataScanRequest.DataScanView.FULL
        )
    )


def test_get_data_scan_called_with_full_view_not_basic_default(mock_gcp_dataplex_client):
    client = _make_client(mock_gcp_dataplex_client)
    mock_gcp_dataplex_client.list_data_scans.return_value = [_scan()]
    mock_gcp_dataplex_client.get_data_scan.return_value = _full_scan_with_result(
        dataplex_v1.DataQualityResult(passed=True)
    )

    client.get_data_quality_results(DATASET_ID, TABLE_ID)

    mock_gcp_dataplex_client.get_data_scan.assert_called_once_with(
        request=dataplex_v1.GetDataScanRequest(
            name=SCAN_NAME, view=dataplex_v1.GetDataScanRequest.DataScanView.FULL
        )
    )
    actual_request = mock_gcp_dataplex_client.get_data_scan.call_args.kwargs["request"]
    assert actual_request.view != dataplex_v1.GetDataScanRequest.DataScanView.BASIC


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


def test_notfound_from_list_data_scans_raises_data_scan_api_error_message(
    mock_gcp_dataplex_client,
):
    client = _make_client(mock_gcp_dataplex_client)
    mock_gcp_dataplex_client.list_data_scans.side_effect = NotFound("nope")

    with pytest.raises(
        RuntimeError,
        match="Data Scan API error. Please ensure Dataplex API is enabled",
    ):
        client.get_data_quality_results(DATASET_ID, TABLE_ID)


def test_notfound_from_get_data_scan_raises_data_scan_api_error_message(
    mock_gcp_dataplex_client,
):
    client = _make_client(mock_gcp_dataplex_client)
    mock_gcp_dataplex_client.list_data_scans.return_value = [_scan()]
    mock_gcp_dataplex_client.get_data_scan.side_effect = NotFound("nope")

    with pytest.raises(
        RuntimeError,
        match="Data Scan API error. Please ensure Dataplex API is enabled",
    ):
        client.get_data_quality_results(DATASET_ID, TABLE_ID)


def test_other_exception_propagates_unchanged(mock_gcp_dataplex_client):
    client = _make_client(mock_gcp_dataplex_client)
    mock_gcp_dataplex_client.list_data_scans.side_effect = PermissionDenied("nope")

    with pytest.raises(PermissionDenied):
        client.get_data_quality_results(DATASET_ID, TABLE_ID)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_scan_name_falls_back_to_scan_name_when_display_name_empty(mock_gcp_dataplex_client):
    client = _make_client(mock_gcp_dataplex_client)
    mock_gcp_dataplex_client.list_data_scans.return_value = [_scan(display_name="")]
    mock_gcp_dataplex_client.get_data_scan.return_value = _full_scan_with_result(
        dataplex_v1.DataQualityResult(passed=True)
    )

    output = client.get_data_quality_results(DATASET_ID, TABLE_ID)

    assert output["scanName"] == SCAN_NAME


def test_dimensions_empty_list_is_not_omitted(mock_gcp_dataplex_client):
    client = _make_client(mock_gcp_dataplex_client)
    mock_gcp_dataplex_client.list_data_scans.return_value = [_scan()]
    mock_gcp_dataplex_client.get_data_scan.return_value = _full_scan_with_result(
        dataplex_v1.DataQualityResult(passed=True, dimensions=[])
    )

    output = client.get_data_quality_results(DATASET_ID, TABLE_ID)

    assert output["dimensions"] == []


def test_row_count_zero_is_not_omitted_or_null(mock_gcp_dataplex_client):
    client = _make_client(mock_gcp_dataplex_client)
    mock_gcp_dataplex_client.list_data_scans.return_value = [_scan()]
    mock_gcp_dataplex_client.get_data_scan.return_value = _full_scan_with_result(
        dataplex_v1.DataQualityResult(passed=True, row_count=0)
    )

    output = client.get_data_quality_results(DATASET_ID, TABLE_ID)

    assert output["rowCount"] == 0
