"""Tests for the FastMCP entrypoint (app/main.py).

Covers the `ping` tool, every data tool through the real MCP protocol via
`fastmcp.Client(mcp)`, app factory behavior, stateless HTTP semantics, and
SIGTERM/port handling. Google Cloud clients are monkeypatched at the module's
DI seams, so no real ADC or network calls are made.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import json
import signal
from unittest.mock import MagicMock

import httpx
import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError
from fastmcp.utilities.tests import find_available_port

import app.main as main_module
from app.config import Settings
from app.main import (
    SERVICE_NAME,
    _handle_sigterm,
    create_app,
    execute_sql,
    get_data_lineage,
    get_data_quality_results,
    get_table_metadata,
    list_datasets,
    list_tables,
    mcp,
    ping,
    resolve_port,
)
from app.rejection_log import McpRejectionLogger

EXPECTED_PING_RESULT = {"status": "ok", "service": "bq-dataplex-mcp"}

# These six descriptions use a three-part invocation-clarity structure
# (one-sentence purpose, "Use this when ...", "Not this when ... -- use <tool>
# instead.", plus an `Args:` block for `execute_sql`/`get_data_lineage`).
# Hand-typed here,
# independent of app/main.py's own docstring text, so a divergence (typo,
# whitespace, or a later accidental docstring edit) is a real test failure,
# not a tautology.
EXPECTED_TOOL_DESCRIPTIONS = {
    "ping": None,  # not part of the description contract; not asserted here
    "list_datasets": (
        "List all BigQuery datasets in the configured GCP project.\n"
        "\n"
        "Use this when you need to enumerate which datasets exist before drilling into\n"
        "a specific one, or a user asks what datasets/schemas exist in general.\n"
        "Not this when you already know the dataset and need its tables or a table's\n"
        "schema -- use `list_tables` or `get_table_metadata` instead. Not this when\n"
        "you could instead run an `INFORMATION_SCHEMA` query via `execute_sql` --\n"
        "this tool is the cheaper, purpose-built path for enumeration and should\n"
        "always be preferred."
    ),
    "list_tables": (
        "List all tables in a BigQuery dataset.\n"
        "\n"
        "Use this when you know the dataset and need to see what tables it contains,\n"
        "or a user asks what tables exist in a given dataset.\n"
        "Not this when you need the datasets themselves -- use `list_datasets` first.\n"
        "Not this when you need a specific table's schema, size, or partitioning --\n"
        "use `get_table_metadata` instead. Not this when you could instead run a\n"
        "`SELECT table_name FROM <dataset>.INFORMATION_SCHEMA.TABLES` via\n"
        "`execute_sql` -- this tool is the cheaper, purpose-built path for\n"
        "enumeration and should always be preferred."
    ),
    "get_table_metadata": (
        "Get comprehensive metadata for a BigQuery table including schema,\n"
        "descriptions, clustering, partitioning, and partition filters.\n"
        "\n"
        "Use this when you need structural facts about a table itself -- its column\n"
        "schema, row/byte counts, clustering, partitioning, or labels -- not the data\n"
        "inside it.\n"
        "Not this when you need upstream/downstream relationships -- use\n"
        "`get_data_lineage` instead. Not this when you need pass/fail data-quality\n"
        "scan results -- use `get_data_quality_results` instead. Not this when you\n"
        "need actual row data or aggregates -- use `execute_sql` instead; do not\n"
        "query `INFORMATION_SCHEMA` for facts this tool already returns directly."
    ),
    "get_data_lineage": (
        "Get upstream and downstream data lineage for a BigQuery table with Mermaid\n"
        "diagram visualization.\n"
        "\n"
        "Use this when a user asks where a table's data comes from, what depends on\n"
        "it downstream, or wants a lineage/dependency diagram.\n"
        "Not this when you need the table's own schema, size, or partitioning -- use\n"
        "`get_table_metadata` instead. Not this when you need data-quality scan\n"
        "results -- use `get_data_quality_results` instead.\n"
        "\n"
        "Args:\n"
        "    dataset_id: BigQuery dataset ID.\n"
        "    table_id: BigQuery table ID. Lineage depth is fixed at 3 levels\n"
        "        upstream/downstream and is not a caller-adjustable parameter."
    ),
    "get_data_quality_results": (
        "Get the latest data quality scan results for a BigQuery table.\n"
        "\n"
        "Use this when a user asks whether a table's data quality checks are passing,\n"
        "or wants scan scores/dimensions (completeness, validity, etc.) for a table.\n"
        "Not this when you need the table's schema, size, or partitioning -- use\n"
        "`get_table_metadata` instead. Not this when you need lineage/dependency\n"
        "information -- use `get_data_lineage` instead."
    ),
    "execute_sql": (
        "Execute a read-only (SELECT / WITH) BigQuery SQL query and return the rows.\n"
        "DML/DDL is rejected. A maximumBytesBilled cap is always applied. Use dryRun\n"
        "to estimate bytes processed without running the query.\n"
        "\n"
        "Use this when you need actual row data, aggregates, joins, or any\n"
        "computation over table contents that the metadata tools below don't already\n"
        "return directly.\n"
        "Not this when the question is answerable by `list_datasets`, `list_tables`,\n"
        "`get_table_metadata`, `get_data_lineage`, or `get_data_quality_results` --\n"
        "prefer those purpose-built tools over an `INFORMATION_SCHEMA` query or\n"
        "manual introspection; they are cheaper and already return the exact shape\n"
        "needed.\n"
        "\n"
        "Every response (dryRun and real runs alike) includes estimatedCostUsd, an\n"
        "informational, non-blocking on-demand cost estimate derived from bytes\n"
        "processed -- it is never used to block, delay, or otherwise gate query\n"
        "execution. When a flat-rate slot reservation is active (BIGQUERY_RESERVATION\n"
        "set, prod), this figure is a notional on-demand-equivalent proxy for cost\n"
        "attribution, not prod's actual billed amount -- prod's flat-rate billing has\n"
        "no true per-byte cost.\n"
        "\n"
        "Args:\n"
        "    query: A single SELECT or WITH statement. Any DML/DDL keyword anywhere\n"
        "        in the body, or more than one statement, is rejected before any\n"
        "        BigQuery call is made.\n"
        "    max_rows: Optional cap on returned rows (default 1000 if unset --\n"
        "        verified against `BigQueryClient.execute_sql`'s\n"
        "        `job.result(max_results=max_rows or 1000)` call).\n"
        "    max_bytes_billed: Optional override of the maximumBytesBilled cost cap\n"
        "        (default 100 GiB).\n"
        "    dry_run: When true, estimates bytes processed without billing or\n"
        "        running the query -- returns `{dryRun, totalBytesProcessed,\n"
        "        estimatedGiB, estimatedCostUsd}` instead of rows. Real runs return\n"
        "        `{rows, rowCount, schema, totalBytesProcessed, cacheHit, jobId,\n"
        "        estimatedCostUsd}`."
    ),
}


@pytest.fixture
def fake_bq_client(monkeypatch):
    """Installs a MagicMock in place of `app.main._bq_client`, bypassing
    `_get_bq_client()`'s real construction entirely, and clears the shared
    `cache` singleton before/after so tests don't leak state into each other.
    """
    fake_client = MagicMock()
    monkeypatch.setattr(main_module, "_bq_client", fake_client)
    main_module.cache.clear()
    yield fake_client
    main_module.cache.clear()


@pytest.fixture
def fake_lineage_client(monkeypatch):
    """Installs a MagicMock in place of `app.main._lineage_client`, bypassing
    `_get_lineage_client()`'s real construction entirely, and clears the
    shared `cache` singleton before/after so tests don't leak state into each
    other.
    """
    fake_client = MagicMock()
    monkeypatch.setattr(main_module, "_lineage_client", fake_client)
    main_module.cache.clear()
    yield fake_client
    main_module.cache.clear()


@pytest.fixture
def fake_dataplex_client(monkeypatch):
    """Installs a MagicMock in place of `app.main._dataplex_client`, bypassing
    `_get_dataplex_client()`'s real construction entirely, and clears the
    shared `cache` singleton before/after so tests don't leak state into each
    other.
    """
    fake_client = MagicMock()
    monkeypatch.setattr(main_module, "_dataplex_client", fake_client)
    main_module.cache.clear()
    yield fake_client
    main_module.cache.clear()


@pytest.fixture
def anyio_backend():
    # Restricts anyio's pytest plugin to asyncio only -- trio is not installed
    # and is not needed here (mirrors this repo's narrow dependency set).
    return "asyncio"


# ---------------------------------------------------------------------------
# Unit tests: ping() called directly, no MCP transport involved
# ---------------------------------------------------------------------------


def test_ping_returns_expected_status_payload():
    assert ping() == EXPECTED_PING_RESULT


def test_ping_return_value_is_json_serializable():
    # Guards against an accidental non-primitive return type creeping in later.
    assert json.dumps(ping())


def test_service_name_constant_matches_expected_service():
    assert SERVICE_NAME == "bq-dataplex-mcp"


# ---------------------------------------------------------------------------
# Unit tests: app.config.Settings env-var-with-fallback behavior
# ---------------------------------------------------------------------------


def test_settings_reads_gcp_project_and_log_level_from_env(monkeypatch):
    monkeypatch.setenv("GCP_PROJECT", "example-project")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")

    settings = Settings()

    assert settings.gcp_project == "example-project"
    assert settings.log_level == "DEBUG"


def test_settings_falls_back_to_defaults_when_env_vars_unset(monkeypatch):
    monkeypatch.delenv("GCP_PROJECT", raising=False)
    monkeypatch.delenv("LOG_LEVEL", raising=False)

    settings = Settings()

    assert settings.gcp_project == ""
    assert settings.log_level == "INFO"


def test_settings_deploy_env_defaults_to_dev_when_unset(monkeypatch):
    monkeypatch.delenv("DEPLOY_ENV", raising=False)

    settings = Settings()

    assert settings.deploy_env == "dev"


def test_settings_deploy_env_reads_from_env(monkeypatch):
    monkeypatch.setenv("DEPLOY_ENV", "prod")

    settings = Settings()

    assert settings.deploy_env == "prod"


# ---------------------------------------------------------------------------
# Unit tests: create_app()'s prod fail-closed behavior
# ---------------------------------------------------------------------------


def test_create_app_raises_when_prod_has_no_oauth_client_id():
    settings = Settings(deploy_env="prod", google_oauth_client_id="")

    with pytest.raises(RuntimeError, match="DEPLOY_ENV=prod"):
        create_app(app_settings=settings)


def test_create_app_disables_auth_without_raising_when_dev_has_no_oauth_client_id():
    settings = Settings(deploy_env="dev", google_oauth_client_id="")

    app = create_app(app_settings=settings)

    assert app is not None


def test_create_app_does_not_raise_when_prod_has_an_oauth_client_id():
    settings = Settings(
        deploy_env="prod", google_oauth_client_id="test-client-id.apps.googleusercontent.com"
    )

    app = create_app(app_settings=settings)

    assert app is not None


# ---------------------------------------------------------------------------
# Integration tests: in-memory fastmcp.Client(mcp) -- real MCP protocol dispatch
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_ping_via_mcp_client_matches_direct_call():
    async with Client(mcp) as client:
        result = await client.call_tool("ping", {})

    assert result.data == EXPECTED_PING_RESULT == ping()


@pytest.mark.anyio
async def test_list_tools_returns_ping_and_the_six_bigquery_lineage_quality_tools():
    async with Client(mcp) as client:
        tools = await client.list_tools()

    assert {tool.name for tool in tools} == {
        "ping",
        "list_datasets",
        "list_tables",
        "get_table_metadata",
        "execute_sql",
        "get_data_lineage",
        "get_data_quality_results",
    }


@pytest.mark.anyio
async def test_list_tools_descriptions_match_hardened_strings():
    # Asserts the hardened, invocation-clarity descriptions. Round-trips
    # through the real
    # MCP `tools/list` protocol (not just a direct `__doc__` read) to prove
    # FastMCP actually serves the new multi-line docstring content over the
    # wire.
    async with Client(mcp) as client:
        tools = await client.list_tools()

    descriptions = {tool.name: tool.description for tool in tools}
    for name, expected in EXPECTED_TOOL_DESCRIPTIONS.items():
        if expected is None:
            continue
        assert descriptions[name] == expected


def test_six_tool_docstrings_match_hardened_strings_directly():
    # Direct `__doc__` counterpart to the MCP-protocol round trip above --
    # same hardened strings, read straight off the function objects rather
    # than through FastMCP's `tools/list` serialization.
    direct_docstrings = {
        "list_datasets": list_datasets.__doc__,
        "list_tables": list_tables.__doc__,
        "get_table_metadata": get_table_metadata.__doc__,
        "get_data_lineage": get_data_lineage.__doc__,
        "get_data_quality_results": get_data_quality_results.__doc__,
        "execute_sql": execute_sql.__doc__,
    }
    for name, expected in EXPECTED_TOOL_DESCRIPTIONS.items():
        if expected is None:
            continue
        assert inspect.cleandoc(direct_docstrings[name]) == expected


def test_ping_docstring_still_lists_the_correct_six_sibling_tool_names():
    # Guard against drift in the tool names/count ping's docstring lists.
    doc = ping.__doc__
    assert doc is not None
    for tool_name in (
        "list_datasets",
        "list_tables",
        "get_table_metadata",
        "get_data_lineage",
        "get_data_quality_results",
        "execute_sql",
    ):
        assert f"`{tool_name}`" in doc or tool_name in doc
    assert "all six data tools" in doc


# ---------------------------------------------------------------------------
# Unit tests: list_datasets() / list_tables() / get_table_metadata() called
# directly, with app.main._bq_client monkeypatched to a mock -- no real GCP
# client/ADC involved.
# ---------------------------------------------------------------------------


def test_list_datasets_returns_datasets_from_bq_client(fake_bq_client):
    fake_bq_client.list_datasets.return_value = ["analytics", "raw_events"]

    assert list_datasets() == {"datasets": ["analytics", "raw_events"]}


def test_list_datasets_is_served_from_cache_on_second_call(fake_bq_client):
    fake_bq_client.list_datasets.return_value = ["analytics"]

    list_datasets()
    list_datasets()

    assert fake_bq_client.list_datasets.call_count == 1


def test_list_tables_returns_tables_from_bq_client(fake_bq_client):
    fake_bq_client.list_tables.return_value = ["daily_active_users"]

    assert list_tables("analytics") == {"tables": ["daily_active_users"]}
    fake_bq_client.list_tables.assert_called_once_with("analytics")


def test_list_tables_rejects_invalid_dataset_id_before_calling_bq_client(
    fake_bq_client,
):
    with pytest.raises(ValueError):
        list_tables("bad-id")

    fake_bq_client.list_tables.assert_not_called()


def test_get_table_metadata_returns_metadata_from_bq_client(fake_bq_client):
    fake_metadata = {"tableId": "t", "datasetId": "d", "projectId": "p"}
    fake_bq_client.get_table_metadata.return_value = fake_metadata

    assert get_table_metadata("d", "t") == fake_metadata
    fake_bq_client.get_table_metadata.assert_called_once_with("d", "t")


def test_get_table_metadata_rejects_invalid_table_id_before_calling_bq_client(
    fake_bq_client,
):
    with pytest.raises(ValueError):
        get_table_metadata("analytics", "bad table id")

    fake_bq_client.get_table_metadata.assert_not_called()


def test_get_data_lineage_returns_lineage_from_lineage_client_on_cache_miss(
    fake_lineage_client,
):
    fake_lineage = {
        "upstream": [
            {
                "resource": "bigquery:p.raw.events",
                "displayName": "raw.events",
                "type": "table",
            }
        ],
        "downstream": [],
        "links": [],
        "mermaidDiagram": 'graph LR\n  Current["d.t"]:::current',
    }
    fake_lineage_client.get_table_lineage.return_value = fake_lineage

    assert get_data_lineage("d", "t") == fake_lineage
    fake_lineage_client.get_table_lineage.assert_called_once_with("d", "t", 3)


def test_get_data_lineage_is_served_from_cache_on_second_call(fake_lineage_client):
    fake_lineage_client.get_table_lineage.return_value = {
        "upstream": [],
        "downstream": [],
        "links": [],
        "mermaidDiagram": 'graph LR\n  Current["d.t"]:::current',
    }

    get_data_lineage("d", "t")
    get_data_lineage("d", "t")

    assert fake_lineage_client.get_table_lineage.call_count == 1


def test_get_data_lineage_returns_empty_diagram_result_when_no_lineage_data_available(
    fake_lineage_client,
):
    fake_lineage_client.get_table_lineage.side_effect = RuntimeError(
        "Data Lineage API is not enabled or no lineage data available. "
        "Please ensure the Data Lineage API is enabled in your GCP project."
    )

    result = get_data_lineage("analytics", "daily_active_users")

    assert result == {
        "upstream": [],
        "downstream": [],
        "links": [],
        "mermaidDiagram": (
            "graph LR\n"
            '  Current["analytics.daily_active_users"]:::current\n'
            '  Note["No lineage data available for this table"]:::note\n'
            "  Note -.-> Current\n"
            "  classDef current fill:#f9f,stroke:#333,stroke-width:4px\n"
            "  classDef note fill:#fff,stroke:#999,stroke-width:1px,stroke-dasharray: 5 5"
        ),
    }


def test_get_data_lineage_does_not_cache_the_empty_diagram_fallback(
    fake_lineage_client,
):
    # Matches the reference implementation's control flow: `cache.set` sits
    # on the success
    # path only, so a lineage-less table re-triggers the real client call
    # (and empty-diagram construction) on every request, never served from
    # cache.
    fake_lineage_client.get_table_lineage.side_effect = RuntimeError(
        "Data Lineage API is not enabled or no lineage data available. "
        "Please ensure the Data Lineage API is enabled in your GCP project."
    )

    get_data_lineage("analytics", "daily_active_users")
    get_data_lineage("analytics", "daily_active_users")

    assert fake_lineage_client.get_table_lineage.call_count == 2


def test_get_data_lineage_propagates_non_lineage_errors_unchanged(fake_lineage_client):
    from google.api_core.exceptions import PermissionDenied

    fake_lineage_client.get_table_lineage.side_effect = PermissionDenied("nope")

    with pytest.raises(PermissionDenied):
        get_data_lineage("analytics", "daily_active_users")


def test_get_data_lineage_rejects_invalid_dataset_id_before_calling_lineage_client(
    fake_lineage_client,
):
    with pytest.raises(ValueError):
        get_data_lineage("bad-id", "t")

    fake_lineage_client.get_table_lineage.assert_not_called()


def test_get_data_lineage_rejects_invalid_table_id_before_calling_lineage_client(
    fake_lineage_client,
):
    with pytest.raises(ValueError):
        get_data_lineage("d", "bad table id")

    fake_lineage_client.get_table_lineage.assert_not_called()


def test_get_data_quality_results_returns_result_from_dataplex_client_on_cache_miss(
    fake_dataplex_client,
):
    fake_result = {
        "scanName": "daily-active-users-dq-scan",
        "tableId": "t",
        "datasetId": "d",
        "executionTime": "Unknown",
        "passed": True,
        "dimensions": [{"dimension": "[object Object]", "passed": True, "score": 98.5}],
        "rowCount": 1523847,
    }
    fake_dataplex_client.get_data_quality_results.return_value = fake_result

    assert get_data_quality_results("d", "t") == fake_result
    fake_dataplex_client.get_data_quality_results.assert_called_once_with("d", "t")


def test_get_data_quality_results_is_served_from_cache_on_second_call(
    fake_dataplex_client,
):
    fake_dataplex_client.get_data_quality_results.return_value = {
        "scanName": "s",
        "tableId": "t",
        "datasetId": "d",
        "executionTime": "Unknown",
        "passed": True,
        "dimensions": [],
        "rowCount": 0,
    }

    get_data_quality_results("d", "t")
    get_data_quality_results("d", "t")

    assert fake_dataplex_client.get_data_quality_results.call_count == 1


def test_get_data_quality_results_returns_no_scan_message_when_client_returns_none(
    fake_dataplex_client,
):
    fake_dataplex_client.get_data_quality_results.return_value = None

    result = get_data_quality_results("d", "t")

    assert result == {"message": "No data quality scans configured for this table"}


def test_get_data_quality_results_does_not_cache_the_no_scan_message(
    fake_dataplex_client,
):
    # Mirrors get_data_lineage's "empty diagram fallback is not cached" test:
    # a table with no scan configured re-triggers the real client call on
    # every request.
    fake_dataplex_client.get_data_quality_results.return_value = None

    get_data_quality_results("d", "t")
    get_data_quality_results("d", "t")

    assert fake_dataplex_client.get_data_quality_results.call_count == 2


def test_get_data_quality_results_rejects_invalid_dataset_id_before_calling_dataplex_client(
    fake_dataplex_client,
):
    with pytest.raises(ValueError):
        get_data_quality_results("bad-id", "t")

    fake_dataplex_client.get_data_quality_results.assert_not_called()


def test_get_data_quality_results_rejects_invalid_table_id_before_calling_dataplex_client(
    fake_dataplex_client,
):
    with pytest.raises(ValueError):
        get_data_quality_results("d", "bad table id")

    fake_dataplex_client.get_data_quality_results.assert_not_called()


def test_execute_sql_returns_result_from_bq_client(fake_bq_client):
    fake_result = {
        "rows": [{"date": "2026-07-20", "platform": "ios"}],
        "rowCount": 1,
        "schema": [{"name": "date", "type": "DATE", "mode": "NULLABLE"}],
        "totalBytesProcessed": "1048576",
        "cacheHit": False,
        "jobId": "bquxjob_1234abcd_98765",
    }
    fake_bq_client.execute_sql.return_value = fake_result

    assert execute_sql("SELECT date, platform FROM t") == fake_result
    fake_bq_client.execute_sql.assert_called_once_with(
        "SELECT date, platform FROM t",
        max_rows=None,
        max_bytes_billed=None,
        dry_run=False,
    )


def test_execute_sql_rejects_invalid_query_before_calling_bq_client(fake_bq_client):
    with pytest.raises(ValueError):
        execute_sql("DROP TABLE t")

    fake_bq_client.execute_sql.assert_not_called()


def test_execute_sql_does_not_touch_cache_even_when_called_twice_with_same_query(
    fake_bq_client,
):
    fake_bq_client.execute_sql.return_value = {
        "rows": [],
        "rowCount": 0,
        "schema": [],
        "totalBytesProcessed": "0",
        "cacheHit": False,
        "jobId": "j1",
    }

    execute_sql("SELECT 1")
    execute_sql("SELECT 1")

    # Unlike list_tables/get_table_metadata, execute_sql never consults the
    # shared cache -- the underlying client method is invoked once per call.
    assert fake_bq_client.execute_sql.call_count == 2


# ---------------------------------------------------------------------------
# Integration tests: fastmcp.Client(mcp) round-trips for the three new tools
# -- proves each is actually wired into mcp.tool(), not just defined.
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_list_datasets_via_mcp_client_round_trips(fake_bq_client):
    fake_bq_client.list_datasets.return_value = ["analytics", "raw_events"]

    async with Client(mcp) as client:
        result = await client.call_tool("list_datasets", {})

    assert result.data == {"datasets": ["analytics", "raw_events"]}


@pytest.mark.anyio
async def test_list_tables_via_mcp_client_round_trips(fake_bq_client):
    fake_bq_client.list_tables.return_value = ["daily_active_users"]

    async with Client(mcp) as client:
        result = await client.call_tool("list_tables", {"dataset_id": "analytics"})

    assert result.data == {"tables": ["daily_active_users"]}


@pytest.mark.anyio
async def test_get_table_metadata_via_mcp_client_round_trips(fake_bq_client):
    fake_metadata = {"tableId": "t", "datasetId": "d", "projectId": "p"}
    fake_bq_client.get_table_metadata.return_value = fake_metadata

    async with Client(mcp) as client:
        result = await client.call_tool(
            "get_table_metadata", {"dataset_id": "d", "table_id": "t"}
        )

    assert result.data == fake_metadata


@pytest.mark.anyio
async def test_get_data_lineage_via_mcp_client_round_trips(fake_lineage_client):
    fake_lineage = {
        "upstream": [],
        "downstream": [],
        "links": [],
        "mermaidDiagram": 'graph LR\n  Current["d.t"]:::current',
    }
    fake_lineage_client.get_table_lineage.return_value = fake_lineage

    async with Client(mcp) as client:
        result = await client.call_tool(
            "get_data_lineage", {"dataset_id": "d", "table_id": "t"}
        )

    assert result.data == fake_lineage


@pytest.mark.anyio
async def test_get_data_lineage_via_mcp_client_rejects_invalid_dataset_id_but_server_stays_reachable(
    fake_lineage_client,
):
    async with Client(mcp) as client:
        with pytest.raises(ToolError):
            await client.call_tool(
                "get_data_lineage", {"dataset_id": "bogus id", "table_id": "t"}
            )

        fake_lineage_client.get_table_lineage.assert_not_called()

        fake_lineage_client.get_table_lineage.return_value = {
            "upstream": [],
            "downstream": [],
            "links": [],
            "mermaidDiagram": 'graph LR\n  Current["d.t"]:::current',
        }
        result = await client.call_tool(
            "get_data_lineage", {"dataset_id": "d", "table_id": "t"}
        )
        assert result.data["upstream"] == []


@pytest.mark.anyio
async def test_get_data_quality_results_via_mcp_client_round_trips(
    fake_dataplex_client,
):
    fake_result = {
        "scanName": "daily-active-users-dq-scan",
        "tableId": "t",
        "datasetId": "d",
        "executionTime": "Unknown",
        "passed": True,
        "dimensions": [{"dimension": "[object Object]", "passed": True, "score": 98.5}],
        "rowCount": 1523847,
    }
    fake_dataplex_client.get_data_quality_results.return_value = fake_result

    async with Client(mcp) as client:
        result = await client.call_tool(
            "get_data_quality_results", {"dataset_id": "d", "table_id": "t"}
        )

    assert result.data == fake_result


@pytest.mark.anyio
async def test_get_data_quality_results_via_mcp_client_rejects_invalid_dataset_id_but_server_stays_reachable(
    fake_dataplex_client,
):
    async with Client(mcp) as client:
        with pytest.raises(ToolError):
            await client.call_tool(
                "get_data_quality_results", {"dataset_id": "bogus id", "table_id": "t"}
            )

        fake_dataplex_client.get_data_quality_results.assert_not_called()

        fake_dataplex_client.get_data_quality_results.return_value = None
        result = await client.call_tool(
            "get_data_quality_results", {"dataset_id": "d", "table_id": "t"}
        )
        assert result.data == {
            "message": "No data quality scans configured for this table"
        }


@pytest.mark.anyio
async def test_execute_sql_via_mcp_client_round_trips(fake_bq_client):
    fake_result = {
        "rows": [{"date": "2026-07-20", "platform": "ios"}],
        "rowCount": 1,
        "schema": [{"name": "date", "type": "DATE", "mode": "NULLABLE"}],
        "totalBytesProcessed": "1048576",
        "cacheHit": False,
        "jobId": "bquxjob_1234abcd_98765",
    }
    fake_bq_client.execute_sql.return_value = fake_result

    async with Client(mcp) as client:
        result = await client.call_tool(
            "execute_sql", {"query": "SELECT date, platform FROM t"}
        )

    assert result.data == fake_result


@pytest.mark.anyio
async def test_execute_sql_via_mcp_client_rejects_drop_table_before_calling_bq_client(
    fake_bq_client,
):
    async with Client(mcp) as client:
        with pytest.raises(ToolError):
            await client.call_tool("execute_sql", {"query": "DROP TABLE t"})

        fake_bq_client.execute_sql.assert_not_called()

        # Server must stay reachable for a subsequent, valid call.
        fake_bq_client.execute_sql.return_value = {
            "rows": [],
            "rowCount": 0,
            "schema": [],
            "totalBytesProcessed": "0",
            "cacheHit": False,
            "jobId": "j1",
        }
        result = await client.call_tool("execute_sql", {"query": "SELECT 1"})
        assert result.data["rowCount"] == 0


@pytest.mark.anyio
async def test_execute_sql_response_includes_estimated_cost_usd_via_mcp_client(
    fake_bq_client,
):
    """: estimatedCostUsd is present end-to-end through the real MCP
    tool-call path, not just at the BigQueryClient unit-test layer."""
    fake_result = {
        "rows": [{"date": "2026-07-20", "platform": "ios"}],
        "rowCount": 1,
        "schema": [{"name": "date", "type": "DATE", "mode": "NULLABLE"}],
        "totalBytesProcessed": "1048576",
        "cacheHit": False,
        "jobId": "bquxjob_1234abcd_98765",
        "estimatedCostUsd": 5.9604644775390625e-06,
    }
    fake_bq_client.execute_sql.return_value = fake_result

    async with Client(mcp) as client:
        result = await client.call_tool(
            "execute_sql", {"query": "SELECT date, platform FROM t"}
        )

    assert result.data == fake_result
    assert "estimatedCostUsd" in result.data


@pytest.mark.anyio
async def test_execute_sql_via_mcp_client_calls_bq_client_twice_for_two_identical_calls(
    fake_bq_client,
):
    fake_bq_client.execute_sql.return_value = {
        "rows": [],
        "rowCount": 0,
        "schema": [],
        "totalBytesProcessed": "0",
        "cacheHit": False,
        "jobId": "j1",
    }

    async with Client(mcp) as client:
        await client.call_tool("execute_sql", {"query": "SELECT 1"})
        await client.call_tool("execute_sql", {"query": "SELECT 1"})

    # Proves execute_sql deliberately bypasses the shared cache singleton,
    # unlike list_tables/get_table_metadata.
    assert fake_bq_client.execute_sql.call_count == 2


@pytest.mark.anyio
async def test_list_tables_via_mcp_client_rejects_invalid_dataset_id_but_server_stays_reachable(
    fake_bq_client,
):
    async with Client(mcp) as client:
        with pytest.raises(ToolError):
            await client.call_tool("list_tables", {"dataset_id": "bogus id"})

        # Server must stay reachable for a subsequent, correctly-shaped call.
        fake_bq_client.list_tables.return_value = ["t1"]
        result = await client.call_tool("list_tables", {"dataset_id": "analytics"})
        assert result.data == {"tables": ["t1"]}


@pytest.mark.anyio
async def test_list_tables_via_mcp_client_calls_bq_client_once_when_cached_twice_when_disabled(
    fake_bq_client, monkeypatch
):
    fake_bq_client.list_tables.return_value = ["t1"]

    async with Client(mcp) as client:
        await client.call_tool("list_tables", {"dataset_id": "analytics"})
        await client.call_tool("list_tables", {"dataset_id": "analytics"})

    assert fake_bq_client.list_tables.call_count == 1

    # Disabling the cache: every call reaches the underlying client.
    from app.services.cache_service import CacheService

    monkeypatch.setattr(main_module, "cache", CacheService(enabled=False))
    fake_bq_client.list_tables.reset_mock()

    async with Client(mcp) as client:
        await client.call_tool("list_tables", {"dataset_id": "analytics"})
        await client.call_tool("list_tables", {"dataset_id": "analytics"})

    assert fake_bq_client.list_tables.call_count == 2


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_ping_with_extra_arguments_is_rejected_but_server_stays_reachable():
    # ping() takes no parameters. Observed behavior (fastmcp>=2.14.7,<3): the
    # client-side call_tool raises fastmcp.exceptions.ToolError from the
    # server's own pydantic-based argument-validation layer -- the server
    # process itself does not crash. Asserted against this pinned version's
    # actual behavior, not an assumption.
    async with Client(mcp) as client:
        with pytest.raises(ToolError):
            await client.call_tool("ping", {"unexpected": "arg"})

        # Server must stay reachable for a subsequent, correctly-shaped call.
        result = await client.call_tool("ping", {})
        assert result.data == EXPECTED_PING_RESULT


_VALID_ARGS_PER_TOOL = {
    "ping": {},
    "list_datasets": {},
    "list_tables": {"dataset_id": "ds"},
    "get_table_metadata": {"dataset_id": "ds", "table_id": "tbl"},
    "get_data_lineage": {"dataset_id": "ds", "table_id": "tbl"},
    "get_data_quality_results": {"dataset_id": "ds", "table_id": "tbl"},
    "execute_sql": {"query": "SELECT 1", "dry_run": True},
}


@pytest.mark.anyio
@pytest.mark.parametrize("tool_name", sorted(_VALID_ARGS_PER_TOOL))
async def test_every_tool_rejects_unexpected_arguments_before_running(tool_name, monkeypatch):
    """The advertised input schemas carry `additionalProperties: false`
    (fastmcp 4); the same rejection already held under fastmcp 2. The tool
    body must never run: every client getter is patched to fail loudly, and
    the rejection must come from argument validation, not from that failure.
    """

    def _body_reached(*args, **kwargs):
        raise RuntimeError("tool body reached")

    for getter in ("_get_bq_client", "_get_lineage_client", "_get_dataplex_client"):
        monkeypatch.setattr(f"app.main.{getter}", _body_reached)

    async with Client(mcp) as client:
        with pytest.raises(ToolError) as excinfo:
            await client.call_tool(tool_name, {**_VALID_ARGS_PER_TOOL[tool_name], "unexpected": "arg"})

        assert "tool body reached" not in str(excinfo.value)
        assert "unexpected" in str(excinfo.value).lower()


def test_resolve_port_defaults_to_8080_when_env_var_absent(monkeypatch):
    monkeypatch.delenv("PORT", raising=False)

    assert resolve_port() == 8080


def test_resolve_port_defaults_to_8080_when_env_var_empty(monkeypatch):
    monkeypatch.setenv("PORT", "")

    assert resolve_port() == 8080


def test_resolve_port_reads_env_var_when_set(monkeypatch):
    monkeypatch.setenv("PORT", "9090")

    assert resolve_port() == 9090


def test_sigterm_handler_exits_cleanly_with_code_zero():
    with pytest.raises(SystemExit) as exc_info:
        _handle_sigterm(signal.SIGTERM, None)

    assert exc_info.value.code == 0


def test_double_sigterm_handler_does_not_raise_anything_but_systemexit():
    # Cloud Run/Docker can resend SIGTERM during shutdown; the handler must be
    # idempotent -- always the same clean SystemExit(0), never an unhandled
    # exception.
    for _ in range(2):
        with pytest.raises(SystemExit) as exc_info:
            _handle_sigterm(signal.SIGTERM, None)
        assert exc_info.value.code == 0


# ---------------------------------------------------------------------------
# main(): logging setup, SIGTERM registration, transport bind -- mcp.run()
# itself is monkeypatched out since it blocks forever serving the real
# streamable-http transport.
# ---------------------------------------------------------------------------


def test_main_configures_logging_signal_and_binds_transport(monkeypatch):
    fake_run_calls = {}

    def fake_run(**kwargs):
        fake_run_calls.update(kwargs)

    monkeypatch.setattr(main_module.mcp, "run", fake_run)

    signal_calls = {}

    def fake_signal(sig, handler):
        signal_calls["sig"] = sig
        signal_calls["handler"] = handler

    monkeypatch.setattr(main_module.signal, "signal", fake_signal)
    monkeypatch.setenv("PORT", "9999")

    main_module.main()

    middleware = fake_run_calls.pop("middleware")
    assert [m.cls for m in middleware] == [McpRejectionLogger]
    assert fake_run_calls == {
        "transport": "streamable-http",
        "host": "0.0.0.0",
        "port": 9999,
        "stateless_http": True,
        "uvicorn_config": {"access_log": False},
    }
    assert signal_calls == {
        "sig": signal.SIGTERM,
        "handler": main_module._handle_sigterm,
    }


# ---------------------------------------------------------------------------
# /: stateless_http=True behavioral proof.
#
# The unit test above only proves the *kwarg* is passed to mcp.run(). This
# section proves what that kwarg actually buys in production: a real
# in-process HTTP server run with stateless_http=True (mirroring exactly what
# main() now does) never emits an Mcp-Session-Id response header, and -- the
# actual cross-instance-affinity concern from's
# Finding 3 -- a tool call sent with a bogus/unknown Mcp-Session-Id (standing
# in for "a different Cloud Run instance than the one that would have created
# this session") still succeeds, because stateless mode never looks up a
# server-side session at all: every request gets a brand-new transport
# (mcp/server/streamable_http_manager.py's `_handle_stateless_request`,
# confirmed via source read -- `mcp_session_id=None`, `event_store=None`).
#
# `fastmcp.utilities.tests.run_server_async` (used by
# tests/test_mcp_auth_integration.py) does not expose a stateless_http
# passthrough, so this test starts the server directly via
# `FastMCP.run_http_async`, replicating run_server_async's own
# start-task/wait-for-lifespan/cancel-on-teardown pattern. Uses a fresh
# `create_app()` instance (auth-disabled default Settings, per
# tests/conftest.py's env-var scrub) rather than the shared `main_module.mcp`
# singleton, since a StreamableHTTPSessionManager cannot be reused once its
# run() context has started.
# ---------------------------------------------------------------------------

_MCP_ACCEPT = "application/json, text/event-stream"

_MCP_INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "test-client", "version": "0.0.1"},
    },
}


@contextlib.asynccontextmanager
async def _run_stateless_server(server):
    """Start `server` as a real in-process HTTP server with
    stateless_http=True -- the same kwarg main() now passes to mcp.run().
    Mirrors fastmcp.utilities.tests.run_server_async, which has no
    stateless_http passthrough of its own.
    """
    port = find_available_port()
    server_task = asyncio.create_task(
        server.run_http_async(
            host="127.0.0.1",
            port=port,
            transport="streamable-http",
            path="/mcp",
            show_banner=False,
            stateless_http=True,
        )
    )
    # Note: _started is a private fastmcp attribute; wrapped with timeout to surface
    # hangs immediately if fastmcp's internal implementation changes in a future upgrade.
    await asyncio.wait_for(server._started.wait(), timeout=10.0)
    await asyncio.sleep(0.1)
    try:
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        server_task.cancel()
        with contextlib.suppress(asyncio.CancelledError, TimeoutError):
            await asyncio.wait_for(server_task, timeout=2.0)


@pytest.mark.anyio
async def test_stateless_http_initialize_returns_no_session_id_header():
    """With stateless_http=True, no Mcp-Session-Id is ever minted -- there is
    no server-side session to key it to."""
    async with _run_stateless_server(create_app()) as url:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                json=_MCP_INITIALIZE,
                headers={"Content-Type": "application/json", "Accept": _MCP_ACCEPT},
            )

    assert response.status_code == 200, f"Expected 200 but got {response.status_code}: {response.text[:500]}"
    assert "mcp-session-id" not in response.headers


@pytest.mark.anyio
async def test_stateless_http_tool_call_succeeds_with_unknown_session_id():
    """The actual  Finding 3 regression proof: a tool call carrying a
    Mcp-Session-Id that this process never created (standing in for a request
    that autoscaling/recycling routed to a *different* Cloud Run instance
    than the one that handled `initialize`) must still succeed under
    stateless_http=True, since every request gets a fresh transport rather
    than a session-manager lookup keyed on that header."""
    unknown_session_id = "session-id-this-process-never-issued"
    async with _run_stateless_server(create_app()) as url:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "ping", "arguments": {}},
                },
                headers={
                    "Content-Type": "application/json",
                    "Accept": _MCP_ACCEPT,
                    "Mcp-Session-Id": unknown_session_id,
                },
            )

    assert response.status_code == 200, f"Expected 200 but got {response.status_code}: {response.text[:500]}"


# ---------------------------------------------------------------------------
# Event-loop offload: sync tools must not block the asyncio loop
# (see app/main.py's _offload_to_thread)
# ---------------------------------------------------------------------------


def test_offload_to_thread_wrapper_is_coroutine_with_original_signature():
    import inspect

    wrapped = main_module._offload_to_thread(execute_sql)

    assert inspect.iscoroutinefunction(wrapped)
    assert inspect.signature(wrapped) == inspect.signature(execute_sql)
    assert wrapped.__name__ == "execute_sql"
    assert wrapped.__doc__ == execute_sql.__doc__


@pytest.mark.anyio
async def test_slow_sync_tool_does_not_block_event_loop():
    import threading
    import time

    loop_thread = threading.get_ident()
    tool_thread: list[int] = []

    def slow_tool() -> dict:
        tool_thread.append(threading.get_ident())
        time.sleep(0.5)
        return {"ok": True}

    wrapped = main_module._offload_to_thread(slow_tool)

    ticks = 0

    async def ticker() -> None:
        nonlocal ticks
        while True:
            await asyncio.sleep(0.02)
            ticks += 1

    ticker_task = asyncio.create_task(ticker())
    try:
        assert await wrapped() == {"ok": True}
    finally:
        ticker_task.cancel()

    assert tool_thread[0] != loop_thread
    assert ticks >= 10


@pytest.mark.anyio
async def test_offloaded_tool_propagates_exceptions():
    def boom() -> dict:
        raise ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        await main_module._offload_to_thread(boom)()


@pytest.mark.anyio
async def test_offloaded_tool_preserves_contextvars():
    import contextvars

    var: contextvars.ContextVar[str] = contextvars.ContextVar("var")
    var.set("from-request")

    def read_var() -> dict:
        return {"value": var.get()}

    assert await main_module._offload_to_thread(read_var)() == {"value": "from-request"}


@pytest.mark.anyio
async def test_registered_tools_run_off_the_event_loop(fake_bq_client):
    import threading

    loop_thread = threading.get_ident()
    seen: list[int] = []

    def record_thread() -> list[str]:
        seen.append(threading.get_ident())
        return ["analytics"]

    fake_bq_client.list_datasets.side_effect = record_thread

    async with Client(mcp) as client:
        result = await client.call_tool("list_datasets", {})

    assert result.data == {"datasets": ["analytics"]}
    assert seen and seen[0] != loop_thread
