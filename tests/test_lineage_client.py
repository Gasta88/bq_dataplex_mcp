"""Tests for app/services/lineage_client.py (LineageClient).

Mocks the underlying `google.cloud.datacatalog_lineage.LineageClient`
(`search_links`/`get_process`), following `tests/test_bigquery_client.py`'s
existing GCP-SDK-mock pattern --'s Test
Strategy (Unit Tests / Edge Cases)."""

from __future__ import annotations

from unittest.mock import patch

import google.protobuf.struct_pb2 as struct_pb2
import pytest
from google.api_core.exceptions import NotFound, PermissionDenied

from google.cloud import datacatalog_lineage as dl

from app.services.lineage_client import LineageClient

PROJECT_ID = "example-project"


@pytest.fixture
def mock_gcp_lineage_client():
    with patch("app.services.lineage_client.datacatalog_lineage.LineageClient") as mock_ctor:
        yield mock_ctor.return_value


def _make_client(mock_gcp_lineage_client) -> LineageClient:
    return LineageClient(PROJECT_ID)


def _link(source_fqn: str | None, target_fqn: str | None, name: str = "") -> dl.Link:
    kwargs: dict = {"name": name}
    if source_fqn is not None:
        kwargs["source"] = dl.EntityReference(fully_qualified_name=source_fqn)
    if target_fqn is not None:
        kwargs["target"] = dl.EntityReference(fully_qualified_name=target_fqn)
    return dl.Link(**kwargs)


# ---------------------------------------------------------------------------
# _parse_resource_to_node
# ---------------------------------------------------------------------------


def test_parse_resource_to_node_splits_bigquery_fqn_into_table_type(mock_gcp_lineage_client):
    client = _make_client(mock_gcp_lineage_client)

    node = client._parse_resource_to_node("bigquery:example-project.raw.events")

    assert node == {
        "resource": "bigquery:example-project.raw.events",
        "displayName": "raw.events",
        "type": "table",
    }


def test_parse_resource_to_node_treats_non_bigquery_prefix_as_job(mock_gcp_lineage_client):
    client = _make_client(mock_gcp_lineage_client)

    node = client._parse_resource_to_node("dataproc:example-project.us-central1.job123")

    assert node["type"] == "job"


# ---------------------------------------------------------------------------
# _parse_links_to_nodes
# ---------------------------------------------------------------------------


def test_parse_links_to_nodes_deduplicates_resource_seen_as_both_source_and_target(
    mock_gcp_lineage_client,
):
    client = _make_client(mock_gcp_lineage_client)

    links = [
        _link("bigquery:p.raw.events", "bigquery:p.analytics.dau"),
        _link("bigquery:p.analytics.dau", "bigquery:p.analytics.wau"),
    ]

    nodes = client._parse_links_to_nodes(links)

    resources = [n["resource"] for n in nodes]
    # "bigquery:p.analytics.dau" appears as target in link 1 and source in
    # link 2 -- must appear exactly once, in first-seen order.
    assert resources == [
        "bigquery:p.raw.events",
        "bigquery:p.analytics.dau",
        "bigquery:p.analytics.wau",
    ]


# ---------------------------------------------------------------------------
# generate_mermaid_diagram
# ---------------------------------------------------------------------------


def test_generate_mermaid_diagram_with_upstream_and_downstream(mock_gcp_lineage_client):
    client = _make_client(mock_gcp_lineage_client)

    upstream = [{"resource": "bigquery:p.raw.events", "displayName": "raw.events", "type": "table"}]
    downstream = [
        {"resource": "bigquery:p.analytics.wau", "displayName": "analytics.wau", "type": "table"}
    ]

    diagram = client.generate_mermaid_diagram("analytics", "daily_active_users", upstream, downstream)

    expected = (
        "graph LR\n"
        '  Current["analytics.daily_active_users"]:::current\n'
        '  U0["raw.events"]\n'
        "  U0 --> Current\n"
        '  D0["analytics.wau"]\n'
        "  Current --> D0\n"
        "  classDef current fill:#f9f,stroke:#333,stroke-width:4px"
    )
    assert diagram == expected


def test_generate_mermaid_diagram_with_no_upstream_or_downstream_still_renders_current_node(
    mock_gcp_lineage_client,
):
    client = _make_client(mock_gcp_lineage_client)

    diagram = client.generate_mermaid_diagram("analytics", "daily_active_users", [], [])

    expected = (
        "graph LR\n"
        '  Current["analytics.daily_active_users"]:::current\n'
        "  classDef current fill:#f9f,stroke:#333,stroke-width:4px"
    )
    assert diagram == expected


# ---------------------------------------------------------------------------
# _extract_attributes -- real google.protobuf.struct_pb2.Value instances,
# not mocked dicts.
# ---------------------------------------------------------------------------


def test_extract_attributes_branches_on_each_value_oneof(mock_gcp_lineage_client):
    client = _make_client(mock_gcp_lineage_client)

    process = dl.Process(
        attributes={
            "description": struct_pb2.Value(string_value="daily_active_users ETL"),
            "priority": struct_pb2.Value(number_value=3),
            "enabled": struct_pb2.Value(bool_value=True),
            "config": struct_pb2.Value(
                struct_value=struct_pb2.Struct(
                    fields={"retries": struct_pb2.Value(number_value=2)}
                )
            ),
            "tags": struct_pb2.Value(
                list_value=struct_pb2.ListValue(
                    values=[struct_pb2.Value(string_value="etl"), struct_pb2.Value(string_value="daily")]
                )
            ),
            "unused": struct_pb2.Value(null_value=struct_pb2.NullValue.NULL_VALUE),
        }
    )

    attributes = client._extract_attributes(process)

    assert attributes["description"] == "daily_active_users ETL"
    assert attributes["priority"] == 3
    assert attributes["enabled"] is True
    assert attributes["config"] == {"retries": 2}
    assert attributes["tags"] == ["etl", "daily"]
    # null_value resolves to None and is skipped entirely, matching the
    # reference implementation's implicit behavior (none of its five oneof checks match
    # a `nullValue`-shaped object).
    assert "unused" not in attributes


def test_extract_attributes_returns_empty_dict_when_process_has_no_attributes(
    mock_gcp_lineage_client,
):
    client = _make_client(mock_gcp_lineage_client)

    assert client._extract_attributes(dl.Process()) == {}


# ---------------------------------------------------------------------------
# _extract_links_with_processes
# ---------------------------------------------------------------------------


def test_extract_links_with_processes_calls_get_process_once_per_unique_process_name(
    mock_gcp_lineage_client,
):
    client = _make_client(mock_gcp_lineage_client)

    process_link_name = (
        "projects/example-project/locations/us-central1/processes/abc123/runs/run1/lineageEvents/e1"
    )
    links = [
        _link("bigquery:p.raw.events", "bigquery:p.analytics.dau", name=process_link_name),
        _link("bigquery:p.raw.other", "bigquery:p.analytics.dau", name=process_link_name),
    ]

    fake_process = dl.Process(
        name="projects/example-project/locations/us-central1/processes/abc123",
        display_name="daily_active_users ETL",
        attributes={
            "description": struct_pb2.Value(string_value="ETL job"),
            "created_by": struct_pb2.Value(string_value="sa@example-project.iam.gserviceaccount.com"),
        },
    )
    mock_gcp_lineage_client.get_process.return_value = fake_process

    lineage_links = client._extract_links_with_processes(links)

    assert mock_gcp_lineage_client.get_process.call_count == 1
    assert lineage_links[0]["process"]["processName"] == fake_process.name
    assert lineage_links[0]["process"]["displayName"] == "daily_active_users ETL"
    assert lineage_links[0]["process"]["description"] == "ETL job"
    assert lineage_links[0]["process"]["createdBy"] == "sa@example-project.iam.gserviceaccount.com"
    # Second link resolves the process from cache -- same details, no second call.
    assert lineage_links[1]["process"]["processName"] == fake_process.name


def test_extract_links_with_processes_omits_process_key_when_no_resolvable_name(
    mock_gcp_lineage_client,
):
    # The `process` key is *absent* entirely (not `None`) when unresolved --
    # confirmed against the reference implementation,
    # whose `JSON.stringify` drops the `process: undefined` field rather than
    # emitting `process: null`. See _extract_links_with_processes's docstring.
    client = _make_client(mock_gcp_lineage_client)

    links = [_link("bigquery:p.raw.events", "bigquery:p.analytics.dau", name="")]

    lineage_links = client._extract_links_with_processes(links)

    assert lineage_links == [
        {
            "source": "bigquery:p.raw.events",
            "target": "bigquery:p.analytics.dau",
        }
    ]
    assert "process" not in lineage_links[0]
    mock_gcp_lineage_client.get_process.assert_not_called()


def test_extract_process_name_from_link_returns_none_for_real_world_link_name_format(
    mock_gcp_lineage_client,
):
    # Confirms the code-comment-documented quirk: real `Link.name` values are
    # shaped `projects/{p}/locations/{l}/links/{link}` (no `processes/`
    # segment), so this regex, ported verbatim from the reference,
    # legitimately never matches in practice.
    client = _make_client(mock_gcp_lineage_client)

    assert (
        client._extract_process_name_from_link(
            "projects/example-project/locations/us-central1/links/abc123"
        )
        is None
    )


def test_extract_links_with_processes_swallows_get_process_failure(mock_gcp_lineage_client):
    # Mirrors the reference implementation's `try { ... } catch (error) { ... }`
    # around `getProcessDetails` -- a failed process lookup must not abort
    # the whole lineage result, just leave that link's `process` key absent.
    client = _make_client(mock_gcp_lineage_client)
    mock_gcp_lineage_client.get_process.side_effect = RuntimeError("boom")

    process_link_name = (
        "projects/example-project/locations/us-central1/processes/abc123/runs/run1/lineageEvents/e1"
    )
    links = [_link("bigquery:p.raw.events", "bigquery:p.analytics.dau", name=process_link_name)]

    lineage_links = client._extract_links_with_processes(links)

    assert "process" not in lineage_links[0]


def test_extract_links_with_processes_skips_links_missing_source_or_target(
    mock_gcp_lineage_client,
):
    client = _make_client(mock_gcp_lineage_client)

    links = [_link(None, "bigquery:p.analytics.dau"), _link("bigquery:p.raw.events", None)]

    assert client._extract_links_with_processes(links) == []


# ---------------------------------------------------------------------------
# get_table_lineage
# ---------------------------------------------------------------------------


def test_get_table_lineage_calls_both_directions_and_caps_at_max_depth_times_ten(
    mock_gcp_lineage_client,
):
    client = _make_client(mock_gcp_lineage_client)

    many_links = [
        _link(f"bigquery:p.raw.t{i}", "bigquery:p.analytics.dau") for i in range(50)
    ]
    # Each direction's `_search_links` call must iterate its own independent
    # pager -- a shared `return_value` iterator would be split unpredictably
    # between the two concurrent `ThreadPoolExecutor` workers.
    mock_gcp_lineage_client.search_links.side_effect = lambda **kwargs: iter(many_links)

    result = client.get_table_lineage("analytics", "dau", max_depth=3)

    # 30 = max_depth(3) * 10, applied independently per direction (search_links
    # is called twice -- once per direction -- each capped separately). Every
    # link shares the same target ("bigquery:p.analytics.dau"), so the
    # de-duplicated node count is 30 distinct sources + 1 shared target = 31,
    # not 30 -- the cap applies to raw *links* consumed, not to node count.
    assert mock_gcp_lineage_client.search_links.call_count == 2
    source_nodes = [n for n in result["upstream"] if n["resource"].startswith("bigquery:p.raw.t")]
    assert len(source_nodes) == 30


def test_get_table_lineage_raises_domain_error_on_notfound(mock_gcp_lineage_client):
    client = _make_client(mock_gcp_lineage_client)
    mock_gcp_lineage_client.search_links.side_effect = NotFound("no lineage")

    with pytest.raises(RuntimeError, match="Data Lineage API is not enabled"):
        client.get_table_lineage("analytics", "dau")


def test_get_table_lineage_raises_domain_error_when_message_contains_not_found_literal(
    mock_gcp_lineage_client,
):
    client = _make_client(mock_gcp_lineage_client)
    mock_gcp_lineage_client.search_links.side_effect = RuntimeError("NOT_FOUND: nothing here")

    with pytest.raises(RuntimeError, match="Data Lineage API is not enabled"):
        client.get_table_lineage("analytics", "dau")


def test_get_table_lineage_reraises_other_errors_unchanged(mock_gcp_lineage_client):
    client = _make_client(mock_gcp_lineage_client)
    mock_gcp_lineage_client.search_links.side_effect = PermissionDenied("nope")

    with pytest.raises(PermissionDenied):
        client.get_table_lineage("analytics", "dau")


def test_get_table_lineage_returns_lineage_result_shaped_dict(mock_gcp_lineage_client):
    client = _make_client(mock_gcp_lineage_client)

    upstream_link = _link("bigquery:example-project.raw.events", "bigquery:example-project.analytics.dau")
    mock_gcp_lineage_client.search_links.return_value = iter([upstream_link])

    result = client.get_table_lineage("analytics", "dau", max_depth=3)

    assert set(result.keys()) == {"upstream", "downstream", "links", "mermaidDiagram"}
    assert isinstance(result["mermaidDiagram"], str)
    assert result["mermaidDiagram"].startswith("graph LR")


# ---------------------------------------------------------------------------
# Edge case: no link has a resolvable process (no crash, no `process` key).
# ---------------------------------------------------------------------------


def test_extract_links_with_processes_renders_fine_with_no_resolvable_processes(
    mock_gcp_lineage_client,
):
    client = _make_client(mock_gcp_lineage_client)

    links = [
        _link("bigquery:p.raw.a", "bigquery:p.analytics.dau"),
        _link("bigquery:p.raw.b", "bigquery:p.analytics.dau"),
    ]

    lineage_links = client._extract_links_with_processes(links)

    assert all("process" not in link for link in lineage_links)
