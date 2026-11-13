"""Data Lineage client and Mermaid diagram builder.

Wraps `google.cloud.datacatalog_lineage.LineageClient` to return upstream and
downstream lineage (fixed at three levels) plus a ready-to-render Mermaid
`graph LR` diagram. A table with no recorded lineage returns empty
lists/diagram rather than raising.
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from google.api_core.exceptions import NotFound
from google.cloud import datacatalog_lineage
from proto.marshal.collections.maps import MapComposite
from proto.marshal.collections.repeated import RepeatedComposite

# Matches the reference implementation's `DEFAULT_LOCATION` call-site default exactly.
_DEFAULT_LOCATION = "us-central1"

# Link name format: projects/{project}/locations/{location}/processes/{process}/runs/{run}/lineageEvents/{event}
# Ported verbatim from the reference implementation's `extractProcessNameFromLink` regex --
# deliberate fidelity to the reference implementation ("1:1 port ... not an
# oversight"). Note this pattern is anchored to a *process*-shaped link name;
# real `Link.name` values observed from the live API are actually shaped
# `projects/{project}/locations/{location}/links/{link}` (no `processes/`
# segment), so this regex may rarely/never match in practice -- ported as-is
# regardless, per the explicit instruction not to "fix" reference quirks.
_PROCESS_NAME_PATTERN = re.compile(r"projects/[^/]+/locations/[^/]+/processes/([^/]+)")

# the reference implementation's exact error message text for the NOT_FOUND / lineage-not-
# enabled branch -- must not be reworded, other code (app/main.py's
# get_data_lineage) matches against a substring of this message.
_LINEAGE_NOT_AVAILABLE_MESSAGE = (
    "Data Lineage API is not enabled or no lineage data available. "
    "Please ensure the Data Lineage API is enabled in your GCP project."
)


class LineageClient:
    """Thin wrapper around `google.cloud.datacatalog_lineage.LineageClient`
    for BigQuery table lineage lookups. Instantiating this class builds a
    real `datacatalog_lineage.LineageClient` immediately (resolves ADC
    synchronously) -- callers (`app/main.py`'s `_get_lineage_client()`) are
    responsible for deferring construction until first use, mirroring
    `BigQueryClient`'s existing pattern.
    """

    def __init__(self, project_id: str, location: str = _DEFAULT_LOCATION) -> None:
        self._client = datacatalog_lineage.LineageClient()
        self.project_id = project_id
        self.location = location

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_table_lineage(
        self, dataset_id: str, table_id: str, max_depth: int = 3
    ) -> dict[str, Any]:
        """Returns a `LineageResult`-shaped dict (`upstream`, `downstream`,
        `links`, `mermaidDiagram`) for the given BigQuery table.

        Raises a domain error with the reference implementation's exact "Data Lineage
        API is not enabled..." message when the underlying search fails with
        a `NotFound` (gRPC code 5) or a message containing `"NOT_FOUND"`; any
        other exception re-raises unchanged.
        """
        fully_qualified_name = f"bigquery:{self.project_id}.{dataset_id}.{table_id}"

        try:
            with ThreadPoolExecutor(max_workers=2) as executor:
                upstream_future = executor.submit(
                    self._search_links, fully_qualified_name, "TARGET", max_depth
                )
                downstream_future = executor.submit(
                    self._search_links, fully_qualified_name, "SOURCE", max_depth
                )
                # `.result()` re-raises a worker exception in this (calling)
                # thread automatically -- mirrors `Promise.all`'s rejection
                # propagation.
                upstream_links = upstream_future.result()
                downstream_links = downstream_future.result()

            upstream = self._parse_links_to_nodes(upstream_links)
            downstream = self._parse_links_to_nodes(downstream_links)

            links = self._extract_links_with_processes(upstream_links + downstream_links)

            mermaid_diagram = self.generate_mermaid_diagram(
                dataset_id, table_id, upstream, downstream
            )

            return {
                "upstream": upstream,
                "downstream": downstream,
                "links": links,
                "mermaidDiagram": mermaid_diagram,
            }
        except Exception as exc:
            if isinstance(exc, NotFound) or "NOT_FOUND" in str(exc):
                raise RuntimeError(_LINEAGE_NOT_AVAILABLE_MESSAGE) from exc
            raise

    # ------------------------------------------------------------------
    # Search / node parsing
    # ------------------------------------------------------------------

    def _search_links(self, target: str, direction: str, max_depth: int) -> list[Any]:
        """Runs one `SearchLinks` call, capped at `max_depth * 10` results.

        `direction="TARGET"` searches for links whose *target* is `target`
        (i.e. upstream sources feeding into it); `direction="SOURCE"`
        searches for links whose *source* is `target` (i.e. downstream
        consumers) -- mirrors the reference implementation's own inverted call-site
        convention exactly (`getTableLineage` calls `searchLinks(fqn,
        'TARGET', ...)` for `upstreamLinks` and `searchLinks(fqn, 'SOURCE',
        ...)` for `downstreamLinks`).
        """
        parent = f"projects/{self.project_id}/locations/{self.location}"
        max_results = max_depth * 10
        entity_reference = {"fully_qualified_name": target}

        request_kwargs: dict[str, Any] = {"parent": parent}
        if direction == "SOURCE":
            request_kwargs["source"] = entity_reference
        else:
            request_kwargs["target"] = entity_reference

        request = datacatalog_lineage.SearchLinksRequest(**request_kwargs)

        links: list[Any] = []
        count = 0
        for link in self._client.search_links(request=request):
            if count >= max_results:
                break
            links.append(link)
            count += 1
        return links

    def _parse_links_to_nodes(self, links: list[Any]) -> list[dict[str, str]]:
        """De-duplicates resources across `links` into `LineageNode` dicts,
        preserving first-seen order (reference: `Set` + array push order; Python:
        a plain `set` for membership plus append-only list construction,
        which is order-preserving since we only ever append once per key).
        """
        nodes: list[dict[str, str]] = []
        seen: set[str] = set()

        for link in links:
            source = link.source.fully_qualified_name or None
            target = link.target.fully_qualified_name or None

            for resource in (source, target):
                if resource and resource not in seen:
                    seen.add(resource)
                    nodes.append(self._parse_resource_to_node(resource))

        return nodes

    def _parse_resource_to_node(self, resource: str) -> dict[str, str]:
        """Splits `"bigquery:project.dataset.table"` into `type="table"`
        (or `"job"` for any other prefix) and `displayName` as the last two
        dot-separated segments (`dataset.table`).
        """
        parts = resource.split(":")
        type_prefix = parts[0]
        full_name = parts[1] if len(parts) > 1 else resource

        name_parts = full_name.split(".")
        display_name = ".".join(name_parts[-2:])

        return {
            "resource": resource,
            "displayName": display_name,
            "type": "table" if type_prefix == "bigquery" else "job",
        }

    # ------------------------------------------------------------------
    # Mermaid diagram (non-empty case -- see mermaid_generator.py for the
    # empty-lineage diagram builder)
    # ------------------------------------------------------------------

    def generate_mermaid_diagram(
        self,
        dataset_id: str,
        table_id: str,
        upstream: list[dict[str, str]],
        downstream: list[dict[str, str]],
    ) -> str:
        """Same `graph LR` structure as the reference implementation: a styled `Current`
        node, one `U{index}` node per upstream item with a `U{i} --> Current`
        edge, one `D{index}` node per downstream item with a
        `Current --> D{i}` edge, then the `classDef current ...` line.
        """
        lines = ["graph LR"]
        current_node = f"{dataset_id}.{table_id}"
        lines.append(f'  Current["{current_node}"]:::current')

        for index, node in enumerate(upstream):
            node_id = f"U{index}"
            lines.append(f'  {node_id}["{node["displayName"]}"]')
            lines.append(f"  {node_id} --> Current")

        for index, node in enumerate(downstream):
            node_id = f"D{index}"
            lines.append(f'  {node_id}["{node["displayName"]}"]')
            lines.append(f"  Current --> {node_id}")

        lines.append("  classDef current fill:#f9f,stroke:#333,stroke-width:4px")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Process-detail enrichment
    # ------------------------------------------------------------------

    def _extract_links_with_processes(self, links: list[Any]) -> list[dict[str, Any]]:
        """For each raw link, resolves its owning `Process` (extracted from
        the link's resource name) once per unique process name (an
        in-method `dict` cache, mirroring the the reference implementation's `Map`), and attaches
        `ProcessDetails` to the `LineageLink`.

        The `process` key is *omitted* entirely (not set to `None`/`null`)
        when no process details resolve: the reference implementation's
        `{source, target, process: processDetails}` object literal, with
        `processDetails` left `undefined`, has its `process` key dropped
        entirely by `JSON.stringify` (which never serializes `undefined`
        values) rather than serialized as `null`. The "None/absent" ambiguity
        therefore resolves in favor of "absent".
        """
        lineage_links: list[dict[str, Any]] = []
        process_cache: dict[str, dict[str, Any]] = {}

        for link in links:
            source = link.source.fully_qualified_name or None
            target = link.target.fully_qualified_name or None

            if not source or not target:
                continue

            process_details: dict[str, Any] | None = None

            if link.name:
                process_name = self._extract_process_name_from_link(link.name)

                if process_name and process_name not in process_cache:
                    try:
                        process_details = self._get_process_details(process_name)
                        process_cache[process_name] = process_details
                    except Exception:  # noqa: BLE001 -- mirrors the reference implementation's catch-and-log
                        pass
                elif process_name:
                    process_details = process_cache.get(process_name)

            link_dict: dict[str, Any] = {"source": source, "target": target}
            if process_details is not None:
                link_dict["process"] = process_details
            lineage_links.append(link_dict)

        return lineage_links

    def _extract_process_name_from_link(self, link_name: str) -> str | None:
        match = _PROCESS_NAME_PATTERN.search(link_name)
        if not match:
            return None
        return f"projects/{self.project_id}/locations/{self.location}/processes/{match.group(1)}"

    def _get_process_details(self, process_name: str) -> dict[str, Any]:
        process = self._client.get_process(name=process_name)

        attributes = self._extract_attributes(process)

        # `"origin" in process` mirrors the reference implementation's `process.origin?`
        # optional-chain: Python protobuf message fields always return a
        # default instance on plain attribute access (never `None`), so
        # presence must be checked via the `in` (HasField-equivalent) test
        # instead of truthiness.
        source_type = process.origin.source_type.name if "origin" in process else "UNKNOWN"

        return {
            "processName": process.name or "",
            "displayName": process.display_name or "",
            "sourceType": source_type,
            "attributes": attributes,
            "description": attributes.get("description"),
            "createdBy": attributes.get("created_by"),
        }

    def _extract_attributes(self, process: Any) -> dict[str, Any]:
        attributes: dict[str, Any] = {}
        if process.attributes:
            for key, value in process.attributes.items():
                plain = self._to_plain_value(value)
                if plain is not None:
                    attributes[key] = plain
        return attributes

    @staticmethod
    def _to_plain_value(value: Any) -> Any:
        """Recursively converts a proto-plus-marshaled attribute value
        (`str`/`float`/`bool`/`None` already native, or a `MapComposite`/
        `RepeatedComposite` for `structValue`/`listValue`) into a plain,
        JSON-serializable Python `dict`/`list`/scalar.
        """
        if isinstance(value, MapComposite):
            return {key: LineageClient._to_plain_value(val) for key, val in value.items()}
        if isinstance(value, RepeatedComposite):
            return [LineageClient._to_plain_value(item) for item in value]
        return value
