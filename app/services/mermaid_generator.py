"""Mermaid diagram builder for tables with no lineage data."""

from __future__ import annotations


def generate_empty_lineage_diagram(dataset_id: str, table_id: str, message: str) -> str:
    """Build the Mermaid `graph LR` diagram used when a table has no lineage
    data available.

    Byte-for-byte port of the reference implementation's template literal: same `Current`
    node (styled via the `current` classDef), a dashed `Note -.-> Current`
    edge carrying `message`, and both `classDef` styling lines.
    """
    return (
        "graph LR\n"
        f'  Current["{dataset_id}.{table_id}"]:::current\n'
        f'  Note["{message}"]:::note\n'
        "  Note -.-> Current\n"
        "  classDef current fill:#f9f,stroke:#333,stroke-width:4px\n"
        "  classDef note fill:#fff,stroke:#999,stroke-width:1px,stroke-dasharray: 5 5"
    )
