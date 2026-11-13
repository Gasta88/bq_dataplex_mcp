"""Tests for app/services/mermaid_generator.py (generate_empty_lineage_diagram).

Covers the exact expected output of the empty-lineage Mermaid builder.
"""

from __future__ import annotations

from app.services.mermaid_generator import generate_empty_lineage_diagram


def test_generate_empty_lineage_diagram_matches_ts_reference_exactly():
    result = generate_empty_lineage_diagram(
        "analytics", "daily_active_users", "No lineage data available for this table"
    )

    expected = (
        "graph LR\n"
        '  Current["analytics.daily_active_users"]:::current\n'
        '  Note["No lineage data available for this table"]:::note\n'
        "  Note -.-> Current\n"
        "  classDef current fill:#f9f,stroke:#333,stroke-width:4px\n"
        "  classDef note fill:#fff,stroke:#999,stroke-width:1px,stroke-dasharray: 5 5"
    )
    assert result == expected


def test_generate_empty_lineage_diagram_interpolates_all_three_arguments():
    result = generate_empty_lineage_diagram("raw", "events", "custom message")

    assert '  Current["raw.events"]:::current' in result
    assert '  Note["custom message"]:::note' in result
