"""Shared BigQuery on-demand-pricing arithmetic.

Single source of truth for the `estimatedCostUsd` formula used by both the
audit row and `execute_sql`'s tool response.

The estimate reflects Google's published on-demand per-TiB price. When a
flat-rate reservation is configured there is no true per-byte cost, so the
figure is a notional cost-attribution proxy rather than an actual bill. This
module performs no environment-aware branching; callers surface the caveat.
"""

from __future__ import annotations

# 1 TiB = 1024**4 bytes, matching BigQueryClient.execute_sql's own
# `estimatedGiB` (1024**3) unit convention one level up.
_BYTES_PER_TIB = 1024**4


def estimate_cost_usd(total_bytes_processed: int, price_per_tib_usd: float) -> float:
    """Return the on-demand-equivalent cost estimate for `total_bytes_processed`
    bytes at `price_per_tib_usd` USD per TiB.

    Pure, in-process float arithmetic -- no I/O, no exceptions raised for any
    finite numeric input (including zero). Callers with malformed/missing
    inputs are expected to guard before calling (see `app/audit.py`'s
    fail-safe-to-`None` wrapper around its own call site).
    """
    return (total_bytes_processed / _BYTES_PER_TIB) * price_per_tib_usd
