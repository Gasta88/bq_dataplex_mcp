"""Focused unit tests for app/pricing.py's `estimate_cost_usd`."""

from __future__ import annotations

import math

import pytest

from app.pricing import estimate_cost_usd


def test_estimate_cost_usd_zero_bytes_returns_zero():
    assert estimate_cost_usd(0, 6.25) == 0.0


def test_estimate_cost_usd_known_pair_matches_hand_computed_value():
    assert estimate_cost_usd(1024**4, 6.25) == pytest.approx(6.25)
    assert estimate_cost_usd(2 * 1024**4, 6.25) == pytest.approx(12.5)


def test_estimate_cost_usd_large_bytes_value_is_finite_and_positive():
    # ~1 PiB-equivalent.
    huge_bytes = 1024**5
    result = estimate_cost_usd(huge_bytes, 6.25)

    assert math.isfinite(result)
    assert result > 0
    assert result == pytest.approx(huge_bytes / 1024**4 * 6.25)
