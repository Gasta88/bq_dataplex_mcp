"""Tests for app/audit.py: unit, integration, and lifespan scenarios.

Coverage targets:
- `_safe_json`: None passthrough, JSON serialization, str() fallback,
  truncation.
- Decorator: deque population, latency, `userEmail` resolution (authenticated /
  missing-email-claim anomaly / dev-posture fallback), query extraction, row
  recorded on exception, overflow drop + WARNING, requestId UUID4, createdAt
  UTC ISO. Row shape is intentionally a subset of the live BigQuery table's
  columns.
- Flusher: `insert_rows_json` called per row, error handling, FIFO order.
- Lifespan: flusher start/stop and final drain.
- Concurrency: parallel tool calls all produce distinct audit rows.
"""

import asyncio
import functools
import inspect
import json
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

import app.audit as audit_module
from app.audit import (
    _audit_deque,
    _safe_json,
    audit_tool_call,
    start_audit_flusher,
)
from app.config import settings
from mcp.server.auth.middleware.auth_context import AuthenticatedUser, auth_context_var
from mcp.server.auth.provider import AccessToken

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _wait_mock_called(mock_fn, min_calls: int = 1, timeout: float = 5.0) -> None:
    """Poll until mock_fn.call_count >= min_calls or timeout, avoiding fixed sleeps."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while mock_fn.call_count < min_calls and loop.time() < deadline:
        await asyncio.sleep(0.05)


def _make_simple_tool(name="dummy_tool", has_query=True, raise_exc=None):
    """Return a plain sync function optionally decorated with @audit_tool_call."""
    if has_query:

        def fn(query: str, limit: int = 10) -> dict:
            if raise_exc:
                raise raise_exc
            return {"result": "ok", "q": query}

        fn.__name__ = name
    else:

        def fn(doc_id: str) -> dict:
            if raise_exc:
                raise raise_exc
            return {"result": "ok", "id": doc_id}

        fn.__name__ = name
    return audit_tool_call(fn)


def _make_noarg_tool(name="noarg_tool", return_value=None, raise_exc=None):
    """Return a plain sync function with no parameters, decorated with @audit_tool_call."""

    def fn() -> dict:
        if raise_exc:
            raise raise_exc
        return return_value if return_value is not None else {"result": "ok"}

    fn.__name__ = name
    return audit_tool_call(fn)


def _make_circular():
    """A dict containing itself — json.dumps(..., default=str) still raises
    ValueError on this (cycle detection happens before `default` is ever
    consulted), so it exercises _safe_json's str() fallback branch. Python's
    container repr() is itself cycle-safe (prints '...'), so str() on this
    never raises/recurses infinitely — a true non-JSON-serializable value
    that _safe_json must still turn into *something* without crashing."""
    d: dict = {}
    d["self"] = d
    return d


@pytest.fixture(autouse=True)
def reset_auth_context():
    """Reset the auth_context_var between tests so no cross-test leakage.

    Local to this module (unlike `_clear_audit_deque`, which is repo-wide in
    tests/conftest.py) -- only this file directly manipulates
    `auth_context_var`; other test modules exercise the real HTTP auth path
    instead (see tests/test_mcp_auth_integration.py).
    """
    token = auth_context_var.set(None)
    yield
    auth_context_var.reset(token)


# ---------------------------------------------------------------------------
# _safe_json unit tests
# ---------------------------------------------------------------------------


class TestSafeJson:
    def test_none_returns_none(self):
        assert _safe_json(None) is None

    def test_serializes_plain_dict(self):
        assert json.loads(_safe_json({"a": 1})) == {"a": 1}

    def test_serializes_plain_list(self):
        assert json.loads(_safe_json([1, 2, 3])) == [1, 2, 3]

    def test_non_serializable_value_falls_back_to_str(self):
        circular = _make_circular()
        result = _safe_json(circular)
        assert isinstance(result, str)
        assert "self" in result

    def test_oversized_value_is_truncated(self):
        big_value = {"blob": "x" * 100_000}
        result = _safe_json(big_value)
        assert len(result) <= 32_768
        assert result.endswith("...<truncated>")


# ---------------------------------------------------------------------------
# Decorator unit tests
# ---------------------------------------------------------------------------


class TestDecoratorDequePopulation:
    def test_single_call_appends_one_row(self):
        fn = _make_simple_tool()
        fn(query="hello")
        assert len(_audit_deque) == 1

    def test_row_has_expected_tool_name(self):
        fn = _make_simple_tool(name="my_tool")
        fn(query="hello")
        row = _audit_deque[0]
        assert row["toolName"] == "my_tool"

    def test_row_latency_ms_non_negative(self):
        fn = _make_simple_tool()
        fn(query="hello")
        row = _audit_deque[0]
        assert row["latencyMs"] >= 0

    def test_row_has_no_success_or_error_message_fields(self):
        """The proposed schema has no success/errorMessage columns — the row must not include them."""
        fn = _make_simple_tool()
        fn(query="hello")
        row = _audit_deque[0]
        assert "success" not in row
        assert "errorMessage" not in row

    def test_return_value_unchanged(self):
        fn = _make_simple_tool()
        result = fn(query="hello")
        assert result == {"result": "ok", "q": "hello"}


class TestDecoratorUserEmail:
    """userEmail resolution per  -- column stays REQUIRED, no code
    path in app/audit.py ever produces userEmail is None."""

    def test_user_email_set_via_auth_context(self):
        at = AccessToken(
            token="tok",
            client_id="c1",
            scopes=[],
            subject="sub1",
            claims={"email": "alice@example.com"},
        )
        auth_context_var.set(AuthenticatedUser(at))
        fn = _make_simple_tool()
        fn(query="test")
        row = _audit_deque[0]
        assert row["userEmail"] == "alice@example.com"

    def test_missing_email_claim_falls_back_to_placeholder_and_logs_warning(self, caplog):
        """Validated token whose claims has no `email` key -> 's
        missing-email-claim placeholder, plus a distinctly-tagged WARNING."""
        import logging

        at = AccessToken(
            token="tok",
            client_id="c1",
            scopes=[],
            subject="sub-no-email",
            claims={"sub": "sub-no-email"},
        )
        auth_context_var.set(AuthenticatedUser(at))
        fn = _make_simple_tool()
        with caplog.at_level(logging.WARNING, logger="app.audit"):
            fn(query="test")
        row = _audit_deque[0]
        assert row["userEmail"] == "missing-email-claim@bq-dataplex-mcp.invalid"
        assert any("missing-email-claim anomaly" in r.message for r in caplog.records)

    def test_claims_is_none_falls_back_to_placeholder_and_logs_warning(self, caplog):
        """Validated token with claims=None -> same missing-email-claim
        placeholder + distinctly-tagged WARNING."""
        import logging

        at = AccessToken(
            token="tok",
            client_id="c1",
            scopes=[],
            subject="sub-null-claims",
            claims=None,
        )
        auth_context_var.set(AuthenticatedUser(at))
        fn = _make_simple_tool()
        with caplog.at_level(logging.WARNING, logger="app.audit"):
            fn(query="test")
        row = _audit_deque[0]
        assert row["userEmail"] == "missing-email-claim@bq-dataplex-mcp.invalid"
        assert any("missing-email-claim anomaly" in r.message for r in caplog.records)

    def test_oauth_not_configured_falls_back_to_dev_placeholder(self, monkeypatch):
        """Dev has no GOOGLE_OAUTH_CLIENT_ID (no auth at all, no access
        token on any call) -> the separate dev-posture placeholder, distinct
        from the missing-email-claim anomaly placeholder above."""
        monkeypatch.setattr(settings, "google_oauth_client_id", "")
        fn = _make_simple_tool()
        fn(query="test")
        row = _audit_deque[0]
        assert row["userEmail"] == "dev-smoke-test@bq-dataplex-mcp.invalid"

    def test_dev_placeholder_and_missing_email_placeholder_are_distinguishable(self, monkeypatch, caplog):
        """The two non-authenticated-email fallback values/log lines must be
        distinct from each other ( requires them distinguishable in
        Cloud Logging)."""
        import logging

        with caplog.at_level(logging.WARNING, logger="app.audit"):
            # Dev-posture fallback.
            monkeypatch.setattr(settings, "google_oauth_client_id", "")
            fn = _make_simple_tool(name="dev_tool")
            fn(query="dev-call")

            # Missing-email-claim anomaly fallback.
            monkeypatch.setattr(settings, "google_oauth_client_id", "configured")
            at = AccessToken(
                token="tok", client_id="c1", scopes=[], subject="sub-x", claims={}
            )
            auth_context_var.set(AuthenticatedUser(at))
            fn2 = _make_simple_tool(name="anomaly_tool")
            fn2(query="anomaly-call")

        dev_row, anomaly_row = _audit_deque[0], _audit_deque[1]
        assert dev_row["userEmail"] == "dev-smoke-test@bq-dataplex-mcp.invalid"
        assert anomaly_row["userEmail"] == "missing-email-claim@bq-dataplex-mcp.invalid"
        assert dev_row["userEmail"] != anomaly_row["userEmail"]
        assert any("dev-posture fallback" in r.message for r in caplog.records)
        assert any("missing-email-claim anomaly" in r.message for r in caplog.records)

    def test_no_leakage_across_calls(self):
        """An authenticated call followed by a missing-email-claim-anomaly
        call produces two rows with correct, independent userEmail values."""
        at = AccessToken(
            token="tok",
            client_id="c1",
            scopes=[],
            subject="u1",
            claims={"email": "alice@example.com"},
        )
        fn = _make_simple_tool()

        token = auth_context_var.set(AuthenticatedUser(at))
        fn(query="first")
        auth_context_var.reset(token)

        at2 = AccessToken(token="tok2", client_id="c1", scopes=[], subject="u2", claims={})
        auth_context_var.set(AuthenticatedUser(at2))
        fn(query="second")

        assert _audit_deque[0]["userEmail"] == "alice@example.com"
        assert _audit_deque[1]["userEmail"] == "missing-email-claim@bq-dataplex-mcp.invalid"


class TestDecoratorQueryExtraction:
    def test_query_extracted_from_positional_arg(self):
        fn = _make_simple_tool()
        fn("my search string")
        row = _audit_deque[0]
        assert row["query"] == "my search string"

    def test_query_extracted_from_keyword_arg(self):
        fn = _make_simple_tool()
        fn(query="kw search")
        row = _audit_deque[0]
        assert row["query"] == "kw search"

    def test_query_is_none_for_tools_without_query_param(self):
        fn = _make_simple_tool(has_query=False)
        fn(doc_id="abc123")
        row = _audit_deque[0]
        assert row["query"] is None


class TestDecoratorExceptionHandling:
    def test_row_still_recorded_on_exception(self):
        exc = ValueError("boom")
        fn = _make_simple_tool(raise_exc=exc)
        with pytest.raises(ValueError, match="boom"):
            fn(query="test")
        assert len(_audit_deque) == 1
        row = _audit_deque[0]
        assert row["toolName"] == "dummy_tool"
        assert "success" not in row
        assert "errorMessage" not in row

    def test_exception_is_reraised(self):
        fn = _make_simple_tool(raise_exc=RuntimeError("reraise me"))
        with pytest.raises(RuntimeError, match="reraise me"):
            fn(query="test")


class TestDecoratorOverflow:
    def test_overflow_drops_current_row_and_logs_warning(self, monkeypatch, caplog):
        monkeypatch.setattr(settings, "audit_queue_bound", 1)
        # Pre-fill deque with one sentinel so len == bound.
        sentinel = {"sentinel": True}
        _audit_deque.append(sentinel)

        fn = _make_simple_tool()
        import logging

        with caplog.at_level(logging.WARNING, logger="app.audit"):
            fn(query="overflow test")

        # Deque still has exactly 1 item (the sentinel), new row was dropped.
        assert len(_audit_deque) == 1
        assert _audit_deque[0] is sentinel
        assert any("dropping" in r.message.lower() for r in caplog.records)
        # The stable sentinel token backing deploy/main.tf's
        # google_logging_metric must be present verbatim.
        assert any(
            "audit_queue_overflow_dropped" in r.message for r in caplog.records
        )

    def test_overflow_sentinel_logs_on_every_dropped_row(self, monkeypatch, caplog):
        """Guards against a future refactor silently dropping the log call
        on anything but the first overflow -- the sentinel must fire on
        every dropped row, not just once."""
        monkeypatch.setattr(settings, "audit_queue_bound", 2)
        fn = _make_simple_tool()
        import logging

        with caplog.at_level(logging.WARNING, logger="app.audit"):
            for i in range(5):
                fn(query=f"call-{i}")

        # First 2 calls fit under the bound; the remaining 3 overflow.
        assert len(_audit_deque) == 2
        overflow_records = [
            r for r in caplog.records if "audit_queue_overflow_dropped" in r.message
        ]
        assert len(overflow_records) == 3

    def test_overflow_never_raises_and_return_value_unaffected(self, monkeypatch):
        """The wrapped function's return value/exception behavior must be
        identical whether the row was enqueued or dropped for overflow --
        the audit path is never allowed to affect the tool response."""
        monkeypatch.setattr(settings, "audit_queue_bound", 1)
        _audit_deque.append({"sentinel": True})

        fn = _make_simple_tool()
        result = fn(query="overflow test")
        assert result == {"result": "ok", "q": "overflow test"}

        exc = ValueError("boom during overflow")
        fn_raising = _make_simple_tool(name="raising_tool", raise_exc=exc)
        with pytest.raises(ValueError, match="boom during overflow"):
            fn_raising(query="test")
        # Still just the one pre-existing sentinel row -- both calls dropped.
        assert len(_audit_deque) == 1

    def test_wrapper_stays_synchronous(self):
        """Structural check: audit_tool_call's wrapper must never become a
        coroutine function -- the enqueue path must stay O(1)/non-blocking
        with no `await` on I/O. A future refactor that made this async
        (e.g. to `await` the BQ write inline) would silently regress the
        "never on the critical path" property."""
        fn = _make_simple_tool()
        assert inspect.iscoroutinefunction(fn) is False

    def test_no_overflow_when_deque_is_below_bound(self, monkeypatch):
        monkeypatch.setattr(settings, "audit_queue_bound", 5)
        fn = _make_simple_tool()
        fn(query="test")
        assert len(_audit_deque) == 1

    def test_audit_queue_bound_rejects_zero_via_env_var(self, monkeypatch):
        """When AUDIT_QUEUE_BOUND=0 is set, it should be rejected and default to 1000."""
        monkeypatch.setenv("AUDIT_QUEUE_BOUND", "0")
        from app.config import _parse_audit_queue_bound

        result = _parse_audit_queue_bound()
        assert result == 1000, "audit_queue_bound=0 must be rejected, defaulting to 1000"

    def test_audit_queue_bound_rejects_negative_via_env_var(self, monkeypatch):
        """When AUDIT_QUEUE_BOUND is a negative number, it should be rejected and default to 1000."""
        monkeypatch.setenv("AUDIT_QUEUE_BOUND", "-5")
        from app.config import _parse_audit_queue_bound

        result = _parse_audit_queue_bound()
        assert result == 1000, "negative audit_queue_bound must be rejected, defaulting to 1000"

    def test_audit_queue_bound_accepts_positive_integers(self, monkeypatch):
        """When AUDIT_QUEUE_BOUND is a positive integer, it should be accepted."""
        monkeypatch.setenv("AUDIT_QUEUE_BOUND", "500")
        from app.config import _parse_audit_queue_bound

        result = _parse_audit_queue_bound()
        assert result == 500, "positive audit_queue_bound values must be accepted"


class TestDecoratorMetadata:
    def test_request_id_is_valid_uuid4(self):
        fn = _make_simple_tool()
        fn(query="uuid test")
        row = _audit_deque[0]
        parsed = uuid.UUID(row["requestId"], version=4)
        assert str(parsed) == row["requestId"]

    def test_created_at_is_utc_iso8601(self):
        fn = _make_simple_tool()
        fn(query="ts test")
        row = _audit_deque[0]
        assert row["createdAt"].endswith("Z"), f"createdAt not UTC: {row['createdAt']}"
        dt = datetime.fromisoformat(row["createdAt"].replace("Z", "+00:00"))
        assert dt.tzinfo == timezone.utc

    def test_functools_wraps_preserves_name(self):
        fn = _make_simple_tool(name="my_tool")
        assert fn.__name__ == "my_tool"

    def test_no_arg_tool_does_not_raise(self):
        """Mirrors a no-argument tool helper -- the decorator must not
        raise on functions with zero parameters."""
        fn = _make_noarg_tool()
        result = fn()
        assert result == {"result": "ok"}
        assert len(_audit_deque) == 1


class TestDecoratorRequestResponse:
    def test_request_contains_all_bound_args_positional_and_keyword(self):
        fn = _make_simple_tool()
        fn("hello", limit=25)
        row = _audit_deque[0]
        assert json.loads(row["request"]) == {"query": "hello", "limit": 25}

    def test_request_reflects_apply_defaults(self):
        fn = _make_simple_tool()
        fn(query="only-required")
        row = _audit_deque[0]
        assert json.loads(row["request"]) == {"query": "only-required", "limit": 10}

    def test_request_is_empty_object_for_noarg_tool(self):
        fn = _make_noarg_tool()
        fn()
        row = _audit_deque[0]
        assert row["request"] == "{}"

    def test_response_equals_serialized_return_value_on_success(self):
        fn = _make_simple_tool()
        fn(query="hello")
        row = _audit_deque[0]
        assert json.loads(row["response"]) == {"result": "ok", "q": "hello"}

    def test_response_is_none_when_wrapped_function_raises(self):
        exc = ValueError("boom")
        fn = _make_simple_tool(raise_exc=exc)
        with pytest.raises(ValueError, match="boom"):
            fn(query="test")
        row = _audit_deque[0]
        assert row["response"] is None

    def test_request_still_populated_when_wrapped_function_raises(self):
        exc = ValueError("boom")
        fn = _make_simple_tool(raise_exc=exc)
        with pytest.raises(ValueError, match="boom"):
            fn(query="test")
        row = _audit_deque[0]
        assert json.loads(row["request"]) == {"query": "test", "limit": 10}

    def test_non_serializable_argument_falls_back_to_str(self):
        fn = _make_simple_tool()
        circular = _make_circular()
        fn(query=circular)  # type: ignore[arg-type]
        row = _audit_deque[0]
        assert isinstance(row["request"], str)
        assert "query" in row["request"]

    def test_non_serializable_return_value_falls_back_to_str(self):
        circular = _make_circular()
        fn = _make_noarg_tool(return_value=circular)
        fn()
        row = _audit_deque[0]
        assert isinstance(row["response"], str)

    def test_oversized_response_is_truncated(self):
        big_value = {"blob": "x" * 100_000}
        fn = _make_noarg_tool(return_value=big_value)
        fn()
        row = _audit_deque[0]
        assert len(row["response"]) <= 32_768
        assert row["response"].endswith("...<truncated>")

    def test_row_still_recorded_and_appended_despite_truncation(self):
        big_value = {"blob": "x" * 100_000}
        fn = _make_noarg_tool(return_value=big_value)
        fn()
        assert len(_audit_deque) == 1

    def test_oversized_query_is_truncated(self):
        """Query column is also length-bounded (raw string, not JSON-encoded)
        to prevent row-size violations in BigQuery, especially for
        execute_sql with large generated SQL strings."""
        big_query = "SELECT " + "x" * 100_000
        fn = _make_simple_tool(name="big_query_tool")
        fn(query=big_query)
        row = _audit_deque[0]
        assert len(row["query"]) <= 32_768
        assert row["query"].endswith("...<truncated>")
        assert row["query"].startswith("SELECT ")


class TestDecoratorResultSizeBytes:
    """`resultSizeBytes` is a nullable integer column on the audit table."""

    def test_result_size_bytes_equals_response_json_byte_length(self):
        fn = _make_simple_tool()
        fn(query="hello")
        row = _audit_deque[0]
        assert row["resultSizeBytes"] == len(row["response"].encode("utf-8"))

    def test_result_size_bytes_is_none_when_response_is_none(self):
        exc = ValueError("boom")
        fn = _make_simple_tool(raise_exc=exc)
        with pytest.raises(ValueError, match="boom"):
            fn(query="test")
        row = _audit_deque[0]
        assert row["response"] is None
        assert row["resultSizeBytes"] is None

    def test_result_size_bytes_reflects_truncated_not_original_size(self):
        """Documents the accepted tradeoff: for results larger than
        _safe_json's 32,768-char max_len, resultSizeBytes
        measures the truncated, stored payload -- not the true,
        pre-truncation tool result size."""
        big_value = {"blob": "x" * 100_000}
        fn = _make_noarg_tool(return_value=big_value)
        fn()
        row = _audit_deque[0]
        assert row["resultSizeBytes"] == len(row["response"].encode("utf-8"))
        assert row["resultSizeBytes"] < len(json.dumps(big_value).encode("utf-8"))


class TestDecoratorBytesProcessedAndCost:
    """: `bytesProcessed`/`estimatedCostUsd` are populated
    for `execute_sql` rows only, derived purely from `totalBytesProcessed` in
    the tool's own already-computed return dict -- no new network call, and
    NULL for every other tool (FR5). Fails safe to None/None on any
    malformed/missing shape rather than raising (FR6)."""

    def test_execute_sql_populates_bytes_processed_and_cost(self, monkeypatch):
        monkeypatch.setattr(settings, "bq_price_per_tib_usd", 6.25)
        fn = _make_noarg_tool(
            name="execute_sql",
            return_value={
                "rows": [],
                "rowCount": 0,
                "schema": [],
                "totalBytesProcessed": str(1024**4),  # exactly 1 TiB
                "cacheHit": False,
                "jobId": "job1",
            },
        )
        fn()
        row = _audit_deque[0]
        assert row["bytesProcessed"] == 1024**4
        assert row["estimatedCostUsd"] == pytest.approx(6.25)

    def test_execute_sql_dry_run_shaped_result_also_populates_both_fields(self, monkeypatch):
        """FR4: the dry_run=True branch's result shape (no `rows`/`schema`,
        just `dryRun`/`totalBytesProcessed`/`estimatedGiB`) must also be
        captured."""
        monkeypatch.setattr(settings, "bq_price_per_tib_usd", 6.25)
        fn = _make_noarg_tool(
            name="execute_sql",
            return_value={
                "dryRun": True,
                "totalBytesProcessed": str(2 * 1024**4),  # 2 TiB
                "estimatedGiB": 2048.0,
            },
        )
        fn()
        row = _audit_deque[0]
        assert row["bytesProcessed"] == 2 * 1024**4
        assert row["estimatedCostUsd"] == pytest.approx(12.5)

    def test_execute_sql_zero_bytes_is_zero_not_none(self, monkeypatch):
        """A dry run where BigQuery itself reports 0 bytes processed is a
        real, valid result -- distinct from extraction failure -- so both
        fields must be 0/0.0, not None."""
        monkeypatch.setattr(settings, "bq_price_per_tib_usd", 6.25)
        fn = _make_noarg_tool(
            name="execute_sql",
            return_value={"dryRun": True, "totalBytesProcessed": "0", "estimatedGiB": 0.0},
        )
        fn()
        row = _audit_deque[0]
        assert row["bytesProcessed"] == 0
        assert row["estimatedCostUsd"] == 0.0

    def test_non_execute_sql_tools_leave_both_fields_none(self):
        """FR5: every non-execute_sql tool must produce NULL bytesProcessed/
        estimatedCostUsd, even when its result happens to contain a
        totalBytesProcessed-shaped key (defense against a naive `fn.__name__`
        check being bypassed)."""
        fn = _make_noarg_tool(
            name="list_datasets", return_value={"totalBytesProcessed": "12345"}
        )
        fn()
        row = _audit_deque[0]
        assert row["bytesProcessed"] is None
        assert row["estimatedCostUsd"] is None

    def test_missing_total_bytes_processed_key_degrades_to_none(self, caplog):
        """FR6: execute_sql result missing the key entirely -> None/None,
        no raise."""
        import logging

        fn = _make_noarg_tool(name="execute_sql", return_value={"rows": [], "rowCount": 0})
        with caplog.at_level(logging.WARNING, logger="app.audit"):
            fn()
        row = _audit_deque[0]
        assert row["bytesProcessed"] is None
        assert row["estimatedCostUsd"] is None

    def test_non_numeric_total_bytes_processed_degrades_to_none_and_logs_warning(self, caplog):
        """FR6: a malformed, non-numeric totalBytesProcessed string ->
        None/None, no raise, plus a WARNING log."""
        import logging

        fn = _make_noarg_tool(
            name="execute_sql", return_value={"totalBytesProcessed": "not-a-number"}
        )
        with caplog.at_level(logging.WARNING, logger="app.audit"):
            fn()
        row = _audit_deque[0]
        assert row["bytesProcessed"] is None
        assert row["estimatedCostUsd"] is None
        assert any(
            "failed to extract bytesProcessed" in r.message for r in caplog.records
        )

    def test_result_not_a_dict_degrades_to_none(self):
        """FR6: a non-dict execute_sql result (e.g. a future refactor
        returning something else entirely) must not raise."""
        fn = _make_noarg_tool(name="execute_sql", return_value="not-a-dict")
        fn()
        row = _audit_deque[0]
        assert row["bytesProcessed"] is None
        assert row["estimatedCostUsd"] is None

    def test_execute_sql_raises_before_result_exists_degrades_to_none(self):
        """Edge case: execute_sql raises (e.g. invalid SQL) before returning
        any result dict -- row is still recorded (existing behavior) with
        both new fields None, since there is no result to extract from."""
        exc = ValueError("invalid SQL")
        fn = _make_noarg_tool(name="execute_sql", raise_exc=exc)
        with pytest.raises(ValueError, match="invalid SQL"):
            fn()
        row = _audit_deque[0]
        assert row["bytesProcessed"] is None
        assert row["estimatedCostUsd"] is None

    def test_estimated_cost_usd_uses_configured_price_per_tib(self, monkeypatch):
        """Arithmetic pinned for a known bytesProcessed/price pair: exactly
        1 TiB processed -> cost equals the configured price verbatim."""
        monkeypatch.setattr(settings, "bq_price_per_tib_usd", 9.99)
        fn = _make_noarg_tool(
            name="execute_sql", return_value={"totalBytesProcessed": str(1024**4)}
        )
        fn()
        row = _audit_deque[0]
        assert row["estimatedCostUsd"] == pytest.approx(9.99)

    def test_estimated_cost_usd_scales_with_bytes_processed(self, monkeypatch):
        """Half a TiB processed -> half the configured price."""
        monkeypatch.setattr(settings, "bq_price_per_tib_usd", 6.25)
        fn = _make_noarg_tool(
            name="execute_sql", return_value={"totalBytesProcessed": str(1024**4 // 2)}
        )
        fn()
        row = _audit_deque[0]
        assert row["estimatedCostUsd"] == pytest.approx(3.125)

    def test_large_bytes_processed_does_not_overflow_or_lose_sane_precision(self, monkeypatch):
        """A full-table scan of a multi-PiB table must produce a finite,
        sane float, not an overflow/NaN/inf."""
        monkeypatch.setattr(settings, "bq_price_per_tib_usd", 6.25)
        huge_bytes = 5 * 1024**5  # 5 PiB
        fn = _make_noarg_tool(
            name="execute_sql", return_value={"totalBytesProcessed": str(huge_bytes)}
        )
        fn()
        row = _audit_deque[0]
        assert row["bytesProcessed"] == huge_bytes
        assert row["estimatedCostUsd"] == pytest.approx(huge_bytes / 1024**4 * 6.25)
        assert row["estimatedCostUsd"] > 0
        import math

        assert math.isfinite(row["estimatedCostUsd"])


class TestBqPricePerTibUsdSetting:
    """: `bq_price_per_tib_usd` env-var parsing, mirroring the
    existing `_parse_audit_queue_bound` test pattern in this same file."""

    def test_default_when_unset(self, monkeypatch):
        monkeypatch.delenv("BQ_PRICE_PER_TIB_USD", raising=False)
        from app.config import _parse_bq_price_per_tib_usd

        assert _parse_bq_price_per_tib_usd() == 6.25

    def test_reads_positive_float_override(self, monkeypatch):
        monkeypatch.setenv("BQ_PRICE_PER_TIB_USD", "7.5")
        from app.config import _parse_bq_price_per_tib_usd

        assert _parse_bq_price_per_tib_usd() == 7.5

    def test_malformed_value_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("BQ_PRICE_PER_TIB_USD", "not-a-number")
        from app.config import _parse_bq_price_per_tib_usd

        assert _parse_bq_price_per_tib_usd() == 6.25

    def test_non_positive_value_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("BQ_PRICE_PER_TIB_USD", "0")
        from app.config import _parse_bq_price_per_tib_usd

        assert _parse_bq_price_per_tib_usd() == 6.25

    def test_negative_value_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("BQ_PRICE_PER_TIB_USD", "-3.5")
        from app.config import _parse_bq_price_per_tib_usd

        assert _parse_bq_price_per_tib_usd() == 6.25

    def test_nan_value_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("BQ_PRICE_PER_TIB_USD", "nan")
        from app.config import _parse_bq_price_per_tib_usd

        assert _parse_bq_price_per_tib_usd() == 6.25

    def test_inf_value_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("BQ_PRICE_PER_TIB_USD", "inf")
        from app.config import _parse_bq_price_per_tib_usd

        assert _parse_bq_price_per_tib_usd() == 6.25

    def test_negative_inf_value_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("BQ_PRICE_PER_TIB_USD", "-inf")
        from app.config import _parse_bq_price_per_tib_usd

        assert _parse_bq_price_per_tib_usd() == 6.25


# ---------------------------------------------------------------------------
# Flusher tests (async)
# ---------------------------------------------------------------------------


class TestFlusher:
    def test_flusher_calls_insert_rows_json_for_each_row(self):
        mock_client = MagicMock()
        mock_client.insert_rows_json.return_value = []  # no errors

        async def run():
            task = asyncio.create_task(audit_module._audit_flusher(mock_client, "proj.ds.table"))
            _audit_deque.append({"requestId": "abc", "toolName": "test"})
            await _wait_mock_called(mock_client.insert_rows_json)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        asyncio.run(run())
        assert mock_client.insert_rows_json.called
        args = mock_client.insert_rows_json.call_args[0]
        assert args[1][0]["requestId"] == "abc"

    def test_flusher_continues_on_bq_insert_error(self):
        mock_client = MagicMock()
        mock_client.insert_rows_json.side_effect = Exception("BQ down")
        calls = []

        async def run():
            task = asyncio.create_task(audit_module._audit_flusher(mock_client, "proj.ds.table"))
            _audit_deque.append({"requestId": "r1", "toolName": "t"})
            _audit_deque.append({"requestId": "r2", "toolName": "t"})
            await _wait_mock_called(mock_client.insert_rows_json, min_calls=2)
            calls.append(mock_client.insert_rows_json.call_count)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        asyncio.run(run())
        assert calls[0] >= 2

    def test_flusher_drains_in_fifo_order(self):
        inserted_order = []
        mock_client = MagicMock()

        def capture_insert(table, rows):
            inserted_order.append(rows[0]["requestId"])
            return []

        mock_client.insert_rows_json.side_effect = capture_insert

        async def run():
            task = asyncio.create_task(audit_module._audit_flusher(mock_client, "proj.ds.table"))
            for i in range(3):
                _audit_deque.append({"requestId": f"row-{i}", "toolName": "t"})
            await _wait_mock_called(mock_client.insert_rows_json, min_calls=3)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        asyncio.run(run())
        assert inserted_order == ["row-0", "row-1", "row-2"]

    def test_flusher_logs_warning_on_bq_error(self, caplog):
        import logging

        mock_client = MagicMock()
        mock_client.insert_rows_json.side_effect = Exception("network error")

        async def run():
            task = asyncio.create_task(audit_module._audit_flusher(mock_client, "proj.ds.table"))
            _audit_deque.append({"requestId": "err-row", "toolName": "t"})
            await _wait_mock_called(mock_client.insert_rows_json)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        with caplog.at_level(logging.WARNING, logger="app.audit"):
            asyncio.run(run())

        assert any("BQ write failed" in r.message for r in caplog.records)

    def test_flusher_passes_request_response_fields_through_untouched(self):
        mock_client = MagicMock()
        mock_client.insert_rows_json.return_value = []

        async def run():
            task = asyncio.create_task(audit_module._audit_flusher(mock_client, "proj.ds.table"))
            _audit_deque.append(
                {
                    "requestId": "abc",
                    "toolName": "test",
                    "request": '{"query": "hello"}',
                    "response": '{"result": "ok"}',
                }
            )
            await _wait_mock_called(mock_client.insert_rows_json)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        asyncio.run(run())
        args = mock_client.insert_rows_json.call_args[0]
        sent_row = args[1][0]
        assert sent_row["request"] == '{"query": "hello"}'
        assert sent_row["response"] == '{"result": "ok"}'

    def test_flusher_passes_bytes_processed_and_cost_fields_through_untouched(self):
        """: bytesProcessed/estimatedCostUsd flow through the
        flusher unmodified, same as the pre-existing request/response
        passthrough (test_flusher_passes_request_response_fields_through_untouched)."""
        mock_client = MagicMock()
        mock_client.insert_rows_json.return_value = []

        async def run():
            task = asyncio.create_task(audit_module._audit_flusher(mock_client, "proj.ds.table"))
            _audit_deque.append(
                {
                    "requestId": "cost-row",
                    "toolName": "execute_sql",
                    "bytesProcessed": 1024**4,
                    "estimatedCostUsd": 6.25,
                }
            )
            await _wait_mock_called(mock_client.insert_rows_json)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        asyncio.run(run())
        args = mock_client.insert_rows_json.call_args[0]
        sent_row = args[1][0]
        assert sent_row["bytesProcessed"] == 1024**4
        assert sent_row["estimatedCostUsd"] == 6.25

    def test_flusher_logs_warning_on_insert_errors_list(self, caplog):
        import logging

        mock_client = MagicMock()
        mock_client.insert_rows_json.return_value = [{"errors": [{"reason": "stopped"}]}]

        async def run():
            task = asyncio.create_task(audit_module._audit_flusher(mock_client, "proj.ds.table"))
            _audit_deque.append({"requestId": "err2", "toolName": "t"})
            await _wait_mock_called(mock_client.insert_rows_json)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        with caplog.at_level(logging.WARNING, logger="app.audit"):
            asyncio.run(run())

        assert any("BQ insert errors" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Concurrency stress tests
# ---------------------------------------------------------------------------


class TestDecoratorConcurrency:
    r"""Concurrent overflow from multiple simultaneous tool calls, simulated
    via a small thread pool.

    In production, synchronous `def` tool handlers run directly on the single
    asyncio event-loop thread, so there is no real cross-thread race on
    `_audit_deque`. A `concurrent.futures.ThreadPoolExecutor` is still the
    correct concurrency-injection mechanism for these tests: it fires N
    `audit_tool_call`-wrapped calls simultaneously from a synchronous test and
    proves the decorator and deque hold up under genuine concurrent access,
    regardless of the thread model a deployment uses.
    """

    N = 50

    def test_concurrent_calls_produce_no_lost_or_duplicated_rows(self, monkeypatch):
        monkeypatch.setattr(settings, "audit_queue_bound", 1000)
        fn = _make_simple_tool()

        def call(i: int):
            return fn(query=f"concurrent-{i}")

        with ThreadPoolExecutor(max_workers=self.N) as pool:
            futures = [pool.submit(call, i) for i in range(self.N)]
            # .result() re-raises any worker exception here, in the test's
            # own thread -- "no exception propagates from any call" is
            # enforced by simply not catching anything.
            results = [f.result() for f in futures]

        assert len(results) == self.N
        assert len(_audit_deque) == self.N, (
            f"expected exactly {self.N} rows, got {len(_audit_deque)} -- "
            "rows were lost or duplicated under concurrent producer access"
        )
        request_ids = [row["requestId"] for row in _audit_deque]
        assert len(request_ids) == len(set(request_ids)), "duplicate requestId found"
        assert len(set(request_ids)) == self.N

    def test_concurrent_calls_stay_under_overflow_bound(self, monkeypatch, caplog):
        # Real default (1000), not an artificially small test value --
        # proves the overflow-drop path (already covered by
        # TestDecoratorOverflow) is not why coverage is 100% at this N; it's
        # genuinely unneeded here (N=50 is far below the bound).
        monkeypatch.setattr(settings, "audit_queue_bound", 1000)
        fn = _make_simple_tool()
        import logging

        def call(i: int):
            fn(query=f"bound-{i}")

        with caplog.at_level(logging.WARNING, logger="app.audit"):
            with ThreadPoolExecutor(max_workers=self.N) as pool:
                list(pool.map(call, range(self.N)))

        assert len(_audit_deque) == self.N
        assert not any(
            "audit_queue_overflow_dropped" in r.message for r in caplog.records
        ), "overflow-drop path fired at N=50 against the real 1000 bound -- should be unreachable"

    def test_flusher_drains_all_concurrently_produced_rows(self):
        mock_client = MagicMock()
        mock_client.insert_rows_json.return_value = []
        fn = _make_simple_tool()

        async def run():
            task = asyncio.create_task(
                audit_module._audit_flusher(mock_client, "proj.ds.table")
            )
            loop = asyncio.get_running_loop()
            with ThreadPoolExecutor(max_workers=self.N) as pool:
                await asyncio.gather(
                    *[
                        loop.run_in_executor(
                            pool, functools.partial(fn, query=f"flush-{i}")
                        )
                        for i in range(self.N)
                    ]
                )
            # Generous, backed-off polling (not a fixed short timeout) --
            # the flusher drains one row per insert_rows_json call in
            # steady state (non-batched), so a 50-row burst can take
            # noticeably longer than a single BQ round-trip to fully land.
            await _wait_mock_called(
                mock_client.insert_rows_json, min_calls=self.N, timeout=10.0
            )
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        asyncio.run(run())

        assert mock_client.insert_rows_json.call_count == self.N, (
            "flusher did not drain exactly N rows -- possible loss or "
            "duplication under concurrent producer load"
        )
        sent_request_ids = [
            call.args[1][0]["requestId"]
            for call in mock_client.insert_rows_json.call_args_list
        ]
        assert len(sent_request_ids) == self.N
        assert len(set(sent_request_ids)) == self.N, "duplicate requestId reached BQ sink"

    def test_slow_bq_write_does_not_delay_tool_response(self):
        """Latency-isolation test: a stalled/slow BigQuery flusher must not
        delay any tool's own response, even under a 50-way concurrent
        burst -- directly exercises "no critical-path impact" under load,
        not just single-call latency (see
        TestDecoratorDequePopulation::test_row_latency_ms_non_negative for
        the pre-existing, non-concurrent, non-injected-delay baseline)."""
        mock_client = MagicMock()
        delay_seconds = 0.5

        def slow_insert(table, rows):
            time.sleep(delay_seconds)
            return []

        mock_client.insert_rows_json.side_effect = slow_insert
        fn = _make_simple_tool()

        def call(i: int) -> float:
            t0 = time.perf_counter()
            fn(query=f"latency-{i}")
            return time.perf_counter() - t0

        async def run() -> list[float]:
            task = asyncio.create_task(
                audit_module._audit_flusher(mock_client, "proj.ds.table")
            )
            loop = asyncio.get_running_loop()
            with ThreadPoolExecutor(max_workers=self.N) as pool:
                latencies = await asyncio.gather(
                    *[
                        loop.run_in_executor(pool, functools.partial(call, i))
                        for i in range(self.N)
                    ]
                )
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            return list(latencies)

        latencies = asyncio.run(run())

        # Every individual tool call's own wall-clock time must stay far
        # below the injected BQ-write delay -- the audit path (an O(1)
        # deque.append()) never blocks on the flusher's slow I/O, even
        # while N=50 rows are queued for a deliberately stalled sink.
        assert max(latencies) < delay_seconds, (
            f"a tool call took {max(latencies):.3f}s, close to/over the "
            f"{delay_seconds}s injected BQ-write delay -- audit path is "
            "leaking latency onto the critical path"
        )

    def test_overflow_composes_correctly_with_concurrency(self, monkeypatch, caplog):
        """Edge case: audit_queue_bound deliberately low (10) with N=50
        concurrent calls -- confirms the existing, already-tested
 overflow-drop path and the concurrency-
        correctness path compose correctly: every call is accounted for as
        either enqueued or cleanly dropped with a sentinel log line, and no
        corruption appears on the rows that did make it through.

        Note: the bound check (`len() >= bound`) and the append are two
        separate statements, not one atomic operation -- under genuine
        multi-thread concurrency (unlike 's single-thread production
        model) a benign race can let two threads both observe `len == bound-1`,
        both pass the check, and both append, causing the deque to transiently
        exceed the bound before settling to a final state. This test asserts
        the invariants that must hold regardless of where that race resolves:
        enqueued + dropped == N with no duplicate/lost requestIds among
        survivors.
        """
        monkeypatch.setattr(settings, "audit_queue_bound", 10)
        fn = _make_simple_tool()
        import logging

        def call(i: int):
            fn(query=f"overflow-concurrent-{i}")

        with caplog.at_level(logging.WARNING, logger="app.audit"):
            with ThreadPoolExecutor(max_workers=self.N) as pool:
                list(pool.map(call, range(self.N)))

        dropped = sum(
            1 for r in caplog.records if "audit_queue_overflow_dropped" in r.message
        )
        assert len(_audit_deque) + dropped == self.N, "some calls unaccounted for"
        request_ids = [row["requestId"] for row in _audit_deque]
        assert len(request_ids) == len(set(request_ids)), "duplicate/corrupted survivor row"

    def test_concurrent_exception_still_records_row_for_raising_calls(self):
        """Edge case: one or more concurrent calls raising an exception
        mid-burst -- confirms TestDecoratorExceptionHandling's existing
        single-call guarantee ("row still recorded on exception") still
        holds when the exception happens concurrently with other
        successful calls, not just in isolation."""
        ok_fn = _make_simple_tool(name="ok_tool")
        raising_fn = _make_simple_tool(name="raising_tool", raise_exc=ValueError("boom"))
        half = self.N // 2

        def call_ok(i: int):
            return ok_fn(query=f"ok-{i}")

        def call_raising(i: int) -> bool:
            try:
                raising_fn(query=f"raise-{i}")
                return False  # would be a bug -- exception must propagate
            except ValueError:
                return True

        with ThreadPoolExecutor(max_workers=self.N) as pool:
            ok_futures = [pool.submit(call_ok, i) for i in range(half)]
            raise_futures = [pool.submit(call_raising, i) for i in range(half)]
            ok_results = [f.result() for f in ok_futures]
            raise_results = [f.result() for f in raise_futures]

        assert all(ok_results[i] == {"result": "ok", "q": f"ok-{i}"} for i in range(half))
        assert all(raise_results), "raising_fn did not re-raise under concurrency"
        assert len(_audit_deque) == self.N
        ok_rows = [r for r in _audit_deque if r["toolName"] == "ok_tool"]
        raising_rows = [r for r in _audit_deque if r["toolName"] == "raising_tool"]
        assert len(ok_rows) == half
        assert len(raising_rows) == half
        for row in raising_rows:
            assert "success" not in row
            assert "errorMessage" not in row


# ---------------------------------------------------------------------------
# start_audit_flusher tests
# ---------------------------------------------------------------------------


class TestStartAuditFlusher:
    def test_returns_none_when_bq_client_fails(self, monkeypatch):
        monkeypatch.setattr(settings, "gcp_project", "test-project")

        def bad_client(*args, **kwargs):
            raise Exception("no credentials")

        with patch("app.audit.bigquery") as mock_bq:
            mock_bq.Client.side_effect = bad_client

            async def run():
                return await start_audit_flusher()

            result = asyncio.run(run())
        assert result is None

    def test_returns_task_when_bq_client_succeeds(self, monkeypatch):
        monkeypatch.setattr(settings, "gcp_project", "test-project")
        monkeypatch.setattr(settings, "bq_audit_dataset", "bq_audit_test")

        mock_client = MagicMock()

        with patch("app.audit.bigquery") as mock_bq:
            mock_bq.Client.return_value = mock_client

            async def run():
                task = await start_audit_flusher()
                assert task is not None
                assert isinstance(task, asyncio.Task)
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                return task

            result = asyncio.run(run())
        assert result is not None

    def test_sets_module_level_bq_client(self, monkeypatch):
        monkeypatch.setattr(settings, "gcp_project", "test-project")
        monkeypatch.setattr(settings, "bq_audit_dataset", "bq_audit_test")

        mock_client = MagicMock()

        with patch("app.audit.bigquery") as mock_bq:
            mock_bq.Client.return_value = mock_client

            async def run():
                task = await start_audit_flusher()
                if task:
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass

            asyncio.run(run())

        assert audit_module._bq_client is mock_client

    def test_returns_none_when_bigquery_unavailable(self, monkeypatch):
        """When google.cloud.bigquery could not be imported (module-level
        `bigquery = None`), start_audit_flusher returns None without raising."""
        monkeypatch.setattr(audit_module, "bigquery", None)

        async def run():
            return await start_audit_flusher()

        assert asyncio.run(run()) is None


# ---------------------------------------------------------------------------
# Integration tests — decorated tools in app.main
# ---------------------------------------------------------------------------


class TestIntegrationDecoratedTools:
    """All 7 tool functions exported from app/main.py are wrapped with
    @audit_tool_call -- calling each directly (mocked BigQuery/Dataplex/
    Lineage clients, same DI-seam pattern tests/test_main.py already uses)
    appends exactly one row to _audit_deque per call.
    """

    @pytest.fixture
    def fake_bq_client(self, monkeypatch):
        import app.main as main_module

        fake_client = MagicMock()
        monkeypatch.setattr(main_module, "_bq_client", fake_client)
        main_module.cache.clear()
        yield fake_client
        main_module.cache.clear()

    @pytest.fixture
    def fake_lineage_client(self, monkeypatch):
        import app.main as main_module

        fake_client = MagicMock()
        monkeypatch.setattr(main_module, "_lineage_client", fake_client)
        main_module.cache.clear()
        yield fake_client
        main_module.cache.clear()

    @pytest.fixture
    def fake_dataplex_client(self, monkeypatch):
        import app.main as main_module

        fake_client = MagicMock()
        monkeypatch.setattr(main_module, "_dataplex_client", fake_client)
        main_module.cache.clear()
        yield fake_client
        main_module.cache.clear()

    def test_ping_appends_to_deque(self):
        from app.main import ping

        result = ping()
        assert isinstance(result, dict)
        assert len(_audit_deque) == 1
        assert _audit_deque[0]["toolName"] == "ping"
        assert _audit_deque[0]["query"] is None
        #  FR5: non-execute_sql tools leave bytesProcessed/estimatedCostUsd NULL.
        assert _audit_deque[0]["bytesProcessed"] is None
        assert _audit_deque[0]["estimatedCostUsd"] is None

    def test_list_datasets_appends_to_deque(self, fake_bq_client):
        from app.main import list_datasets

        fake_bq_client.list_datasets.return_value = ["analytics"]
        result = list_datasets()
        assert result == {"datasets": ["analytics"]}
        assert len(_audit_deque) == 1
        row = _audit_deque[0]
        assert row["toolName"] == "list_datasets"
        assert row["query"] is None
        assert json.loads(row["response"]) == {"datasets": ["analytics"]}
        #  FR5.
        assert row["bytesProcessed"] is None
        assert row["estimatedCostUsd"] is None

    def test_list_tables_appends_to_deque(self, fake_bq_client):
        from app.main import list_tables

        fake_bq_client.list_tables.return_value = ["daily_active_users"]
        result = list_tables("analytics")
        assert result == {"tables": ["daily_active_users"]}
        assert len(_audit_deque) == 1
        row = _audit_deque[0]
        assert row["toolName"] == "list_tables"
        #  FR5.
        assert row["bytesProcessed"] is None
        assert row["estimatedCostUsd"] is None

    def test_get_table_metadata_appends_to_deque(self, fake_bq_client):
        from app.main import get_table_metadata

        fake_bq_client.get_table_metadata.return_value = {"tableId": "t"}
        result = get_table_metadata("d", "t")
        assert result == {"tableId": "t"}
        assert len(_audit_deque) == 1
        row = _audit_deque[0]
        assert row["toolName"] == "get_table_metadata"
        #  FR5.
        assert row["bytesProcessed"] is None
        assert row["estimatedCostUsd"] is None

    def test_get_data_lineage_appends_to_deque(self, fake_lineage_client):
        from app.main import get_data_lineage

        fake_lineage_client.get_table_lineage.return_value = {
            "upstream": [],
            "downstream": [],
            "links": [],
            "mermaidDiagram": "graph LR",
        }
        result = get_data_lineage("d", "t")
        assert result["mermaidDiagram"] == "graph LR"
        assert len(_audit_deque) == 1
        row = _audit_deque[0]
        assert row["toolName"] == "get_data_lineage"
        #  FR5.
        assert row["bytesProcessed"] is None
        assert row["estimatedCostUsd"] is None

    def test_get_data_quality_results_appends_to_deque(self, fake_dataplex_client):
        from app.main import get_data_quality_results

        fake_dataplex_client.get_data_quality_results.return_value = None
        result = get_data_quality_results("d", "t")
        assert result == {"message": "No data quality scans configured for this table"}
        assert len(_audit_deque) == 1
        row = _audit_deque[0]
        assert row["toolName"] == "get_data_quality_results"
        #  FR5.
        assert row["bytesProcessed"] is None
        assert row["estimatedCostUsd"] is None

    def test_execute_sql_appends_to_deque_and_extracts_query(self, fake_bq_client, monkeypatch):
        """execute_sql is the one query-bearing tool, so it exercises the
        query-extraction assertion. Also
        asserts the row's bytesProcessed/estimatedCostUsd, derived from a
        realistic totalBytesProcessed in the (mocked) BigQueryClient result."""
        from app.main import execute_sql

        monkeypatch.setattr(settings, "bq_price_per_tib_usd", 6.25)
        fake_bq_client.execute_sql.return_value = {
            "rows": [],
            "rowCount": 0,
            "totalBytesProcessed": str(1024**4),  # 1 TiB
        }
        result = execute_sql("SELECT 1")
        assert result["rows"] == []
        assert len(_audit_deque) == 1
        row = _audit_deque[0]
        assert row["toolName"] == "execute_sql"
        assert row["query"] == "SELECT 1"
        assert row["bytesProcessed"] == 1024**4
        assert row["estimatedCostUsd"] == pytest.approx(6.25)

    def test_all_seven_tools_are_wrapped_with_audit_tool_call(self):
        from app.main import _TOOL_FUNCTIONS

        assert len(_TOOL_FUNCTIONS) == 7
        for fn in _TOOL_FUNCTIONS:
            # functools.wraps sets __wrapped__ on the outer wrapper.
            assert hasattr(fn, "__wrapped__"), f"{fn.__name__} is not decorated with @audit_tool_call"


class TestCreateAppLifespanWiring:
    """create_app() passes lifespan=_audit_lifespan into every FastMCP(...)
    instance it returns (both the auth-disabled default path and an
    auth-enabled Settings(google_oauth_client_id=...) path)."""

    def test_default_auth_disabled_instance_has_audit_lifespan(self):
        from app.main import _audit_lifespan, create_app

        app = create_app()
        assert app._lifespan is _audit_lifespan

    def test_auth_enabled_instance_has_audit_lifespan(self):
        from app.config import Settings
        from app.main import _audit_lifespan, create_app

        app = create_app(app_settings=Settings(google_oauth_client_id="test-client-id"))
        assert app._lifespan is _audit_lifespan


# ---------------------------------------------------------------------------
# Lifespan tests
# ---------------------------------------------------------------------------


class TestLifespan:
    def test_lifespan_starts_and_stops_flusher(self):
        """Lifespan context manager starts the flusher task and cancels it on exit."""
        mock_client = MagicMock()
        mock_client.insert_rows_json.return_value = []

        with patch("app.audit.bigquery") as mock_bq, patch.object(settings, "gcp_project", "test-project"):
            mock_bq.Client.return_value = mock_client

            async def run():
                from app.main import _audit_lifespan

                server_stub = MagicMock()
                async with _audit_lifespan(server_stub):
                    current_tasks = [
                        t for t in asyncio.all_tasks() if not t.done() and t is not asyncio.current_task()
                    ]
                    assert len(current_tasks) >= 1

            asyncio.run(run())

    def test_lifespan_no_crash_when_client_fails(self):
        """Lifespan exits cleanly even when BQ client init fails."""
        with patch("app.audit.bigquery") as mock_bq, patch.object(settings, "gcp_project", "test-project"):
            mock_bq.Client.side_effect = Exception("no creds")

            async def run():
                from app.main import _audit_lifespan

                server_stub = MagicMock()
                async with _audit_lifespan(server_stub):
                    pass  # Should not raise

            asyncio.run(run())  # Must not raise

    def test_lifespan_final_drain_flushes_remaining_rows(self):
        """On shutdown, any rows still in the deque are flushed synchronously
        via a final insert_rows_json call."""
        mock_client = MagicMock()
        mock_client.insert_rows_json.return_value = []

        with patch("app.audit.bigquery") as mock_bq, patch.object(settings, "gcp_project", "test-project"):
            mock_bq.Client.return_value = mock_client

            async def run():
                from app.main import _audit_lifespan

                server_stub = MagicMock()
                async with _audit_lifespan(server_stub):
                    # Cancel the background flusher's own drain race by
                    # appending a row right before exiting the lifespan --
                    # the final-drain step should pick it up on shutdown.
                    _audit_deque.append({"requestId": "final-row", "toolName": "t"})

            asyncio.run(run())

        assert mock_client.insert_rows_json.called

    def test_lifespan_final_drain_batches_large_deques(self):
        """When the deque contains more rows than the batch size (500),
        the final drain chunks them into multiple insert_rows_json calls."""
        mock_client = MagicMock()
        mock_client.insert_rows_json.return_value = []

        with patch("app.audit.bigquery") as mock_bq, patch.object(settings, "gcp_project", "test-project"):
            mock_bq.Client.return_value = mock_client

            async def run():
                from app.main import _audit_lifespan

                server_stub = MagicMock()
                async with _audit_lifespan(server_stub):
                    # Pre-fill deque with 1100 rows to force batching
                    # (exceeds default chunk size of 500).
                    for i in range(1100):
                        _audit_deque.append(
                            {"requestId": f"row-{i}", "toolName": "t", "latencyMs": 1}
                        )

            asyncio.run(run())

        # With 1100 rows and chunk_size=500, expect at least 3 calls:
        # batch 1: rows 0-499 (500 rows)
        # batch 2: rows 500-999 (500 rows)
        # batch 3: rows 1000-1099 (100 rows)
        assert mock_client.insert_rows_json.call_count >= 3, (
            f"Expected at least 3 batched calls for 1100 rows, "
            f"got {mock_client.insert_rows_json.call_count}"
        )

        # Verify first call has exactly 500 rows, second call has 500 rows,
        # last call has remaining (100).
        calls = mock_client.insert_rows_json.call_args_list
        rows_in_first_batch = calls[0][0][1]
        rows_in_second_batch = calls[1][0][1]
        rows_in_last_batch = calls[-1][0][1]

        assert len(rows_in_first_batch) == 500
        assert len(rows_in_second_batch) == 500
        assert len(rows_in_last_batch) == 100


class TestExecuteSqlFailureDoesNotLogExtractionWarning:
    """A failed `execute_sql` has no `result`; the audit `finally` block must
    not rely on a swallowed NameError (which logged a misleading WARNING)."""

    def test_failed_execute_sql_does_not_log_bytes_extraction_warning(self, caplog):
        def execute_sql(query: str) -> dict:
            raise RuntimeError("job cancelled")

        wrapped = audit_tool_call(execute_sql)

        with caplog.at_level("WARNING", logger="app.audit"):
            with pytest.raises(RuntimeError, match="job cancelled"):
                wrapped(query="SELECT 1")

        assert "failed to extract bytesProcessed" not in caplog.text
        assert _audit_deque[-1]["bytesProcessed"] is None
        assert _audit_deque[-1]["estimatedCostUsd"] is None
