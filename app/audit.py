"""Per-tool-call audit logging for bq-dataplex-mcp.

Captures one row per MCP tool call and writes it to BigQuery asynchronously,
without adding latency to the tool response.

Design:
- A synchronous decorator (`@audit_tool_call`) appends rows to a bounded
  `collections.deque` (drop-current on overflow).
- A background async flusher drains the deque via `popleft()` with
  `asyncio.sleep(0.1)` yields between passes.
- The BigQuery client is lazily instantiated in `start_audit_flusher()`, so
  importing this module without credentials never raises.

`userEmail` is a REQUIRED column and no code path writes NULL:
1. A validated token whose claims include `email` -> that email.
2. A validated token whose claims unexpectedly lack `email` -> the distinctly
   logged `missing-email-claim@bq-dataplex-mcp.invalid` placeholder.
3. No access token at all (auth disabled) -> the distinctly logged
   `dev-smoke-test@bq-dataplex-mcp.invalid` placeholder.

An unauthenticated call while auth is configured is rejected before tool
dispatch and is intentionally left without its own fallback.
"""

import asyncio
import collections
import functools
import inspect
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from mcp.server.auth.middleware.auth_context import get_access_token  # SDK-provided; flag on SDK version bumps

from app.config import settings
from app.pricing import estimate_cost_usd

try:
    from google.cloud import bigquery
except ImportError:  # pragma: no cover
    bigquery = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------

# Unbounded deque — overflow is enforced by the decorator via an explicit
# len() >= audit_queue_bound guard (drop-current, not drop-oldest).
#
# Thread-safety: fastmcp 2.x runs sync `def`
# tools inline on the event-loop thread, so a slow tool (e.g. a long
# execute_sql) used to freeze the whole server. app/main.py's
# `_offload_to_thread` now runs every tool body -- including this module's
# wrapper -- on a dedicated worker thread, so the producer (.append(), worker
# threads) and the consumer (_audit_flusher's asyncio.Task, .popleft(), loop
# thread) are on different threads. deque.append()/popleft() are atomic in
# CPython, so no lock is needed; the len() >= audit_queue_bound guard below is
# a benign race (the deque can overshoot the bound by at most the number of
# concurrent tool threads).
_audit_deque: collections.deque = collections.deque()

# Set by start_audit_flusher() after successful lazy instantiation; exposed
# at module scope so lifespan teardown in app/main.py can reference it for
# the final drain pass.
_bq_client: Any | None = None  # bigquery.Client | None

#  narrow anomaly fallback: a validated token whose claims unexpectedly
# lack an `email` key (or claims is unexpectedly None) -- a real Google-side
# anomaly, not an expected code path.
_MISSING_EMAIL_CLAIM_PLACEHOLDER = "missing-email-claim@bq-dataplex-mcp.invalid"

# Existing, expected dev posture: no GOOGLE_OAUTH_CLIENT_ID configured at all
# (RequireAuthMiddleware itself is never installed), so no request on this
# transport path is ever authenticated.
_DEV_POSTURE_PLACEHOLDER = "dev-smoke-test@bq-dataplex-mcp.invalid"


# ---------------------------------------------------------------------------
# Serialization helper
# ---------------------------------------------------------------------------

def _safe_json(value: Any, max_len: int = 32_768) -> str | None:
    """JSON-serialize value for the request/response audit columns.

    Never raises: non-JSON-serializable values fall back to str(value).
    Returns None for None input (so callers with no args/return value produce
    a real BigQuery NULL rather than the literal string "null"). Serialized
    strings longer than max_len are truncated with a trailing marker so a
    single row can never blow up BigQuery streaming-insert row-size limits.
    """
    if value is None:
        return None
    try:
        serialized = json.dumps(value, default=str)
    except Exception:
        serialized = str(value)
    if len(serialized) > max_len:
        marker = "...<truncated>"
        serialized = serialized[: max_len - len(marker)] + marker
    return serialized


def _truncate_str(value: str | None, max_len: int = 32_768) -> str | None:
    """Bound a plain string for the query audit column without JSON-encoding it.

    Unlike _safe_json, this preserves the raw string as-is.
    "Raw query string passed to the tool" column description) -- it only
    caps length so a single row can never blow up BigQuery streaming-insert
    row-size limits.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)
    if len(value) > max_len:
        marker = "...<truncated>"
        return value[: max_len - len(marker)] + marker
    return value


def _resolve_user_email() -> str:
    """Resolve the calling user's email for the audit row.

    Never returns None -- userEmail is a REQUIRED BigQuery column (per
     See this module's docstring for the full
    three-branch resolution order and rationale.
    """
    access_token = get_access_token()
    if access_token is not None:
        claims = access_token.claims
        email = claims.get("email") if claims else None
        if email is not None:
            return email
        logger.warning(
            "audit: missing-email-claim anomaly -- verified token (sub=%r) has no "
            "usable email claim; falling back to placeholder %r",
            access_token.subject,
            _MISSING_EMAIL_CLAIM_PLACEHOLDER,
        )
        return _MISSING_EMAIL_CLAIM_PLACEHOLDER

    if not settings.google_oauth_client_id:
        # userEmail is a REQUIRED column in bq_dataplex_mcp_audit_tool_called.
        # Environments with no GOOGLE_OAUTH_CLIENT_ID (dev) have no app-level
        # auth at all, so there is no access token on any call there -- use an
        # RFC 2606 .invalid placeholder (never a real, ownable address) so
        # dev's audit trail can still be exercised. Never fires where auth is
        # actually configured (see this module's docstring -- that case is
        # structurally unreachable in production per ).
        logger.warning(
            "audit: dev-posture fallback -- GOOGLE_OAUTH_CLIENT_ID unset and no "
            "access token; falling back to placeholder %r",
            _DEV_POSTURE_PLACEHOLDER,
        )
        return _DEV_POSTURE_PLACEHOLDER

    # Structurally unreachable in production: auth is configured
    # (GOOGLE_OAUTH_CLIENT_ID set) but no access token is present on this
    # call. RequireAuthMiddleware rejects unauthenticated calls with a 401
    # before tool dispatch ever runs -- see
    # tests/test_mcp_auth_integration.py::test_missing_bearer_token_returns_401.
    # No dedicated fallback/test is designed for this path (per,
    # relying on the middleware-rejection ordering instead) -- this is purely
    # a defensive last resort so userEmail (a REQUIRED BigQuery column) is
    # never None even if this branch is somehow reached despite that
    # ordering. Reuses the anomaly placeholder rather than inventing a third
    # undocumented value.
    logger.warning(
        "audit: unexpected unauthenticated call with auth configured (no access "
        "token, GOOGLE_OAUTH_CLIENT_ID set) -- this should be structurally "
        "unreachable in production; falling back to placeholder %r",
        _MISSING_EMAIL_CLAIM_PLACEHOLDER,
    )
    return _MISSING_EMAIL_CLAIM_PLACEHOLDER


# ---------------------------------------------------------------------------
# Synchronous decorator
# ---------------------------------------------------------------------------

def audit_tool_call(fn):
    """Synchronous decorator that records one audit row per tool call.

    The row is appended to _audit_deque (O(1), non-blocking) and drained
    asynchronously by the background flusher. Tool signatures and return
    values are unchanged.
    """
    # Detect at decoration time whether the function has a 'query' parameter.
    _has_query = "query" in inspect.signature(fn).parameters

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        t0 = time.perf_counter()
        request_id = str(uuid.uuid4())
        user_email = _resolve_user_email()

        # Derive query value from positional or keyword args.
        query_value: str | None = None
        if _has_query:
            sig = inspect.signature(fn)
            params = list(sig.parameters.keys())
            if "query" in kwargs:
                query_value = kwargs["query"]
            elif "query" in params:
                idx = params.index("query")
                if idx < len(args):
                    query_value = args[idx]

        # Pre-initialized so `finally` can always reference both, even if an
        # exception is raised before either is (re)assigned below — e.g. a
        # genuine TypeError from sig.bind() (bad call args) or from fn() itself.
        request_json: str | None = None
        response_json: str | None = None
        # `result` is likewise pre-initialized so a failed fn() (e.g. a
        # cancelled BigQuery job) leaves it None rather than undefined; the
        # bytesProcessed extraction below then skips cleanly instead of
        # logging a spurious WARNING for the NameError.
        result: Any = None
        # bytesProcessed/estimatedCostUsd, execute_sql only. Also
        # pre-initialized to None so the `finally` block always has both
        # defined even if fn() raised before producing a result.
        bytes_processed: int | None = None
        estimated_cost_usd: float | None = None

        try:
            sig = inspect.signature(fn)
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            request_json = _safe_json(dict(bound.arguments))

            result = fn(*args, **kwargs)
            response_json = _safe_json(result)
        finally:
            latency_ms = int((time.perf_counter() - t0) * 1000)
            created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            # Field names/set must match the live BigQuery table schema exactly —
            # bq_dataplex_mcp_audit_tool_called has no success/errorMessage
            # columns, and the timestamp column is createdAt, not calledAt.
            #'s Database Changes section.
            #
            # resultSizeBytes: measures the
            # byte length of response_json as actually stored in the
            # `response` column above -- i.e. post-_safe_json-truncation, not
            # the pre-truncation tool result. For results larger than
            # _safe_json's 32,768-char max_len this understates the true
            # payload size; accepted per's Risks
            # table rather than paying for a second, untruncated
            # serialization pass purely for this field.
            result_size_bytes = (
                len(response_json.encode("utf-8")) if response_json is not None else None
            )

            # bytesProcessed/estimatedCostUsd: populated
            # for execute_sql rows only -- NULL for every other tool (FR5).
            # Pure, in-process arithmetic on `result`'s already-computed
            # `totalBytesProcessed` (BigQueryClient.execute_sql, both the
            # dry_run and real-execution branches) -- no new network call
            # (FR6). Fails safe to None/None on any malformed/missing shape
            # (FR6) rather than raising or affecting the tool call's own
            # response, mirroring _safe_json's fail-safe posture. `result`
            # is None here if fn() raised before assigning it.
            # The formula lives in app.pricing.estimate_cost_usd
            # (shared with BigQueryClient.execute_sql's own response fields) --
            # this call site no longer inlines the arithmetic.
            if fn.__name__ == "execute_sql":
                try:
                    if isinstance(result, dict) and "totalBytesProcessed" in result:
                        bytes_processed = int(result["totalBytesProcessed"])
                        estimated_cost_usd = estimate_cost_usd(
                            bytes_processed, settings.bq_price_per_tib_usd
                        )
                except Exception as exc:
                    logger.warning(
                        "audit: failed to extract bytesProcessed/estimatedCostUsd "
                        "for tool %r: %s",
                        fn.__name__,
                        exc,
                    )
                    bytes_processed = None
                    estimated_cost_usd = None

            row = {
                "requestId": request_id,
                "toolName": fn.__name__,
                "userEmail": user_email,
                "query": _truncate_str(query_value),
                "createdAt": created_at,
                "latencyMs": latency_ms,
                "request": request_json,
                "response": response_json,
                "resultSizeBytes": result_size_bytes,
                "bytesProcessed": bytes_processed,
                "estimatedCostUsd": estimated_cost_usd,
            }
            if len(_audit_deque) >= settings.audit_queue_bound:
                # Sentinel token "audit_queue_overflow_dropped" is a stable
                # match target for deploy/main.tf's google_logging_metric
                # -- keep this exact substring
                # first in the message; the rest is human-readable detail.
                logger.warning(
                    "audit_queue_overflow_dropped: deque full (%d >= %d), "
                    "dropping row for tool %r",
                    len(_audit_deque),
                    settings.audit_queue_bound,
                    fn.__name__,
                )
            else:
                _audit_deque.append(row)

        return result

    return wrapper


# ---------------------------------------------------------------------------
# Background flusher
# ---------------------------------------------------------------------------

async def _audit_flusher(bq_client, table: str) -> None:
    """Drain _audit_deque and write rows to BigQuery in a tight loop.

    Runs until cancelled (SIGTERM / lifespan shutdown). Does not retry on BQ
    write errors — drop and log.
    """
    loop = asyncio.get_running_loop()
    while True:
        while _audit_deque:
            try:
                row = _audit_deque.popleft()
            except IndexError:
                break
            try:
                errors = await loop.run_in_executor(
                    None, bq_client.insert_rows_json, table, [row]
                )
                if errors:
                    logger.warning(
                        "audit: BQ insert errors for tool %r: %s",
                        row.get("toolName"),
                        errors,
                    )
                else:
                    logger.debug(
                        "audit: wrote row for tool %r requestId=%s",
                        row.get("toolName"),
                        row.get("requestId"),
                    )
            except Exception as exc:
                logger.warning(
                    "audit: BQ write failed for tool %r: %s",
                    row.get("toolName"),
                    exc,
                )
        await asyncio.sleep(0.1)


# ---------------------------------------------------------------------------
# Entry point — called from lifespan
# ---------------------------------------------------------------------------

async def start_audit_flusher() -> asyncio.Task | None:
    """Lazily init the BQ client and start the background flusher task.

    Returns the asyncio.Task on success, or None if client init fails
    (no-op mode — rows accumulate in deque until overflow drops them).
    """
    global _bq_client

    if bigquery is None:
        logger.error("audit: google-cloud-bigquery is not installed; audit disabled")
        return None

    try:
        _bq_client = bigquery.Client(project=settings.gcp_project)
    except Exception as exc:
        logger.error("audit: failed to initialise BQ client: %s", exc)
        return None

    table = (
        f"{settings.gcp_project}.{settings.bq_audit_dataset}"
        ".bq_dataplex_mcp_audit_tool_called"
    )
    logger.info("audit: flusher starting; target table=%s", table)
    task = asyncio.create_task(_audit_flusher(_bq_client, table))
    return task
