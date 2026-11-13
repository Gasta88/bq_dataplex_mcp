"""BigQuery/Dataplex MCP Cloud Run service entrypoint.

A `fastmcp.FastMCP` streamable-HTTP application exposing seven read-only tools:
`ping`, `list_datasets`, `list_tables`, `get_table_metadata`, `execute_sql`,
`get_data_lineage`, and `get_data_quality_results`.

The module-level `mcp` singleton is built by `create_app()` rather than eagerly,
because `FastMCP.__init__`'s `auth` parameter is fixed at construction time.
The factory lets the test suite build both an auth-disabled instance and an
independent auth-enabled instance without either leaking into the other through
Python's module-import cache.

When OAuth is configured (`GOOGLE_OAUTH_CLIENT_ID`/`_SECRET` set), the app
publishes its own authorization-server surface (`/.well-known/*`, `/oauth/*`)
and validates Google Workspace ID tokens on `/mcp` via `JWTAuthProvider`.
Tool handlers run on a dedicated bounded thread pool so slow BigQuery calls do
not block the event loop.
"""

from __future__ import annotations

import asyncio
import contextvars
import functools
import inspect
import logging
import os
import signal
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager

from fastmcp import FastMCP
from starlette.middleware import Middleware

import app.audit as audit
from app.audit import audit_tool_call, start_audit_flusher
from app.config import Settings, settings
from app.jwt_auth import JWTAuthProvider
from app.oauth_server import (
    oauth_authorization_server_metadata,
    oauth_authorize,
    oauth_callback,
    oauth_protected_resource_metadata,
    oauth_register,
    oauth_revoke,
    oauth_token,
)
from app.rejection_log import McpRejectionLogger
from app.services.bigquery_client import BigQueryClient
from app.services.cache_service import CacheService
from app.services.dataplex_client import DataplexClient
from app.services.lineage_client import LineageClient
from app.services.mermaid_generator import generate_empty_lineage_diagram
from app.validation import validate_dataset_id, validate_sql_query, validate_table_id

# Substring match against LineageClient.get_table_lineage's exact reference-derived
# error message (see app/services/lineage_client.py's
# _LINEAGE_NOT_AVAILABLE_MESSAGE) -- distinguishes the "no lineage data"
# branch from any other error re-raised unchanged, matching the reference
# implementation's own substring check.
_NO_LINEAGE_DATA_MESSAGE_SUBSTRING = "no lineage data available"

SERVICE_NAME = "bq-dataplex-mcp"
DEFAULT_PORT = 8080

logger = logging.getLogger(__name__)

# Safe to build eagerly at import time -- touches no credentials. Shared
# across every `create_app()`-constructed `FastMCP` instance (module-level
# state, not per-instance) since the tool functions below read it by name,
# not through the `mcp` object itself.
cache = CacheService(settings.cache_enabled)

# `BigQueryClient` is *not* built eagerly: its constructor builds a real
# `google.cloud.bigquery.Client`, which resolves Application Default
# Credentials synchronously. `tests/test_main.py` imports this module
# directly, so eager construction here would require real ADC just to
# collect the test suite. `_get_bq_client()` defers construction to first
# tool call and caches the result for the remainder of the process.
_bq_client: BigQueryClient | None = None
_bq_client_lock = threading.Lock()


def _get_bq_client() -> BigQueryClient:
    global _bq_client
    if _bq_client is None:
        with _bq_client_lock:
            if _bq_client is None:
                _bq_client = BigQueryClient(
                    settings.gcp_project,
                    settings.bigquery_location,
                    settings.bigquery_reservation,
                )
    return _bq_client


# `LineageClient` is *not* built eagerly either, for the same reason as
# `_bq_client` above: its constructor builds a real
# `google.cloud.datacatalog_lineage.LineageClient`, which resolves
# Application Default Credentials synchronously.
_lineage_client: LineageClient | None = None
_lineage_client_lock = threading.Lock()


def _get_lineage_client() -> LineageClient:
    global _lineage_client
    if _lineage_client is None:
        with _lineage_client_lock:
            if _lineage_client is None:
                # No `settings.bigquery_location` argument: the reference
                # implementation likewise constructs its client with only the
                # project ID.
                _lineage_client = LineageClient(settings.gcp_project)
    return _lineage_client


# `DataplexClient` is *not* built eagerly either, for the same reason as
# `_bq_client`/`_lineage_client` above: its constructor builds a real
# `google.cloud.dataplex_v1.DataScanServiceClient`, which resolves
# Application Default Credentials synchronously.
_dataplex_client: DataplexClient | None = None
_dataplex_client_lock = threading.Lock()


def _get_dataplex_client() -> DataplexClient:
    global _dataplex_client
    if _dataplex_client is None:
        with _dataplex_client_lock:
            if _dataplex_client is None:
                # No `location` argument, matching the reference
                # implementation's `new DataplexClient(config.gcp.projectId)`.
                _dataplex_client = DataplexClient(settings.gcp_project)
    return _dataplex_client


# ---------------------------------------------------------------------------
# MCP tools
# ---------------------------------------------------------------------------


@audit_tool_call
def ping() -> dict:
    """Check if the Dataplex/BQ MCP service is running.

    Use this when you need to verify service health or connectivity.
    Not this when you need real Dataplex/BigQuery/lineage data -- use
    `list_datasets`, `list_tables`, `get_table_metadata`, `get_data_lineage`,
    `get_data_quality_results`, or `execute_sql` instead (all six data tools
    are registered below).
    """
    return {"status": "ok", "service": SERVICE_NAME}


@audit_tool_call
def list_datasets() -> dict:
    """List all BigQuery datasets in the configured GCP project.

    Use this when you need to enumerate which datasets exist before drilling into
    a specific one, or a user asks what datasets/schemas exist in general.
    Not this when you already know the dataset and need its tables or a table's
    schema -- use `list_tables` or `get_table_metadata` instead. Not this when
    you could instead run an `INFORMATION_SCHEMA` query via `execute_sql` --
    this tool is the cheaper, purpose-built path for enumeration and should
    always be preferred.
    """
    cache_key = cache.generate_key("datasets")
    if cache.has(cache_key):
        return {"datasets": cache.get(cache_key)}

    datasets = _get_bq_client().list_datasets()
    cache.set(cache_key, datasets)
    return {"datasets": datasets}


@audit_tool_call
def list_tables(dataset_id: str) -> dict:
    """List all tables in a BigQuery dataset.

    Use this when you know the dataset and need to see what tables it contains,
    or a user asks what tables exist in a given dataset.
    Not this when you need the datasets themselves -- use `list_datasets` first.
    Not this when you need a specific table's schema, size, or partitioning --
    use `get_table_metadata` instead. Not this when you could instead run a
    `SELECT table_name FROM <dataset>.INFORMATION_SCHEMA.TABLES` via
    `execute_sql` -- this tool is the cheaper, purpose-built path for
    enumeration and should always be preferred.
    """
    dataset_id = validate_dataset_id(dataset_id)

    cache_key = cache.generate_key("tables", dataset_id)
    if cache.has(cache_key):
        return {"tables": cache.get(cache_key)}

    tables = _get_bq_client().list_tables(dataset_id)
    cache.set(cache_key, tables)
    return {"tables": tables}


@audit_tool_call
def get_table_metadata(dataset_id: str, table_id: str) -> dict:
    """Get comprehensive metadata for a BigQuery table including schema,
    descriptions, clustering, partitioning, and partition filters.

    Use this when you need structural facts about a table itself -- its column
    schema, row/byte counts, clustering, partitioning, or labels -- not the data
    inside it.
    Not this when you need upstream/downstream relationships -- use
    `get_data_lineage` instead. Not this when you need pass/fail data-quality
    scan results -- use `get_data_quality_results` instead. Not this when you
    need actual row data or aggregates -- use `execute_sql` instead; do not
    query `INFORMATION_SCHEMA` for facts this tool already returns directly.
    """
    dataset_id = validate_dataset_id(dataset_id)
    table_id = validate_table_id(table_id)

    cache_key = cache.generate_key("metadata", dataset_id, table_id)
    if cache.has(cache_key):
        return cache.get(cache_key)

    metadata = _get_bq_client().get_table_metadata(dataset_id, table_id)
    cache.set(cache_key, metadata)
    return metadata


@audit_tool_call
def get_data_lineage(dataset_id: str, table_id: str) -> dict:
    """Get upstream and downstream data lineage for a BigQuery table with Mermaid
    diagram visualization.

    Use this when a user asks where a table's data comes from, what depends on
    it downstream, or wants a lineage/dependency diagram.
    Not this when you need the table's own schema, size, or partitioning -- use
    `get_table_metadata` instead. Not this when you need data-quality scan
    results -- use `get_data_quality_results` instead.

    Args:
        dataset_id: BigQuery dataset ID.
        table_id: BigQuery table ID. Lineage depth is fixed at 3 levels
            upstream/downstream and is not a caller-adjustable parameter.
    """
    dataset_id = validate_dataset_id(dataset_id)
    table_id = validate_table_id(table_id)

    cache_key = cache.generate_key("lineage", dataset_id, table_id)
    if cache.has(cache_key):
        return cache.get(cache_key)

    try:
        lineage = _get_lineage_client().get_table_lineage(dataset_id, table_id, 3)
    except Exception as exc:
        if _NO_LINEAGE_DATA_MESSAGE_SUBSTRING in str(exc):
            # Deliberately not cached -- mirrors the reference implementation's own
            # `getDataLineage`, whose `cache.set` call sits inside the `try`
            # block, before the real lineage call's own exception can be
            # raised, so it is never reached on this branch. Each call to a
            # lineage-less table re-triggers the real API call and
            # empty-diagram construction every time (see
            # Strategy -- NEEDS VERIFICATION note).
            return {
                "upstream": [],
                "downstream": [],
                "links": [],
                "mermaidDiagram": generate_empty_lineage_diagram(
                    dataset_id, table_id, "No lineage data available for this table"
                ),
            }
        raise

    cache.set(cache_key, lineage)
    return lineage


@audit_tool_call
def get_data_quality_results(dataset_id: str, table_id: str) -> dict:
    """Get the latest data quality scan results for a BigQuery table.

    Use this when a user asks whether a table's data quality checks are passing,
    or wants scan scores/dimensions (completeness, validity, etc.) for a table.
    Not this when you need the table's schema, size, or partitioning -- use
    `get_table_metadata` instead. Not this when you need lineage/dependency
    information -- use `get_data_lineage` instead.
    """
    dataset_id = validate_dataset_id(dataset_id)
    table_id = validate_table_id(table_id)

    cache_key = cache.generate_key("quality", dataset_id, table_id)
    if cache.has(cache_key):
        return cache.get(cache_key)

    result = _get_dataplex_client().get_data_quality_results(dataset_id, table_id)

    if result is None:
        # Deliberately not cached -- mirrors the reference implementation's own
        # `getDataQualityResults` tool wrapper, whose `if (!result) return {
        # message: ... }` branch sits before its `cache.set` call.
        return {"message": "No data quality scans configured for this table"}

    cache.set(cache_key, result)
    return result


@audit_tool_call
def execute_sql(
    query: str,
    max_rows: int | None = None,
    max_bytes_billed: str | None = None,
    dry_run: bool = False,
) -> dict:
    """Execute a read-only (SELECT / WITH) BigQuery SQL query and return the rows.
    DML/DDL is rejected. A maximumBytesBilled cap is always applied. Use dryRun
    to estimate bytes processed without running the query.

    Use this when you need actual row data, aggregates, joins, or any
    computation over table contents that the metadata tools below don't already
    return directly.
    Not this when the question is answerable by `list_datasets`, `list_tables`,
    `get_table_metadata`, `get_data_lineage`, or `get_data_quality_results` --
    prefer those purpose-built tools over an `INFORMATION_SCHEMA` query or
    manual introspection; they are cheaper and already return the exact shape
    needed.

    Every response (dryRun and real runs alike) includes estimatedCostUsd, an
    informational, non-blocking on-demand cost estimate derived from bytes
    processed -- it is never used to block, delay, or otherwise gate query
    execution. When a flat-rate slot reservation is active (BIGQUERY_RESERVATION
    set, prod), this figure is a notional on-demand-equivalent proxy for cost
    attribution, not prod's actual billed amount -- prod's flat-rate billing has
    no true per-byte cost.

    Args:
        query: A single SELECT or WITH statement. Any DML/DDL keyword anywhere
            in the body, or more than one statement, is rejected before any
            BigQuery call is made.
        max_rows: Optional cap on returned rows (default 1000 if unset --
            verified against `BigQueryClient.execute_sql`'s
            `job.result(max_results=max_rows or 1000)` call).
        max_bytes_billed: Optional override of the maximumBytesBilled cost cap
            (default 100 GiB).
        dry_run: When true, estimates bytes processed without billing or
            running the query -- returns `{dryRun, totalBytesProcessed,
            estimatedGiB, estimatedCostUsd}` instead of rows. Real runs return
            `{rows, rowCount, schema, totalBytesProcessed, cacheHit, jobId,
            estimatedCostUsd}`.
    """
    query = validate_sql_query(query)

    # No cache reads/writes here: `execute_sql` results are never cached,
    # unlike the metadata tools.
    return _get_bq_client().execute_sql(
        query, max_rows=max_rows, max_bytes_billed=max_bytes_billed, dry_run=dry_run
    )


# ---------------------------------------------------------------------------
# Audit lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def _audit_lifespan(server):
    """FastMCP lifespan: start the audit flusher on enter, cancel it on exit.

    `app/audit.py`'s
    module-level deque/BQ-client state is process-wide, not per-`FastMCP`-
    instance -- every instance `create_app()` returns is wired to this same
    lifespan, but only one instance is ever actually served via `.run()` in
    production, so no state is ever shared across two *live* instances (see
    risks section).
    """
    flusher_task = await start_audit_flusher()
    try:
        yield
    finally:
        if flusher_task is not None:
            flusher_task.cancel()
            try:
                await flusher_task
            except asyncio.CancelledError:
                pass
        # Final drain: flush any rows still in the deque at shutdown.
        if audit._bq_client is not None and audit._audit_deque:
            table = (
                f"{settings.gcp_project}.{settings.bq_audit_dataset}"
                ".bq_dataplex_mcp_audit_tool_called"
            )
            remaining = list(audit._audit_deque)
            audit._audit_deque.clear()
            loop = asyncio.get_running_loop()
            # Batch rows to stay within BigQuery's 10 MB streaming-insert limit
            # (worst-case ~96 MB with QUEUE_BOUND=1000 and 32KB per-field truncation).
            # Chunk size of 500 rows is safe and mirrors the per-row loop in _audit_flusher.
            chunk_size = 500
            total_written = 0
            for i in range(0, len(remaining), chunk_size):
                chunk = remaining[i : i + chunk_size]
                try:
                    errors = await loop.run_in_executor(
                        None, audit._bq_client.insert_rows_json, table, chunk
                    )
                    if errors:
                        logger.warning(
                            "audit: final drain chunk %d had BQ errors: %s",
                            i // chunk_size,
                            errors,
                        )
                    else:
                        total_written += len(chunk)
                except Exception as exc:
                    logger.warning(
                        "audit: final drain chunk %d failed: %s", i // chunk_size, exc
                    )
            logger.info("audit: final drain wrote %d/%d rows", total_written, len(remaining))


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

# All seven tool functions above (`ping`, `list_datasets`, `list_tables`,
# `get_table_metadata`, `get_data_lineage`, `get_data_quality_results`,
# `execute_sql`).
_TOOL_FUNCTIONS = (
    ping,
    list_datasets,
    list_tables,
    get_table_metadata,
    get_data_lineage,
    get_data_quality_results,
    execute_sql,
)


# Dedicated pool for tool bodies, separate from asyncio's default executor
# (which app/oauth_server.py uses for the Google token exchange/revoke calls),
# so a burst of slow tool calls can never starve OAuth. Bounded so a flood of
# slow queries cannot spawn unbounded threads.
_TOOL_EXECUTOR_MAX_WORKERS = 16
_tool_executor = ThreadPoolExecutor(
    max_workers=_TOOL_EXECUTOR_MAX_WORKERS, thread_name_prefix="mcp-tool"
)


def _offload_to_thread(fn):
    """Wrap a sync tool so FastMCP awaits it on `_tool_executor`.

    fastmcp 2.x calls sync `def` tools inline on the event-loop thread, so one
    slow `execute_sql` (`job.result()`, up to 120s) froze the whole instance --
    including `/oauth/token` and `/mcp` auth. Applied at registration time
    rather than inside
    `audit_tool_call` so the module-level tool functions stay plain sync
    callables. `functools.wraps` keeps the signature/docstring FastMCP builds
    the tool schema from; the copied context carries the request's auth
    contextvar, which `audit_tool_call` reads inside the worker thread.
    """

    @functools.wraps(fn)
    async def wrapper(*args, **kwargs):
        loop = asyncio.get_running_loop()
        ctx = contextvars.copy_context()
        return await loop.run_in_executor(
            _tool_executor, functools.partial(ctx.run, fn, *args, **kwargs)
        )

    return wrapper


def create_app(app_settings: Settings | None = None) -> FastMCP:
    """Build a fresh, independently-configured `FastMCP` instance.

    `FastMCP.__init__`'s `auth` parameter is baked into the instance at
    construction time -- it is not a mutable post-construction attribute
    (confirmed via reading the installed `fastmcp` package's `FastMCP.__init__`
    signature). A single process-wide, import-time-cached `mcp` object can
    therefore only ever have ONE fixed auth state for the life of the process,
    but this repo's test suite needs both: `tests/test_mcp_auth_integration.py`
    needs auth enforced, while the pre-existing `tests/test_main.py` needs it
    disabled. This factory resolves that by returning a brand-new `FastMCP`
    instance on every call -- `FastMCP` has no shared/global registry
    (confirmed via reading `fastmcp/server/server.py`), so two instances never
    cross-contaminate.

    Every call registers the same 7 pre-existing tools and the 8 OAuth
    discovery/DCR/authorize/callback/token/revoke custom routes
    -- the only thing that varies between calls is `auth=`, controlled by
    whether `(app_settings or settings).google_oauth_client_id` is set.

    Parameters
    ----------
    app_settings : Settings | None
        Settings to build the `JWTAuthProvider` from. Defaults to the shared
        module-level `settings` singleton (`app.config.settings`) when omitted
        -- this is the production/default-test-environment path, and (with no
        `GOOGLE_OAUTH_CLIENT_ID` env var set) produces an auth-disabled
        instance, behaviorally identical to this service's pre-
        bare `FastMCP(SERVICE_NAME)` singleton. Tests that need a
        *different* auth state (e.g. auth enabled) pass their own
        `Settings(google_oauth_client_id="...")` here to get an independent
        instance without mutating the shared `app.config.settings` singleton.
    """
    resolved_settings = app_settings or settings

    jwt_auth_provider = (
        JWTAuthProvider(
            resolved_settings,
            base_url=resolved_settings.oauth_base_url or None,
            protected_resource_handler=oauth_protected_resource_metadata,
        )
        if resolved_settings.google_oauth_client_id
        else None
    )
    if jwt_auth_provider is None:
        if resolved_settings.deploy_env == "prod":
            # Per : prod's Cloud Run IAM policy is `allUsers`,
            # so this OAuth check is the only remaining access-control layer --
            # silently disabling it (as dev intentionally does) would leave
            # every tool, including `execute_sql`, open to the internet.
            raise RuntimeError(
                "create_app: DEPLOY_ENV=prod but GOOGLE_OAUTH_CLIENT_ID is unset -- "
                "refusing to start unauthenticated in prod"
            )
        logger.warning(
            "create_app: GOOGLE_OAUTH_CLIENT_ID is unset — JWT auth disabled; "
            "MCP transport path is unauthenticated"
        )

    app = FastMCP(SERVICE_NAME, lifespan=_audit_lifespan, auth=jwt_auth_provider)

    for fn in _TOOL_FUNCTIONS:
        # fastmcp 4 strips the docstring's `Args:` block from the tool
        # description (moving it into the input schema); pass the full
        # docstring explicitly to keep descriptions 1:1 with the reference bundle.
        app.tool(description=inspect.getdoc(fn))(_offload_to_thread(fn))

    # OAuth authorization-server surface: discovery
    # metadata, Dynamic Client Registration, and the Authorization Code + PKCE
    # handshake proxied to Google Workspace. These routes are pre-auth by
    # definition -- registered via @app.custom_route(...), they land in
    # FastMCP's _additional_http_routes and are never wrapped by
    # RequireAuthMiddleware (see app/oauth_server.py's module docstring). The
    # token handed back to MCP clients is the raw Google ID token, so
    # JWTAuthProvider.verify_token above is completely unaffected by this
    # surface.
    # When the provider serves the /mcp-scoped route itself (so fastmcp can
    # advertise it in 401 challenges), registering it again here would shadow it.
    if not (jwt_auth_provider and jwt_auth_provider.get_routes("/mcp")):
        app.custom_route("/.well-known/oauth-protected-resource/mcp", methods=["GET"])(
            oauth_protected_resource_metadata
        )
    app.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])(
        oauth_protected_resource_metadata
    )
    app.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])(
        oauth_authorization_server_metadata
    )
    app.custom_route("/oauth/register", methods=["POST"])(oauth_register)
    app.custom_route("/oauth/authorize", methods=["GET"])(oauth_authorize)
    app.custom_route("/oauth/callback", methods=["GET"])(oauth_callback)
    app.custom_route("/oauth/token", methods=["POST"])(oauth_token)
    app.custom_route("/oauth/revoke", methods=["POST"])(oauth_revoke)

    return app


# Sole module-level line for production use (`mcp.run(...)` at the bottom is
# unaffected). With no `GOOGLE_OAUTH_CLIENT_ID` env var set (the case today,
# and unchanged for the default test/CI environment), this is auth-disabled,
# identical in behavior to this service's pre- bare singleton.
mcp = create_app()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def resolve_port() -> int:
    """Reads $PORT, falling back to DEFAULT_PORT when absent or empty.

    Matches the Dockerfile's `ENV PORT=8080` and the  placeholder's
    identical fallback behavior.
    """
    return int(os.environ.get("PORT") or DEFAULT_PORT)


def _handle_sigterm(signum: int, frame: object) -> None:
    """Clean, idempotent shutdown on SIGTERM.

    `sys.exit(0)` raises `SystemExit` in the main thread, which uvicorn's own
    server loop (started via `mcp.run(...)` below) catches to unwind cleanly.
    Cloud Run/Docker can resend SIGTERM during shutdown; calling this handler
    again is safe -- it always just raises the same `SystemExit(0)`, mirroring
    Mirrors the original service's SIGTERM handling.
    """
    sys.exit(0)


def main() -> None:
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # Cost control: framework-level per-request logs scale 1:1 with every tool
    # call and would dwarf this service's own (currently minimal) application
    # logs in GCP Logging volume/cost. Mirrors the original service's
    # rationale/line.
    logging.getLogger("mcp.server.lowlevel.server").setLevel(logging.WARNING)
    signal.signal(signal.SIGTERM, _handle_sigterm)
    port = resolve_port()
    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=port,
        # FastMCP defaults to stateful streamable-HTTP mode, which keeps
        # Mcp-Session-Id -> transport state in-process only. Cloud Run
        # autoscales across instances with no session affinity, so a client's
        # follow-up request can land on a different instance and fail to
        # resolve its session. stateless_http=True gives every request a fresh
        # transport with no server-side session tracking, removing the
        # cross-instance affinity requirement entirely.
        stateless_http=True,
        # Disable uvicorn's per-HTTP-request access log line -- see cost-control
        # comment above.
        uvicorn_config={"access_log": False},
        # One greppable WARNING per protocol-layer rejection on /mcp
        # (see app/rejection_log.py); observes the response, never alters it.
        middleware=[Middleware(McpRejectionLogger)],
    )


if __name__ == "__main__":
    main()
