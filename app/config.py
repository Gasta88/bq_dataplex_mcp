"""Env-driven runtime configuration for the BigQuery/Dataplex MCP service.

Every setting is a dataclass field backed by an environment variable, with a
safe default so importing this module never raises. Deploy-time environments
inject the values; local runs and tests rely on the defaults.

OAuth 2.1 fields default to empty strings. The auth layer (`app/jwt_auth.py`,
`app/google_auth.py`) guards against missing client credentials at call time
rather than at import time.
"""

from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass, field

# Google Cloud's published on-demand BigQuery analysis price per TiB, for
# `us`/`us-central1`. Only meaningful for on-demand billing: when
# `BIGQUERY_RESERVATION` is set, `execute_sql` uses flat-rate slots with no
# true per-byte cost, so the derived estimate is a notional cost-attribution
# proxy rather than an actual bill. See README.md's audit section.
_DEFAULT_BQ_PRICE_PER_TIB_USD = 6.25


def _parse_bq_price_per_tib_usd() -> float:
    """Reads `BQ_PRICE_PER_TIB_USD`, falling back to the default on an unset,
    malformed (non-numeric), or non-positive override -- mirrors the
    defensive posture of `_parse_audit_queue_bound` rather than crashing
    `Settings()` construction at import time.
    """
    raw = os.getenv("BQ_PRICE_PER_TIB_USD")
    if raw is None:
        return _DEFAULT_BQ_PRICE_PER_TIB_USD
    try:
        value = float(raw.strip())
    except (TypeError, ValueError):
        return _DEFAULT_BQ_PRICE_PER_TIB_USD
    if not math.isfinite(value) or value <= 0:
        return _DEFAULT_BQ_PRICE_PER_TIB_USD
    return value


def _parse_audit_queue_bound() -> int:
    """Reads `AUDIT_QUEUE_BOUND`, falling back to 1000 on an unset or
    malformed (non-numeric, non-positive) override. Requires a positive
    integer to prevent the overflow guard from being always-true (0 or
    negative would cause all rows to be dropped silently).
    """
    raw = os.getenv("AUDIT_QUEUE_BOUND", "").strip()
    if not raw or not re.fullmatch(r"\d+", raw):
        return 1000
    value = int(raw)
    if value <= 0:
        return 1000
    return value


@dataclass
class Settings:
    gcp_project: str = field(default_factory=lambda: os.getenv("GCP_PROJECT", ""))
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))
    # "dev" or "prod", injected by deploy/main.tf as `local.stage` (see
    # DEPLOY_ENV env). Defaults to "dev" so local/test runs never accidentally
    # trip create_app()'s prod-only fail-closed check below.
    deploy_env: str = field(default_factory=lambda: os.getenv("DEPLOY_ENV", "dev"))
    bigquery_location: str = field(
        default_factory=lambda: os.getenv("BIGQUERY_LOCATION", "us-central1")
    )
    bigquery_reservation: str = field(
        default_factory=lambda: os.getenv("BIGQUERY_RESERVATION", "")
    )
    cache_enabled: bool = field(
        default_factory=lambda: os.getenv("CACHE_ENABLED", "true").lower() == "true"
    )

    # -- Per-tool-call audit logging (app/audit.py) ------------------------
    # BigQuery dataset that receives the audit table. Create it before
    # enabling the flusher; failed inserts are logged and dropped.
    bq_audit_dataset: str = field(
        default_factory=lambda: os.getenv("BQ_AUDIT_DATASET", "bq_audit")
    )
    # Maximum number of audit rows buffered in the in-memory deque before new
    # rows are dropped (drop-current, not drop-oldest). Requires a positive
    # `_parse_audit_queue_bound()` here). Requires a positive integer
    # (parsed via _parse_audit_queue_bound). On overflow, app/audit.py logs a
    # stable "audit_queue_overflow_dropped" sentinel that
    # backs a Cloud Logging log-based metric in deploy/main.tf -- this field
    # only controls the bound itself, not the log line's text.
    audit_queue_bound: int = field(default_factory=_parse_audit_queue_bound)

    # -- bytesProcessed/estimatedCostUsd audit columns for execute_sql -----
    # USD price per TiB processed, used to derive `estimatedCostUsd` from
    # execute_sql's `totalBytesProcessed`. Defaults to the current on-demand
    # BigQuery analysis rate -- see _DEFAULT_BQ_PRICE_PER_TIB_USD's
    # comment above for the flat-rate-reservation caveat.
    bq_price_per_tib_usd: float = field(default_factory=_parse_bq_price_per_tib_usd)

    # -- : OAuth 2.1 (Google Workspace via OIDC) ---------------------
    # Google OAuth 2.1 client credentials -- injected from Secret Manager via
    # Cloud Run secret bindings (see deploy/main.tf's `local.oauth_envs`).
    # Empty string is the safe default so importing this module never raises;
    # `app/jwt_auth.py`'s `JWTAuthProvider.__init__` and `app/google_auth.py`'s
    # `_require_oauth_config()` guard against an empty value at their own
    # construction/call time. Per, these resolve (in prod) to the same
    google_oauth_client_id: str = field(
        default_factory=lambda: os.getenv("GOOGLE_OAUTH_CLIENT_ID", "")
    )
    google_oauth_client_secret: str = field(
        default_factory=lambda: os.getenv("GOOGLE_OAUTH_CLIENT_SECRET", "")
    )
    #  (revised 2026-09-25): whitelisted CI service-account identity
    # for no-human-in-the-loop MCP access. This replaces the original
    # "second accepted `aud` value" design (a domain-wide-delegated eval-bot
    # audience), which is confirmed broken -- SA ID tokens never carry `hd`,
    # and the reverted implementation enforced `hd` unconditionally for every
    # accepted audience. The new model keeps a single required `aud`
    # (`google_oauth_client_id`) and instead lets `app/jwt_auth.py`'s
    # `JWTAuthProvider._decode_token` skip the `hd` check only when the
    # token's `email` claim exactly matches this value AND `email_verified`
    # is strictly `True`. Empty string (the default) means no identity is
    # ever exempted from the `hd` check -- byte-for-byte identical to
    # pre- behavior. Per 's "safe empty default" convention:
    # importing this module never raises.
    google_oauth_service_account_email: str = field(
        default_factory=lambda: os.getenv("GOOGLE_OAUTH_SERVICE_ACCOUNT_EMAIL", "")
    )
    # Google Workspace hosted-domain constraint for JWT validation. Tokens
    # whose `hd` claim does not match this value are rejected.
    google_workspace_domain: str = field(
        default_factory=lambda: os.getenv("GOOGLE_WORKSPACE_DOMAIN", "example.com")
    )
    # JWKS cache TTL in seconds. After this interval the cache is considered
    # stale and fresh keys are fetched from Google's JWKS endpoint.
    jwks_cache_ttl_seconds: int = field(
        default_factory=lambda: int(os.getenv("JWKS_CACHE_TTL_SECONDS", "3600"))
        if os.getenv("JWKS_CACHE_TTL_SECONDS", "").isdigit()
        else 3600
    )
    # Public base URL of this Cloud Run service (no trailing slash), used to
    # build absolute OAuth endpoint/metadata URLs (issuer, authorization_endpoint,
    # token_endpoint, resource, redirect_uri for the Google leg). Empty string
    # means the OAuth authorization-server surface is not configured; route
    # handlers in app/oauth_server.py fail closed (503) rather than build
    # broken URLs.
    oauth_base_url: str = field(
        default_factory=lambda: os.getenv("OAUTH_BASE_URL", "").rstrip("/")
    )
    # Firestore database ID backing the OAuth handshake store (DCR clients,
    # in-flight authorize/callback transactions, one-time codes, refresh
    # tokens). Empty when the OAuth path is not in use.
    firestore_database_id: str = field(
        default_factory=lambda: os.getenv("FIRESTORE_DATABASE_ID", "")
    )
    # Per-attempt hard cap on each OAuth-store Firestore call (see
    # app/oauth_store.py's `_bounded`). A token refresh makes ~3 calls, so
    # keep this well under the MCP client's connect timeout / 3.
    firestore_timeout_seconds: float = field(
        default_factory=lambda: float(os.getenv("FIRESTORE_TIMEOUT_SECONDS", "5"))
    )


settings = Settings()
