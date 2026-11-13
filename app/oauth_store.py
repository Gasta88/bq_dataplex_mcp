"""Firestore-backed state for the OAuth authorization-server handshake.

Stores the short-lived, cross-instance state a single Cloud Run request cannot
keep in process memory. Autoscaled instances mean each browser redirect in an
OAuth handshake can land on a different instance:

  - oauth_clients:        Dynamic Client Registration (RFC 7591) records.
  - oauth_transactions:   in-flight /oauth/authorize -> Google -> /oauth/callback state.
  - oauth_codes:          one-time codes minted at callback time, consumed at /oauth/token.
  - oauth_refresh_tokens: opaque, server-issued refresh tokens wrapping a
                          Google refresh token, so clients never hold Google's
                          long-lived secret.

Firestore's native TTL is a background garbage-collection sweep only, so every
read re-checks `expires_at` and treats stale-but-not-yet-GC'd documents as
absent. Set `FIRESTORE_DATABASE_ID` to the database that backs this store.
"""

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

from google.api_core.exceptions import (
    DeadlineExceeded,
    InternalServerError,
    NotFound,
    ServiceUnavailable,
)
from google.cloud import firestore

from app.config import settings

logger = logging.getLogger(__name__)

_CLIENTS = "oauth_clients"
_TRANSACTIONS = "oauth_transactions"
_CODES = "oauth_codes"
_REFRESH_TOKENS = "oauth_refresh_tokens"
_REFRESH_TOKEN_GRACE_SECONDS = 30
_MAX_ATTEMPTS = 2
_TRANSIENT_ERRORS = (DeadlineExceeded, InternalServerError, ServiceUnavailable)

T = TypeVar("T")


class StoreUnavailable(Exception):
    """Firestore did not answer within the per-call budget (after retry).

    Distinct from "document absent": callers must map this to a retryable
    failure, never to an invalid/expired-credential outcome.
    """

# Lazily instantiated so importing this module (e.g. under pytest, with no
# ADC credentials) never raises — mirrors app/main.py's _bq_client/
# _lineage_client/_dataplex_client lazy-singleton pattern.
_client: firestore.AsyncClient | None = None


def _get_client() -> firestore.AsyncClient:
    global _client
    if _client is None:
        _client = firestore.AsyncClient(
            project=settings.gcp_project,
            database=settings.firestore_database_id or "(default)",
        )
    return _client


async def _bounded(op: str, call: Callable[[], Awaitable[T]]) -> T:
    """Run one Firestore call under a hard per-attempt timeout.

    The gRPC client's own deadlines did not prevent multi-minute stalls on a
    wedged channel, so `asyncio.wait_for` is the outer cap. Retries only
    transient errors/timeouts; every caller passes an idempotent call.
    """
    last_exc: Exception | None = None
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        try:
            return await asyncio.wait_for(call(), timeout=settings.firestore_timeout_seconds)
        except (asyncio.TimeoutError, *_TRANSIENT_ERRORS) as exc:
            last_exc = exc
            logger.warning(
                "firestore_timeout: op=%s attempt=%d/%d error=%s",
                op,
                attempt,
                _MAX_ATTEMPTS,
                type(exc).__name__,
            )
    raise StoreUnavailable(op) from last_exc


def _not_expired(doc: dict[str, Any]) -> bool:
    return doc.get("expires_at", 0) > time.time()


# ---------------------------------------------------------------------------
# Dynamic Client Registration (RFC 7591) records
# ---------------------------------------------------------------------------


async def save_client(
    client_id: str,
    *,
    redirect_uris: list[str],
    client_name: str | None,
    ttl_seconds: int,
) -> None:
    now = time.time()
    doc = {
        "redirect_uris": redirect_uris,
        "client_name": client_name,
        "created_at": now,
        "expires_at": now + ttl_seconds,
    }
    ref = _get_client().collection(_CLIENTS).document(client_id)
    await _bounded("save_client", lambda: ref.set(doc))


async def get_client(client_id: str) -> dict[str, Any] | None:
    ref = _get_client().collection(_CLIENTS).document(client_id)
    snap = await _bounded("get_client", ref.get)
    if not snap.exists:
        return None
    data = snap.to_dict()
    if data is None or not _not_expired(data):
        return None
    return data


# ---------------------------------------------------------------------------
# In-flight /oauth/authorize -> Google -> /oauth/callback transactions
# ---------------------------------------------------------------------------


async def save_transaction(
    txn_id: str,
    *,
    client_id: str,
    client_redirect_uri: str,
    client_state: str | None,
    code_challenge: str,
    google_code_verifier: str,
    ttl_seconds: int,
) -> None:
    now = time.time()
    doc = {
        "client_id": client_id,
        "client_redirect_uri": client_redirect_uri,
        "client_state": client_state,
        "code_challenge": code_challenge,
        "google_code_verifier": google_code_verifier,
        "created_at": now,
        "expires_at": now + ttl_seconds,
    }
    ref = _get_client().collection(_TRANSACTIONS).document(txn_id)
    await _bounded("save_transaction", lambda: ref.set(doc))


async def get_transaction(txn_id: str) -> dict[str, Any] | None:
    ref = _get_client().collection(_TRANSACTIONS).document(txn_id)
    snap = await _bounded("get_transaction", ref.get)
    if not snap.exists:
        return None
    data = snap.to_dict()
    if data is None or not _not_expired(data):
        return None
    return data


async def delete_transaction(txn_id: str) -> None:
    ref = _get_client().collection(_TRANSACTIONS).document(txn_id)
    await _bounded("delete_transaction", ref.delete)


# ---------------------------------------------------------------------------
# One-time codes: minted at callback time, consumed at /oauth/token
# ---------------------------------------------------------------------------


async def save_code(
    code: str,
    *,
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    id_token: str,
    expires_in: int,
    ttl_seconds: int,
    google_refresh_token: str | None = None,
) -> None:
    now = time.time()
    doc = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "id_token": id_token,
        "expires_in": expires_in,
        "google_refresh_token": google_refresh_token,
        "created_at": now,
        "expires_at": now + ttl_seconds,
    }
    ref = _get_client().collection(_CODES).document(code)
    await _bounded("save_code", lambda: ref.set(doc))


async def consume_code(code: str) -> dict[str, Any] | None:
    """Atomically read-check-delete a one-time code.

    Returns None if the code is missing, already used, or past its stored
    expiry (checked in application code — see module docstring on Firestore
    TTL). Runs inside a Firestore transaction so a duplicate /oauth/token
    POST landing on two different Cloud Run instances can't both succeed.

    Deletes the document on successful consumption rather than marking it
    "used" — the doc carries a Google refresh token (a long-lived secret),
    so it must not linger in Firestore waiting for the native TTL sweep
    (which can lag up to ~24h per the module docstring above).
    """
    client = _get_client()
    doc_ref = client.collection(_CODES).document(code)

    @firestore.async_transactional
    async def _txn(transaction: firestore.AsyncTransaction) -> dict[str, Any] | None:
        snap = await doc_ref.get(transaction=transaction)
        if not snap.exists:
            return None
        data = snap.to_dict()
        if data is None or not _not_expired(data):
            return None
        transaction.delete(doc_ref)
        return data

    try:
        return await asyncio.wait_for(
            _txn(client.transaction()), timeout=settings.firestore_timeout_seconds
        )
    except asyncio.TimeoutError as exc:
        logger.warning("firestore_timeout: op=consume_code attempt=1/1 error=TimeoutError")
        raise StoreUnavailable("consume_code") from exc


# ---------------------------------------------------------------------------
# Server-issued refresh tokens: wrap Google's own refresh token behind an
# opaque token of our own minting. Google's refresh token is a long-lived
# bearer secret for the user's Workspace identity — it lives only in this
# Firestore document, never returned to the MCP client, never logged.
# ---------------------------------------------------------------------------


async def save_refresh_token(
    refresh_token: str,
    *,
    client_id: str,
    google_refresh_token: str,
    ttl_seconds: int,
    expires_at: float | None = None,
) -> None:
    now = time.time()
    resolved_expires_at = expires_at if expires_at is not None else now + ttl_seconds
    doc = {
        "client_id": client_id,
        "google_refresh_token": google_refresh_token,
        "created_at": now,
        "expires_at": resolved_expires_at,
        "lineage_expires_at": resolved_expires_at,
    }
    ref = _get_client().collection(_REFRESH_TOKENS).document(refresh_token)
    await _bounded("save_refresh_token", lambda: ref.set(doc))


async def get_refresh_token(refresh_token: str) -> dict[str, Any] | None:
    ref = _get_client().collection(_REFRESH_TOKENS).document(refresh_token)
    snap = await _bounded("get_refresh_token", ref.get)
    if not snap.exists:
        return None
    data = snap.to_dict()
    if data is None or not _not_expired(data):
        return None
    return data


async def get_refresh_token_for_revoke(refresh_token: str) -> dict[str, Any] | None:
    """Fetch a refresh-token record for /oauth/revoke, ignoring local expiry.

    Unlike :func:`get_refresh_token`, this does not filter out a document
    whose `expires_at` has already passed (e.g. the old side of a rotation
    still inside its physical Firestore lifetime, or any doc not yet swept
    by the native TTL job, which can lag up to ~24h). Revocation is meant to
    be a robust "kill switch": as long as the document — and the Google
    refresh token it wraps — still physically exists, upstream revocation
    should still fire even if this server would no longer accept the token
    for a refresh.
    """
    ref = _get_client().collection(_REFRESH_TOKENS).document(refresh_token)
    snap = await _bounded("get_refresh_token_for_revoke", ref.get)
    if not snap.exists:
        return None
    return snap.to_dict()


async def delete_refresh_token(refresh_token: str) -> None:
    """Revoke a refresh token — the "kill switch".

    A synchronous delete, not reliant on Firestore's native TTL sweep (which
    can lag up to ~24h per the module docstring above), so revocation takes
    effect on the very next refresh attempt.
    """
    ref = _get_client().collection(_REFRESH_TOKENS).document(refresh_token)
    await _bounded("delete_refresh_token", ref.delete)


async def expire_refresh_token_soon(
    refresh_token: str, grace_seconds: int = _REFRESH_TOKEN_GRACE_SECONDS
) -> None:
    """Set a refresh token to expire after a grace window.

    Used during token rotation to keep the old token valid for a brief
    overlap period (e.g. 30 seconds) after the new token is minted, so a
    client retry with the previous token — due to a lost response — can
    still succeed and receive the new token. After the grace period, the
    token naturally expires via the existing _not_expired check.

    Best-effort: if the record was revoked concurrently, swallow NotFound
    rather than fail the refresh operation.
    """
    ref = _get_client().collection(_REFRESH_TOKENS).document(refresh_token)
    try:
        await _bounded(
            "expire_refresh_token_soon",
            lambda: ref.update({"expires_at": time.time() + grace_seconds}),
        )
    except NotFound:
        logger.debug("expire_refresh_token_soon: document already gone (revoked concurrently)")
