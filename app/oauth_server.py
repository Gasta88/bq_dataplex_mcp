"""Minimal MCP-spec OAuth authorization-server surface.

`FastMCP(..., auth=...)` wires token *verification* into `/mcp` but does not
publish discovery metadata or authorization/token endpoints. A real MCP client
needs the full flow: discovery -> Dynamic Client Registration (RFC 7591) ->
browser Authorization Code + PKCE (RFC 7636) -> token exchange. This module
implements that surface, proxying the browser-facing legs to Google.

The token returned to the MCP client is the raw Google ID token obtained at
`/oauth/callback`, so `JWTAuthProvider` keeps validating it unchanged on every
`/mcp` request. A bug in the handshake can only block new logins; it cannot
weaken the per-request JWT/`hd` gate.

Two independent PKCE handshakes are in flight: the MCP client's pair (verified
at `/oauth/token`) and an internally generated pair used with Google (verified
by Google during token exchange). They are never conflated.

All handlers are registered as `@mcp.custom_route(...)` in `create_app()`,
outside `RequireAuthMiddleware`, because they are pre-auth by definition.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import html
import logging
import secrets
import time
import urllib.parse

import jwt as pyjwt
from mcp.shared.auth import OAuthMetadata, ProtectedResourceMetadata
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

import app.oauth_store as store
from app.config import settings
from app.oauth_store import StoreUnavailable
from app.google_auth import (
    OAuthError,
    build_authorization_url,
    exchange_code_for_tokens,
    exchange_refresh_token_for_tokens,
    revoke_refresh_token,
)
from app.jwt_auth import WORKSPACE_IDENTITY_REQUIRED, hd_claim_is_valid

logger = logging.getLogger(__name__)

# This service's own hardcoded resource-name literal -- see module docstring
# on why this is not imported from app.main.SERVICE_NAME.
_RESOURCE_NAME = "bq-dataplex-mcp"

# DCR client registrations: long-lived (clients reconnect over weeks/months).
_CLIENT_TTL_SECONDS = 90 * 24 * 3600
# /oauth/authorize -> Google -> /oauth/callback round trip: a human is
# actively clicking through a browser flow.
_TXN_TTL_SECONDS = 600
# Our one-time code between /oauth/callback and the client's /oauth/token
# exchange: no human interaction, should complete in well under a second.
_CODE_TTL_SECONDS = 60
# Our own server-issued refresh token: same 90-day window as DCR client
# registrations, since a refresh token is worthless once its owning client
# registration has expired. Google's own refresh token additionally
# self-expires after ~6 months of inactivity as a second backstop.
_REFRESH_TOKEN_TTL_SECONDS = 90 * 24 * 3600
# Grace window for old refresh token after rotation: allows a retried request
# after a lost response to succeed with the previous token.
_REFRESH_TOKEN_GRACE_SECONDS = 30


def _oauth_not_configured() -> JSONResponse:
    return JSONResponse({"error": "oauth_not_configured"}, status_code=503)


def _error_page(message: str, *, status_code: int = 400) -> HTMLResponse:
    """Small, self-contained HTML error page — no template engine dependency."""
    body = f"""<!doctype html>
<html>
<head><meta charset="utf-8"><title>Sign-in failed</title></head>
<body style="font-family: sans-serif; max-width: 40em; margin: 4em auto; padding: 0 1em;">
<h1>Sign-in failed</h1>
<p>{html.escape(message)}</p>
</body>
</html>"""
    return HTMLResponse(body, status_code=status_code)


def _append_query(uri: str, **params: str | None) -> str:
    parsed = urllib.parse.urlparse(uri)
    query = urllib.parse.parse_qsl(parsed.query)
    query.extend((k, v) for k, v in params.items() if v is not None)
    return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query)))


def _pkce_challenge_from_verifier(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------------
# Discovery metadata
# ---------------------------------------------------------------------------


async def oauth_protected_resource_metadata(request: Request) -> Response:
    """RFC 9728. Registered at both /.well-known/oauth-protected-resource/mcp
    (the exact path FastMCP's WWW-Authenticate resource_metadata hint points
    to for a resource at /mcp) and a bare root alias.
    """
    if not settings.oauth_base_url:
        return _oauth_not_configured()
    metadata = ProtectedResourceMetadata(
        resource=f"{settings.oauth_base_url}/mcp",
        authorization_servers=[settings.oauth_base_url],
        scopes_supported=["openid", "email"],
        resource_name=_RESOURCE_NAME,
    )
    return JSONResponse(metadata.model_dump(mode="json", exclude_none=True))


async def oauth_authorization_server_metadata(request: Request) -> Response:
    """RFC 8414. We act as the authorization server from the MCP client's
    point of view, proxying the actual login to Google.
    """
    if not settings.oauth_base_url:
        return _oauth_not_configured()
    base = settings.oauth_base_url
    metadata = OAuthMetadata(
        issuer=base,
        authorization_endpoint=f"{base}/oauth/authorize",
        token_endpoint=f"{base}/oauth/token",
        registration_endpoint=f"{base}/oauth/register",
        revocation_endpoint=f"{base}/oauth/revoke",
        scopes_supported=["openid", "email"],
        response_types_supported=["code"],
        grant_types_supported=["authorization_code", "refresh_token"],
        token_endpoint_auth_methods_supported=["none"],
        code_challenge_methods_supported=["S256"],
    )
    return JSONResponse(metadata.model_dump(mode="json", exclude_none=True))


# ---------------------------------------------------------------------------
# Dynamic Client Registration (RFC 7591)
# ---------------------------------------------------------------------------


async def oauth_register(request: Request) -> Response:
    if not settings.oauth_base_url:
        return _oauth_not_configured()
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid_client_metadata"}, status_code=400)

    redirect_uris = body.get("redirect_uris")
    if not redirect_uris or not isinstance(redirect_uris, list):
        return JSONResponse(
            {
                "error": "invalid_client_metadata",
                "error_description": "redirect_uris is required and must be a non-empty array.",
            },
            status_code=400,
        )
    for uri in redirect_uris:
        if not isinstance(uri, str):
            return JSONResponse(
                {
                    "error": "invalid_client_metadata",
                    "error_description": "Each redirect_uri must be a string.",
                },
                status_code=400,
            )
        parsed = urllib.parse.urlparse(uri)
        is_https = parsed.scheme == "https"
        is_loopback = parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1")
        if not (is_https or is_loopback):
            return JSONResponse(
                {
                    "error": "invalid_redirect_uri",
                    "error_description": f"redirect_uri must be https, or http on localhost: {uri!r}",
                },
                status_code=400,
            )

    client_id = secrets.token_urlsafe(24)
    await store.save_client(
        client_id,
        redirect_uris=redirect_uris,
        client_name=body.get("client_name"),
        ttl_seconds=_CLIENT_TTL_SECONDS,
    )
    return JSONResponse(
        {
            "client_id": client_id,
            "redirect_uris": redirect_uris,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "client_id_issued_at": int(time.time()),
        },
        status_code=201,
    )


# ---------------------------------------------------------------------------
# Authorization Code + PKCE, proxied to Google
# ---------------------------------------------------------------------------


async def oauth_authorize(request: Request) -> Response:
    if not settings.oauth_base_url:
        return _oauth_not_configured()

    q = request.query_params
    client_id = q.get("client_id")
    redirect_uri = q.get("redirect_uri")
    state = q.get("state")
    code_challenge = q.get("code_challenge")
    code_challenge_method = q.get("code_challenge_method")

    client = await store.get_client(client_id) if client_id else None
    if client is None:
        return _error_page(
            "Unknown or expired client registration. Please reconnect your MCP "
            "client so it can re-register, then try signing in again."
        )
    if redirect_uri not in client["redirect_uris"]:
        return _error_page("redirect_uri does not match the registered value.")
    if (
        q.get("response_type") != "code"
        or code_challenge_method != "S256"
        or not code_challenge
    ):
        return RedirectResponse(
            _append_query(redirect_uri, error="invalid_request", state=state),
            status_code=302,
        )

    # High-entropy correlator, also used as Google's own `state` param — the
    # MCP client's `state` is never sent to Google, only stashed here and
    # reattached on the final redirect in oauth_callback.
    txn_id = secrets.token_urlsafe(32)
    google = build_authorization_url(
        redirect_uri=f"{settings.oauth_base_url}/oauth/callback",
        state=txn_id,
    )
    await store.save_transaction(
        txn_id,
        client_id=client_id,
        client_redirect_uri=redirect_uri,
        client_state=state,
        code_challenge=code_challenge,
        google_code_verifier=google["code_verifier"],
        ttl_seconds=_TXN_TTL_SECONDS,
    )
    return RedirectResponse(google["url"], status_code=302)


async def oauth_callback(request: Request) -> Response:
    if not settings.oauth_base_url:
        return _oauth_not_configured()

    q = request.query_params
    txn_id = q.get("state")
    code = q.get("code")
    google_error = q.get("error")

    txn = await store.get_transaction(txn_id) if txn_id else None
    if txn is None:
        return _error_page(
            "This sign-in link has expired or was already used. Please retry "
            "from your MCP client."
        )

    if google_error:
        await store.delete_transaction(txn_id)
        return _error_page(f"Google sign-in was not completed: {google_error}")

    try:
        loop = asyncio.get_running_loop()
        tokens = await loop.run_in_executor(
            None,
            lambda: exchange_code_for_tokens(
                code=code,
                redirect_uri=f"{settings.oauth_base_url}/oauth/callback",
                code_verifier=txn["google_code_verifier"],
            ),
        )
    except OAuthError as exc:
        logger.warning("oauth_callback: Google token exchange failed: %s", exc)
        await store.delete_transaction(txn_id)
        return _error_page(
            "Sign-in failed while contacting Google. Please try again.",
            status_code=502,
        )

    id_token = tokens["id_token"]
    claims = pyjwt.decode(id_token, options={"verify_signature": False})
    hd = claims.get("hd")
    if not hd_claim_is_valid(hd, settings.google_workspace_domain):
        logger.warning(
            "oauth_callback: rejection [%s] — hd claim is %r, expected %r",
            WORKSPACE_IDENTITY_REQUIRED,
            hd,
            settings.google_workspace_domain,
        )
        await store.delete_transaction(txn_id)
        return _error_page(
            f"Access is restricted to {settings.google_workspace_domain} Google "
            "Workspace accounts. You signed in with a different Google account — "
            "please retry and choose your Workspace identity.",
            status_code=403,
        )

    google_refresh_token = tokens.get("refresh_token")
    if not google_refresh_token:
        # Can legitimately happen if the user's Google account already granted
        # this OAuth client offline access without prompt=consent forcing a
        # fresh grant (e.g. an org-level policy bypass). Login must still
        # succeed — refresh support is additive, not a hard requirement.
        logger.warning(
            "oauth_callback: Google did not return a refresh_token; this "
            "session will require re-authentication after the access token "
            "expires (~1hr) instead of silently refreshing."
        )

    our_code = secrets.token_urlsafe(32)
    expires_in = max(int(claims.get("exp", time.time() + 3600) - time.time()), 0)
    await store.save_code(
        our_code,
        client_id=txn["client_id"],
        redirect_uri=txn["client_redirect_uri"],
        code_challenge=txn["code_challenge"],
        id_token=id_token,
        expires_in=expires_in,
        ttl_seconds=_CODE_TTL_SECONDS,
        google_refresh_token=google_refresh_token,
    )
    await store.delete_transaction(txn_id)
    return RedirectResponse(
        _append_query(txn["client_redirect_uri"], code=our_code, state=txn["client_state"]),
        status_code=302,
    )


async def oauth_token(request: Request) -> Response:
    if not settings.oauth_base_url:
        return _oauth_not_configured()

    form = await request.form()
    grant_type = form.get("grant_type")
    try:
        if grant_type == "authorization_code":
            return await _oauth_token_authorization_code(form)
        if grant_type == "refresh_token":
            return await _oauth_token_refresh(form)
    except StoreUnavailable:
        # Never an invalid_grant: the credential may be fine, the store just
        # didn't answer. 503 + Retry-After lets the client retry without
        # discarding its session.
        return JSONResponse(
            {
                "error": "temporarily_unavailable",
                "error_description": "Token store did not respond. Please retry.",
            },
            status_code=503,
            headers={"Retry-After": "2"},
        )
    return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)


async def _oauth_token_authorization_code(form) -> Response:
    code = form.get("code")
    redirect_uri = form.get("redirect_uri")
    code_verifier = form.get("code_verifier")
    client_id = form.get("client_id")

    record = await store.consume_code(code) if code else None
    if record is None:
        return JSONResponse(
            {
                "error": "invalid_grant",
                "error_description": "Code is invalid, expired, or already used.",
            },
            status_code=400,
        )
    if client_id and client_id != record["client_id"]:
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    if redirect_uri != record["redirect_uri"]:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "redirect_uri mismatch."},
            status_code=400,
        )
    if not code_verifier:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "code_verifier is required."},
            status_code=400,
        )

    computed = _pkce_challenge_from_verifier(code_verifier)
    if not secrets.compare_digest(computed, record["code_challenge"]):
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "PKCE verification failed."},
            status_code=400,
        )

    response_body: dict[str, str | int] = {
        "access_token": record["id_token"],
        "token_type": "Bearer",
        "expires_in": record["expires_in"],
        "scope": "openid email",
    }

    google_refresh_token = record.get("google_refresh_token")
    if google_refresh_token:
        our_refresh_token = secrets.token_urlsafe(32)
        await store.save_refresh_token(
            our_refresh_token,
            client_id=record["client_id"],
            google_refresh_token=google_refresh_token,
            ttl_seconds=_REFRESH_TOKEN_TTL_SECONDS,
        )
        response_body["refresh_token"] = our_refresh_token

    return JSONResponse(response_body)


async def _oauth_token_refresh(form) -> Response:
    """grant_type=refresh_token: silently exchange our own server-issued
    refresh token for a fresh Google-issued access token, no browser/login
    interaction required. Our opaque refresh token is rotated on every
    successful exchange per OAuth 2.1 guidance: a leaked token grants only a
    single refresh, and subsequent refreshes are issued fresh opaque tokens
    with new TTLs.

    Concurrency note: unlike the one-time authorization code (consumed via a
    Firestore transaction in store.consume_code), our refresh token record is
    *not* single-use and this function does not use a transaction to guard
    it — two concurrent requests bearing the same server-issued refresh token
    (e.g. a client-side retry) can both read the stored Google refresh token
    and both call Google concurrently. This is accepted: Google's own
    refresh-token grant tolerates concurrent use (it may return the same or a
    rotated refresh token), and each call independently re-validates `hd`
    and returns a fresh, independent access token, so no security invariant
    is violated by the race. Code here must not assume Google's refresh
    token value is stable across calls.
    """
    refresh_token = form.get("refresh_token")
    if not refresh_token:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "refresh_token is required."},
            status_code=400,
        )

    record = await store.get_refresh_token(refresh_token)
    if record is None:
        return JSONResponse(
            {
                "error": "invalid_grant",
                "error_description": "Refresh token is invalid, expired, or revoked.",
            },
            status_code=400,
        )

    try:
        loop = asyncio.get_running_loop()
        tokens = await loop.run_in_executor(
            None,
            lambda: exchange_refresh_token_for_tokens(record["google_refresh_token"]),
        )
    except OAuthError as exc:
        logger.warning("oauth_token(refresh_token): Google refresh exchange failed: %s", exc)
        # Distinguish terminal vs transient failures: terminal (4xx client error, not 429)
        # means the token is permanently invalid and must be deleted. Transient (status_code
        # is None, 5xx, 429, or other network/non-JSON errors) means retry is safe.
        is_terminal = exc.status_code is not None and 400 <= exc.status_code < 500 and exc.status_code != 429
        if is_terminal:
            # Terminal failure: Google returned a 4xx client error (except 429 Too Many Requests).
            # Token is permanently invalid; delete it and return 400 invalid_grant.
            await store.delete_refresh_token(refresh_token)
            return JSONResponse(
                {
                    "error": "invalid_grant",
                    "error_description": "Refresh token is invalid, expired, or revoked.",
                },
                status_code=400,
            )
        else:
            # Transient failure: network error (status_code is None), non-JSON response,
            # 5xx upstream error, or 429 Too Many Requests. Keep token intact for retry.
            return JSONResponse(
                {
                    "error": "temporarily_unavailable",
                    "error_description": "Failed to contact Google for token refresh. Please retry.",
                },
                status_code=503,
            )

    id_token = tokens["id_token"]
    claims = pyjwt.decode(id_token, options={"verify_signature": False})
    hd = claims.get("hd")
    if not hd_claim_is_valid(hd, settings.google_workspace_domain):
        # Re-validated on every refresh, not just at initial login, so a
        # since-deprovisioned or wrong-domain identity is rejected within one
        # refresh cycle (~1hr) rather than remaining valid for the life of
        # the refresh token.
        logger.warning(
            "oauth_token(refresh_token): rejection [%s] — hd claim is %r, expected %r",
            WORKSPACE_IDENTITY_REQUIRED,
            hd,
            settings.google_workspace_domain,
        )
        await store.delete_refresh_token(refresh_token)
        return JSONResponse(
            {
                "error": "invalid_grant",
                "error_description": "Workspace identity is no longer valid for this session.",
            },
            status_code=400,
        )

    expires_in = max(int(claims.get("exp", time.time() + 3600) - time.time()), 0)

    # Determine the Google refresh token to store (use rotated value if available).
    stored_google_refresh_token = tokens.get("refresh_token") or record["google_refresh_token"]

    # Mint a new opaque refresh token for this successful refresh (token rotation).
    new_refresh_token = secrets.token_urlsafe(32)
    # Preserve the ORIGINAL expires_at from the login so the 90-day TTL does not
    # reset on every refresh — the entire token lineage expires 90 days after the
    # original login, not 90 days after the most recent refresh.
    await store.save_refresh_token(
        new_refresh_token,
        client_id=record["client_id"],
        google_refresh_token=stored_google_refresh_token,
        ttl_seconds=_REFRESH_TOKEN_TTL_SECONDS,
        expires_at=record.get("lineage_expires_at", record["expires_at"]),
    )
    # Give the old refresh token a grace window instead of deleting it immediately.
    # If the response is lost in transit, a client retry with the old token can
    # still succeed within this grace period and receive the new token.
    await store.expire_refresh_token_soon(refresh_token, _REFRESH_TOKEN_GRACE_SECONDS)

    return JSONResponse(
        {
            "access_token": id_token,
            "token_type": "Bearer",
            "expires_in": expires_in,
            "scope": "openid email",
            "refresh_token": new_refresh_token,
        }
    )


# ---------------------------------------------------------------------------
# Revocation (RFC 7009) — the explicit "kill switch"
# ---------------------------------------------------------------------------


async def oauth_revoke(request: Request) -> Response:
    """RFC 7009 token revocation endpoint.

    Always returns 200 regardless of whether *token* existed or was already
    invalid (RFC 7009 §2.2) — revoking an unknown token is not an error, and
    a non-200 response would leak token validity to the caller.

    Revokes both the local refresh-token record (prevents future refreshes) and
    Google's underlying refresh token (upstream safeguard). The already-issued
    access token (~1hr lifetime) remains valid until it naturally expires.
    """
    if not settings.oauth_base_url:
        return _oauth_not_configured()
    form = await request.form()
    token = form.get("token")
    if token:
        # Fetch the record to get Google's refresh token for upstream revocation.
        # Ignores local expiry (unlike get_refresh_token) — the doc may still
        # physically exist (grace window, or pending Firestore TTL sweep) even
        # if this server would no longer accept it for a refresh; revocation
        # should still reach Google in that case.
        record = await store.get_refresh_token_for_revoke(token)
        if record:
            google_refresh_token = record.get("google_refresh_token")
            # Revoke Google's refresh token upstream (best-effort, doesn't fail the request).
            if google_refresh_token:
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, revoke_refresh_token, google_refresh_token)
        # Delete the local record (prevents further refreshes regardless of upstream result).
        await store.delete_refresh_token(token)
    return Response(status_code=200)
