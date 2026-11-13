"""Google OAuth 2.1 authorization-code flow helpers.

Building blocks for the OAuth 2.1 authorization-code flow with PKCE against
Google Workspace as the identity provider. Route wiring and session/token
management live in `app/oauth_server.py`.

`GOOGLE_OAUTH_CLIENT_ID` and `GOOGLE_OAUTH_CLIENT_SECRET` must be configured;
the helpers raise `OAuthError` when either is missing or the upstream response
is an error.
"""

from __future__ import annotations

import hashlib
import logging
import re
import secrets
import urllib.parse
from typing import Any

import requests

from app.config import settings

logger = logging.getLogger(__name__)

# Google's authorization endpoint (well-known, stable).
_GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
_GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"

# Minimum scopes required by this service.
_SCOPES = ["openid", "email"]


class OAuthError(Exception):
    """Raised when the OAuth flow encounters an upstream or configuration error.

    The human-readable description is accessible via ``str(error)`` or
    ``error.args[0]`` (inherited from :class:`Exception`).

    Attributes
    ----------
    upstream_response : dict | None
        The JSON body returned by the upstream provider, when available.
    status_code : int | None
        The HTTP status code from the upstream provider, when available.
    """

    def __init__(
        self, message: str, upstream_response: dict[str, Any] | None = None, status_code: int | None = None
    ) -> None:
        super().__init__(message)
        self.upstream_response = upstream_response
        self.status_code = status_code


def _require_oauth_config() -> tuple[str, str]:
    """Return (client_id, client_secret) or raise OAuthError if either is empty."""
    client_id = settings.google_oauth_client_id
    client_secret = settings.google_oauth_client_secret
    if not client_id:
        raise OAuthError(
            "GOOGLE_OAUTH_CLIENT_ID is not configured. "
            "Ensure the Secret Manager binding is wired into the Cloud Run service."
        )
    if not client_secret:
        raise OAuthError(
            "GOOGLE_OAUTH_CLIENT_SECRET is not configured. "
            "Ensure the Secret Manager binding is wired into the Cloud Run service."
        )
    return client_id, client_secret


def _generate_pkce_pair() -> tuple[str, str]:
    """Generate a PKCE (code_verifier, code_challenge) pair.

    Returns
    -------
    (code_verifier, code_challenge)
        code_verifier  — 43–128 character high-entropy random string (URL-safe base64).
        code_challenge — S256 challenge derived from the verifier (base64url, no padding).
    """
    code_verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = (
        __import__("base64")
        .urlsafe_b64encode(digest)
        .rstrip(b"=")
        .decode("ascii")
    )
    return code_verifier, code_challenge


_PKCE_VERIFIER_RE = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")


def _validate_pkce_verifier(code_verifier: str) -> None:
    """Raise OAuthError if *code_verifier* doesn't meet RFC 7636 requirements."""
    if not _PKCE_VERIFIER_RE.match(code_verifier):
        raise OAuthError(
            "code_verifier must be 43–128 characters and contain only "
            "unreserved ASCII characters (A-Z a-z 0-9 - . _ ~)."
        )


def build_authorization_url(
    redirect_uri: str,
    state: str | None = None,
    code_verifier: str | None = None,
) -> dict[str, str]:
    """Build the Google authorization URL for the OAuth 2.1 authorization-code flow.

    Parameters
    ----------
    redirect_uri : str
        The registered callback URL, e.g. ``https://<cloud-run-url>/oauth/callback``.
        Must exactly match the URI registered in the GCP Console OAuth client.
    state : str | None
        Opaque anti-CSRF token.  When ``None``, a random token is generated.
    code_verifier : str | None
        A caller-supplied PKCE code verifier.  When ``None``, one is generated
        automatically.  Callers must store the verifier and pass it to
        :func:`exchange_code_for_tokens`.

    Returns
    -------
    dict with keys:
        ``url``             — the full authorization URL to redirect the user to.
        ``state``           — the state token (generated or passed in).
        ``code_verifier``   — the PKCE code verifier (store this; needed for exchange).
        ``code_challenge``  — the S256 PKCE challenge embedded in the URL.

    Raises
    ------
    OAuthError
        If ``GOOGLE_OAUTH_CLIENT_ID`` or ``GOOGLE_OAUTH_CLIENT_SECRET`` is not set.
    """
    client_id, _ = _require_oauth_config()

    if state is None:
        state = secrets.token_urlsafe(32)

    if code_verifier is None:
        code_verifier, code_challenge = _generate_pkce_pair()
    else:
        _validate_pkce_verifier(code_verifier)
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        code_challenge = (
            __import__("base64")
            .urlsafe_b64encode(digest)
            .rstrip(b"=")
            .decode("ascii")
        )

    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(_SCOPES),
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "access_type": "offline",
        "prompt": "consent",
    }
    url = _GOOGLE_AUTH_ENDPOINT + "?" + urllib.parse.urlencode(params)

    logger.debug("Built authorization URL")
    return {
        "url": url,
        "state": state,
        "code_verifier": code_verifier,
        "code_challenge": code_challenge,
    }


def exchange_code_for_tokens(
    code: str,
    redirect_uri: str,
    code_verifier: str,
) -> dict[str, Any]:
    """Exchange an authorization code for access and ID tokens.

    Sends a POST to Google's token endpoint and returns the parsed JSON body.
    The response always contains ``access_token`` and ``id_token`` on success.

    Parameters
    ----------
    code : str
        The authorization code received at the callback endpoint.
    redirect_uri : str
        The same redirect URI used in :func:`build_authorization_url`.
    code_verifier : str
        The PKCE code verifier generated (or supplied) in :func:`build_authorization_url`.

    Returns
    -------
    dict
        Parsed JSON response from Google's token endpoint.  Contains at minimum:
        ``access_token``, ``id_token``, ``token_type``, ``expires_in``.

        .. warning::
            The returned ``id_token`` is a raw JWT that has **not** been
            verified.  Callers must validate its signature, issuer, audience,
            and expiry before trusting any claims it contains.

    Raises
    ------
    OAuthError
        If the client is not configured, or if the upstream response is an error.
    """
    client_id, client_secret = _require_oauth_config()

    payload = {
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
        "code_verifier": code_verifier,
    }

    try:
        response = requests.post(_GOOGLE_TOKEN_ENDPOINT, data=payload, timeout=10)
    except requests.RequestException as exc:
        raise OAuthError(f"Token endpoint request failed: {exc}") from exc

    try:
        body: dict[str, Any] = response.json()
    except ValueError as exc:
        raise OAuthError(
            f"Token endpoint returned non-JSON response (status={response.status_code})"
        ) from exc

    if not response.ok or "error" in body:
        error = body.get("error", f"HTTP {response.status_code}")
        description = body.get("error_description", "")
        raise OAuthError(
            f"Token exchange failed: {error} — {description}",
            upstream_response=body,
        )

    missing = [k for k in ("access_token", "id_token") if k not in body]
    if missing:
        raise OAuthError(
            f"Token response missing expected keys: {missing}",
            upstream_response=body,
        )

    logger.debug("Token exchange successful (token_type=%s)", body.get("token_type"))
    return body


def exchange_refresh_token_for_tokens(refresh_token: str) -> dict[str, Any]:
    """Exchange a Google refresh token for a fresh ID token.

    Sends a ``grant_type=refresh_token`` POST to Google's token endpoint.
    No browser/login interaction is required — this is the silent-refresh
    leg of the flow.

    Parameters
    ----------
    refresh_token : str
        Google's own refresh token, as previously returned on the
        authorization-code leg with ``access_type=offline``. This is a
        long-lived bearer secret — callers must never log it.

    Returns
    -------
    dict
        Parsed JSON response from Google's token endpoint. Contains at
        minimum ``id_token`` on success. Note that Google's refresh-token
        grant does not always return a new ``refresh_token`` — callers must
        not assume one is present, and must not assume the value never
        rotates when Google does return one.

        .. warning::
            The returned ``id_token`` is a raw JWT that has **not** been
            verified. Callers must (re-)validate its signature, issuer,
            audience, and any authorization claims (e.g. ``hd``) before
            trusting it.

    Raises
    ------
    OAuthError
        If the client is not configured, or if the upstream response is an error.
    """
    client_id, client_secret = _require_oauth_config()

    payload = {
        "refresh_token": refresh_token,
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "refresh_token",
    }

    try:
        response = requests.post(_GOOGLE_TOKEN_ENDPOINT, data=payload, timeout=10)
    except requests.RequestException as exc:
        raise OAuthError(f"Refresh token endpoint request failed: {exc}") from exc

    try:
        body: dict[str, Any] = response.json()
    except ValueError as exc:
        raise OAuthError(
            f"Refresh token endpoint returned non-JSON response (status={response.status_code})"
        ) from exc

    if not response.ok or "error" in body:
        error = body.get("error", f"HTTP {response.status_code}")
        description = body.get("error_description", "")
        # Google's token endpoint is expected to use 4xx for errors (RFC 6749
        # §5.2), but the codebase already defends against a 2xx response that
        # still carries a structured "error" body (see the analogous guard in
        # exchange_code_for_tokens). When that happens, synthesize a 4xx-class
        # status so callers classifying terminal-vs-transient failures (e.g.
        # _oauth_token_refresh) still treat it as a definitive rejection
        # instead of a transient one that never gets cleaned up.
        status_code = response.status_code if not response.ok else 400
        raise OAuthError(
            f"Refresh token exchange failed: {error} — {description}",
            upstream_response=body,
            status_code=status_code,
        )

    if "id_token" not in body:
        raise OAuthError(
            "Refresh token response missing expected key: 'id_token'",
            upstream_response=body,
        )

    logger.debug("Refresh token exchange successful (token_type=%s)", body.get("token_type"))
    return body


def revoke_refresh_token(refresh_token: str) -> None:
    """Revoke a Google refresh token by calling Google's revocation endpoint.

    This is a best-effort cleanup call — if it fails, we log a warning but do
    not raise, since the caller's revocation operation must not be blocked by
    this upstream call. Once the local refresh-token record is deleted, the
    session is already invalidated locally; upstream revocation is an additional
    safeguard.

    Parameters
    ----------
    refresh_token : str
        Google's own refresh token to revoke. This is a long-lived bearer
        secret — callers must never log it.
    """
    payload = {"token": refresh_token}

    try:
        response = requests.post("https://oauth2.googleapis.com/revoke", data=payload, timeout=10)
        response.raise_for_status()
        logger.debug("Google refresh token revoked successfully")
    except requests.RequestException as exc:
        # Best-effort: log and swallow. This must not fail the caller's revoke request.
        logger.warning("Failed to revoke Google refresh token upstream: %s", exc)
