"""JWT authentication provider for the BigQuery/Dataplex MCP service.

Validates Google Workspace ID tokens on the MCP transport path. Custom routes
(`/oauth/register`, `/oauth/authorize`, ...) are outside this provider because
FastMCP applies `RequireAuthMiddleware` only to the MCP protocol route.

Validation steps, in order:
  1. Fetch RS256 public keys from Google's JWKS endpoint (cached by TTL).
  2. Decode and verify the signature with PyJWT (RS256 only).
  3. Verify the token has not expired.
  4. Verify `aud` equals `settings.google_oauth_client_id`. This is never
     relaxed by the service-account whitelist.
  5. Verify `hd` equals `settings.google_workspace_domain`, unless the
     optional `settings.google_oauth_service_account_email` is set, the
     token's `email` claim matches it exactly, and `email_verified` is
     strictly `True`. That narrow path lets a Workload-Identity-Federation
     service account authenticate without a Workspace `hd` claim.

On failure the provider logs the reason at WARNING (never the token) and
returns None. On a JWKS network error it logs at ERROR and fails closed.

Stable log codes
----------------
`workspace_identity_required` -- `hd` absent or mismatched.
`token_expired` -- expired token.
`ci_service_account_identity_accepted` -- accepted via the whitelist bypass
(INFO, not WARNING, because it is an expected configured identity).

The `email_verified is True` check is mandatory: an unverified `email` claim is
never trusted as a bypass key.
"""

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

import httpx
import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from jwt.algorithms import RSAAlgorithm

from fastmcp.server.auth import AccessToken, AuthProvider
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from app.config import Settings, settings as _default_settings

logger = logging.getLogger(__name__)

_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"

# Maximum token byte length before we log a warning (not an error — still attempt decode).
_MAX_TOKEN_BYTES = 8 * 1024  # 8 KB

# Error code emitted when a token is rejected because the `hd` claim is absent
# or does not match `settings.google_workspace_domain`.  This code is stable
# across releases and is safe to use in Cloud Logging filter expressions.
WORKSPACE_IDENTITY_REQUIRED = "workspace_identity_required"

# Error code emitted when a token is rejected because it has expired. This
# code is stable across releases and is safe to use in Cloud Logging filter
# expressions.
TOKEN_EXPIRED = "token_expired"

# Log line emitted (at INFO) when a token is accepted via the 
# whitelisted-CI-service-account-identity bypass (missing/mismatched `hd`,
# but an exactly matching, non-empty configured `email`). Stable across
# releases and safe to use in Cloud Logging filter expressions.
CI_SERVICE_ACCOUNT_IDENTITY_ACCEPTED = "ci_service_account_identity_accepted"


def hd_claim_is_valid(hd: str | None, expected_domain: str) -> bool:
    """Return True iff `hd` matches the configured Google Workspace domain.

    Shared by JWTAuthProvider._decode_token (MCP transport path, on every
    request) and app.oauth_server's callback handler (once, at login time)
    so the two enforcement points can never drift apart.
    """
    return hd == expected_domain


class JWTAuthProvider(AuthProvider):
    """Validates Google Workspace ID tokens (RS256) on the MCP transport path.

    Raises ValueError at construction time if `google_oauth_client_id` is empty,
    to catch misconfiguration early rather than silently rejecting all tokens.
    """

    def __init__(
        self,
        app_settings: Settings | None = None,
        *,
        base_url: str | None = None,
        protected_resource_handler: Callable[[Request], Awaitable[Response]] | None = None,
    ) -> None:
        super().__init__(base_url=base_url)
        # fastmcp 4 only advertises `resource_metadata=` in the 401
        # `WWW-Authenticate` challenge when the provider itself serves the
        # RFC 9728 route (a bare `app.custom_route` does not count). The
        # handler is injected because app.oauth_server imports this module.
        self._protected_resource_handler = protected_resource_handler
        self._settings: Settings = app_settings or _default_settings
        if not self._settings.google_oauth_client_id:
            raise ValueError(
                "JWTAuthProvider: settings.google_oauth_client_id is empty. "
                "Ensure GOOGLE_OAUTH_CLIENT_ID is set before constructing JWTAuthProvider."
            )
        # JWKS in-memory cache: dict mapping kid -> RSAPublicKey
        self._jwks_cache: dict[str, RSAPublicKey] = {}
        # Timestamp (monotonic) of the last successful JWKS fetch
        self._jwks_fetched_at: float = 0.0
        # Minimum interval (seconds) between forced JWKS refreshes
        self._jwks_min_forced_refresh_interval: float = 60.0
        # Timestamp (monotonic) of the last forced JWKS refresh (to prevent
        # attackers from triggering a refresh per request via invalid signatures).
        # Initialized to a value that always reads as "long ago" at startup.
        self._jwks_forced_refresh_at: float = -self._jwks_min_forced_refresh_interval
        # Asyncio lock: prevents concurrent coroutines from issuing duplicate JWKS fetches
        self._jwks_lock: asyncio.Lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Public API (fastmcp AuthProvider interface)
    # ------------------------------------------------------------------

    def get_routes(self, mcp_path: str | None = None) -> list[Route]:
        if self._protected_resource_handler is None or not self.base_url or not mcp_path:
            return []
        return [
            Route(
                f"/.well-known/oauth-protected-resource{mcp_path}",
                endpoint=self._protected_resource_handler,
                methods=["GET"],
            )
        ]

    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify a Google Workspace Bearer token.

        Returns an AccessToken on success, None on any validation failure.
        Never logs the token value at any log level.
        """
        if len(token.encode()) > _MAX_TOKEN_BYTES:
            logger.warning(
                "jwt_auth: token exceeds %d bytes — still attempting decode", _MAX_TOKEN_BYTES
            )

        # Step 1: resolve the signing key (from cache or fresh JWKS fetch)
        kid = self._extract_kid(token)
        public_key = await self._get_public_key(kid)
        if public_key is None:
            # The kid was not found in the cache. If the cache is fresh (valid for up
            # to 3600s), we may have missed a recent key rotation. Attempt a single
            # throttled refresh before giving up (reusing the same min-interval guard).
            refreshed_key = await self._get_public_key(kid, force_refresh=True)
            if refreshed_key is None:
                logger.warning("jwt_auth: rejection — public key not found for kid=%r", kid)
                return None
            public_key = refreshed_key

        # Step 2–5: decode + claim validation
        payload, is_sig_error = self._decode_token(token, public_key)

        if payload is None:
            # Only retry with a fresh JWKS fetch on InvalidSignatureError — the one case
            # that indicates Google may have rotated the key material for an existing kid.
            # Claim failures (expired, wrong aud, wrong hd) are definitive rejections that
            # a JWKS refresh cannot fix, and retrying them would amplify load on Google's
            # JWKS endpoint for every rejected request.
            if not is_sig_error:
                return None
            refreshed_key = await self._get_public_key(kid, force_refresh=True)
            if refreshed_key is None or refreshed_key is public_key:
                # No new key was obtained — give up.
                return None
            logger.info("jwt_auth: retrying decode after forced JWKS refresh")
            payload, _ = self._decode_token(token, refreshed_key)
            if payload is None:
                return None

        sub = payload.get("sub", "")
        return AccessToken(
            token=token,
            client_id=sub,
            scopes=[],
            expires_at=payload.get("exp"),
            subject=sub,
            claims=payload,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_kid(token: str) -> str | None:
        """Extract the `kid` header from a JWT without verifying the signature."""
        try:
            header = pyjwt.get_unverified_header(token)
            return header.get("kid")
        except pyjwt.exceptions.DecodeError:
            return None

    def _decode_token(
        self,
        token: str,
        public_key: RSAPublicKey,
    ) -> tuple[dict[str, Any] | None, bool]:
        """Decode and validate the JWT.

        Returns (payload, is_signature_error).
        payload is None on any failure; is_signature_error is True only for
        InvalidSignatureError, indicating a JWKS refresh-and-retry is worthwhile.
        Never logs the token value.
        """
        try:
            payload: dict[str, Any] = pyjwt.decode(
                token,
                key=public_key,
                algorithms=["RS256"],
                audience=self._settings.google_oauth_client_id,
                options={"verify_exp": True},
            )
        except pyjwt.exceptions.ExpiredSignatureError:
            logger.warning("jwt_auth: rejection [%s] — token is expired", TOKEN_EXPIRED)
            return None, False
        except pyjwt.exceptions.InvalidAudienceError:
            logger.warning(
                "jwt_auth: rejection — audience mismatch (expected %s)",
                self._settings.google_oauth_client_id,
            )
            return None, False
        except pyjwt.exceptions.InvalidSignatureError:
            logger.warning("jwt_auth: rejection — invalid signature")
            return None, True
        except pyjwt.exceptions.DecodeError as exc:
            logger.warning("jwt_auth: rejection — decode error: %s", exc)
            return None, False
        except pyjwt.exceptions.PyJWTError as exc:
            logger.warning("jwt_auth: rejection — JWT error: %s", exc)
            return None, False

        hd = payload.get("hd")
        if not hd_claim_is_valid(hd, self._settings.google_workspace_domain):
            # Whitelist-by-email `hd`-skip: a WIF-minted CI service-account
            #  Revision 2, ): a WIF-minted CI service-account ID
            # token never carries an `hd` claim at all (SA tokens aren't
            # user-impersonation tokens), so the one whitelisted identity is
            # allowed to skip the `hd` check -- but only when both the `email`
            # claim exactly matches the configured whitelist AND
            # `email_verified` is strictly `True` (never a bare truthy check).
            ci_email = self._settings.google_oauth_service_account_email
            is_whitelisted_sa = (
                bool(ci_email)
                and payload.get("email") == ci_email
                and payload.get("email_verified") is True
            )
            if is_whitelisted_sa:
                logger.info(
                    "jwt_auth: acceptance [%s] — hd claim is %r, but email %r matches "
                    "the configured CI service-account whitelist (email_verified=True)",
                    CI_SERVICE_ACCOUNT_IDENTITY_ACCEPTED,
                    hd,
                    ci_email,
                )
                return payload, False
            logger.warning(
                "jwt_auth: rejection [%s] — hd claim is %r, expected %r",
                WORKSPACE_IDENTITY_REQUIRED,
                hd,
                self._settings.google_workspace_domain,
            )
            return None, False

        return payload, False

    async def _get_public_key(
        self,
        kid: str | None,
        *,
        force_refresh: bool = False,
    ) -> RSAPublicKey | None:
        """Return the RSA public key for the given kid.

        Uses the in-memory cache; fetches from Google's JWKS endpoint if the
        cache is stale (older than jwks_cache_ttl_seconds) or if force_refresh=True
        (subject to a minimum interval guard to prevent attackers from forcing
        one unthrottled fetch per request).
        """
        ttl = self._settings.jwks_cache_ttl_seconds
        now = time.monotonic()
        cache_is_fresh = (now - self._jwks_fetched_at) < ttl

        # If force_refresh is requested, check the minimum interval guard
        if force_refresh:
            since_last_forced = now - self._jwks_forced_refresh_at
            if since_last_forced < self._jwks_min_forced_refresh_interval:
                # Not enough time has passed; skip the forced fetch and return
                # from the current cache (even if stale)
                return self._jwks_cache.get(kid)  # type: ignore[arg-type]

        if not force_refresh and cache_is_fresh and self._jwks_cache:
            return self._jwks_cache.get(kid)  # type: ignore[arg-type]

        # Fetch fresh keys (one coroutine at a time to avoid stampedes)
        async with self._jwks_lock:
            # Re-check after acquiring the lock — another coroutine may have
            # refreshed while we were waiting.
            now = time.monotonic()
            cache_is_fresh = (now - self._jwks_fetched_at) < ttl

            # Re-check the forced refresh interval inside the lock as well
            if force_refresh:
                since_last_forced = now - self._jwks_forced_refresh_at
                if since_last_forced < self._jwks_min_forced_refresh_interval:
                    return self._jwks_cache.get(kid)  # type: ignore[arg-type]

            if not force_refresh and cache_is_fresh and self._jwks_cache:
                return self._jwks_cache.get(kid)  # type: ignore[arg-type]

            cache_updated = await self._fetch_jwks()
            if force_refresh and cache_updated:
                self._jwks_forced_refresh_at = time.monotonic()

        return self._jwks_cache.get(kid)  # type: ignore[arg-type]

    async def _fetch_jwks(self) -> bool:
        """Fetch JWKS from Google and populate the in-memory cache.

        Logs at ERROR if the fetch fails; leaves the existing cache intact.
        HTTPS certificate verification is always enabled.

        Returns:
            True if the cache was successfully updated, False if the fetch failed
            or produced no usable keys.
        """
        try:
            async with httpx.AsyncClient(verify=True) as client:
                response = await client.get(_JWKS_URL, timeout=10.0)
                response.raise_for_status()
                jwks = response.json()
        except httpx.RequestError as exc:
            logger.error("jwt_auth: JWKS fetch failed (network error): %s", exc)
            return False
        except httpx.HTTPStatusError as exc:
            logger.error(
                "jwt_auth: JWKS fetch returned HTTP %s: %s",
                exc.response.status_code,
                exc,
            )
            return False
        except Exception as exc:  # noqa: BLE001
            logger.error("jwt_auth: JWKS fetch failed unexpectedly: %s", exc)
            return False

        new_cache: dict[str, RSAPublicKey] = {}
        for jwk in jwks.get("keys", []):
            kid = jwk.get("kid")
            if not kid:
                continue
            try:
                public_key = RSAAlgorithm.from_jwk(jwk)
                new_cache[kid] = public_key  # type: ignore[assignment]
            except Exception as exc:  # noqa: BLE001
                logger.warning("jwt_auth: skipping malformed JWK (kid=%r): %s", kid, exc)

        if not new_cache:
            logger.warning("jwt_auth: JWKS response contained 0 usable keys — keeping existing cache")
            return False
        self._jwks_cache = new_cache
        self._jwks_fetched_at = time.monotonic()
        logger.debug("jwt_auth: JWKS cache refreshed (%d keys)", len(new_cache))
        return True
