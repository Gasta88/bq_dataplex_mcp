"""Unit tests for app.jwt_auth.JWTAuthProvider.

Covers valid/expired tokens, audience and `hd` checks, signature and kid
failures, JWKS caching and refresh, network failure, the service-account
whitelist, and the stable log codes emitted on each rejection path.
"""

import base64
import time
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import jwt as pyjwt
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from app.config import Settings
from app.jwt_auth import (
    JWTAuthProvider,
    WORKSPACE_IDENTITY_REQUIRED,
    TOKEN_EXPIRED,
    CI_SERVICE_ACCOUNT_IDENTITY_ACCEPTED,
)


# ---------------------------------------------------------------------------
# anyio backend restriction (mirrors tests/test_main.py's own fixture)
# ---------------------------------------------------------------------------


@pytest.fixture
def anyio_backend():
    return "asyncio"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _generate_rsa_key() -> RSAPrivateKey:
    return rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )


def _int_to_base64url(n: int) -> str:
    """Encode a big integer as base64url (no padding) — needed to build JWK."""
    nb = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(nb).rstrip(b"=").decode()


def _public_key_to_jwk(key: RSAPrivateKey, kid: str) -> dict:
    """Return a minimal RSA JWK dict for the given private key."""
    pub = key.public_key()
    nums = pub.public_numbers()
    return {
        "kty": "RSA",
        "kid": kid,
        "alg": "RS256",
        "use": "sig",
        "n": _int_to_base64url(nums.n),
        "e": _int_to_base64url(nums.e),
    }


def _make_settings(
    client_id: str = "test-client-id.apps.googleusercontent.com",
    workspace_domain: str = "example.com",
    jwks_ttl: int = 3600,
    service_account_email: str | None = None,
) -> Settings:
    s = Settings()
    s.google_oauth_client_id = client_id
    s.google_workspace_domain = workspace_domain
    s.jwks_cache_ttl_seconds = jwks_ttl
    if service_account_email is not None:
        s.google_oauth_service_account_email = service_account_email
    return s


def _make_token(
    private_key: RSAPrivateKey,
    kid: str,
    *,
    audience: str = "test-client-id.apps.googleusercontent.com",
    hd: str | None = "example.com",
    exp_offset: int = 3600,  # seconds from now; negative = expired
    extra_claims: dict | None = None,
) -> str:
    """Build and sign an RS256 JWT using the given private key."""
    now = int(time.time())
    payload: dict = {
        "iss": "https://accounts.google.com",
        "sub": "12345678901234567890",
        "aud": audience,
        "iat": now,
        "exp": now + exp_offset,
        "email": "user@example.com",
    }
    if hd is not None:
        payload["hd"] = hd
    if extra_claims:
        payload.update(extra_claims)
    return pyjwt.encode(
        payload,
        private_key,  # type: ignore[arg-type]
        algorithm="RS256",
        headers={"kid": kid},
    )


def _build_jwks_response(*pairs: tuple[RSAPrivateKey, str]) -> dict:
    """Build a JWKS dict from (private_key, kid) pairs."""
    return {"keys": [_public_key_to_jwk(priv, kid) for priv, kid in pairs]}


async def _make_provider_with_jwks(
    jwks: dict,
    settings: Settings | None = None,
) -> JWTAuthProvider:
    """Construct a JWTAuthProvider whose JWKS cache is pre-populated.

    The provider's _fetch_jwks is replaced with a no-HTTP stub that re-populates
    from the same JWKS dict, so any force-refresh triggered inside verify_token
    (e.g. on InvalidSignatureError) never makes real outbound requests.
    """
    from jwt.algorithms import RSAAlgorithm

    s = settings or _make_settings()
    provider = JWTAuthProvider(s)

    def _populate() -> None:
        new_cache: dict = {}
        for jwk_entry in jwks.get("keys", []):
            kid = jwk_entry.get("kid")
            if not kid:
                continue
            try:
                new_cache[kid] = RSAAlgorithm.from_jwk(jwk_entry)
            except Exception:
                pass
        if new_cache:
            provider._jwks_cache = new_cache
            provider._jwks_fetched_at = time.monotonic()

    _populate()

    async def _stub_fetch_jwks() -> bool:
        _populate()
        return True

    provider._fetch_jwks = _stub_fetch_jwks  # type: ignore[method-assign]
    return provider


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestJWTAuthProviderConstruction:
    def test_raises_when_client_id_empty(self):
        s = _make_settings(client_id="")
        with pytest.raises(ValueError, match="google_oauth_client_id is empty"):
            JWTAuthProvider(s)

    def test_missing_client_id_config_raises_on_construction(self):
        """Alias for the explicit test name."""
        s = Settings()
        s.google_oauth_client_id = ""
        with pytest.raises(ValueError):
            JWTAuthProvider(s)

    def test_construction_succeeds_with_valid_client_id(self):
        s = _make_settings()
        provider = JWTAuthProvider(s)
        assert provider is not None


class TestVerifyTokenValid:
    @pytest.mark.anyio
    async def test_verify_token_valid_returns_access_token(self):
        priv = _generate_rsa_key()
        kid = "kid-1"
        s = _make_settings()
        token = _make_token(priv, kid, audience=s.google_oauth_client_id, hd=s.google_workspace_domain)
        jwks = _build_jwks_response((priv, kid))
        provider = await _make_provider_with_jwks(jwks, s)

        result = await provider.verify_token(token)

        assert result is not None
        assert result.client_id == "12345678901234567890"  # sub claim
        assert result.scopes == []

    @pytest.mark.anyio
    async def test_verify_token_valid_sets_subject(self):
        priv = _generate_rsa_key()
        kid = "kid-1"
        s = _make_settings()
        token = _make_token(priv, kid, audience=s.google_oauth_client_id, hd=s.google_workspace_domain)
        jwks = _build_jwks_response((priv, kid))
        provider = await _make_provider_with_jwks(jwks, s)

        result = await provider.verify_token(token)

        assert result is not None
        assert result.subject == "12345678901234567890"


class TestVerifyTokenExpired:
    @pytest.mark.anyio
    async def test_verify_token_expired_returns_none(self, caplog):
        import logging

        priv = _generate_rsa_key()
        kid = "kid-exp"
        s = _make_settings()
        # Expired 1 hour ago
        token = _make_token(
            priv, kid, audience=s.google_oauth_client_id, hd=s.google_workspace_domain, exp_offset=-3600
        )
        jwks = _build_jwks_response((priv, kid))
        provider = await _make_provider_with_jwks(jwks, s)

        with caplog.at_level(logging.WARNING, logger="app.jwt_auth"):
            result = await provider.verify_token(token)

        assert result is None
        assert any(
            TOKEN_EXPIRED in r.message for r in caplog.records
        ), f"Expected '{TOKEN_EXPIRED}' in log records; got: {[r.message for r in caplog.records]}"


class TestVerifyTokenWrongAudience:
    @pytest.mark.anyio
    async def test_verify_token_wrong_audience_returns_none(self):
        priv = _generate_rsa_key()
        kid = "kid-aud"
        s = _make_settings()
        token = _make_token(
            priv, kid, audience="wrong-client-id.apps.googleusercontent.com", hd=s.google_workspace_domain
        )
        jwks = _build_jwks_response((priv, kid))
        provider = await _make_provider_with_jwks(jwks, s)

        result = await provider.verify_token(token)

        assert result is None


class TestVerifyTokenHdClaim:
    @pytest.mark.anyio
    async def test_verify_token_wrong_hd_returns_none(self, caplog):
        import logging

        priv = _generate_rsa_key()
        kid = "kid-hd"
        s = _make_settings()
        token = _make_token(priv, kid, audience=s.google_oauth_client_id, hd="gmail.com")
        jwks = _build_jwks_response((priv, kid))
        provider = await _make_provider_with_jwks(jwks, s)

        with caplog.at_level(logging.WARNING, logger="app.jwt_auth"):
            result = await provider.verify_token(token)

        assert result is None
        assert any(
            WORKSPACE_IDENTITY_REQUIRED in r.message for r in caplog.records
        ), f"Expected '{WORKSPACE_IDENTITY_REQUIRED}' in log records; got: {[r.message for r in caplog.records]}"

    @pytest.mark.anyio
    async def test_verify_token_missing_hd_returns_none(self, caplog):
        import logging

        priv = _generate_rsa_key()
        kid = "kid-nohd"
        s = _make_settings()
        token = _make_token(priv, kid, audience=s.google_oauth_client_id, hd=None)
        jwks = _build_jwks_response((priv, kid))
        provider = await _make_provider_with_jwks(jwks, s)

        with caplog.at_level(logging.WARNING, logger="app.jwt_auth"):
            result = await provider.verify_token(token)

        assert result is None
        assert any(
            WORKSPACE_IDENTITY_REQUIRED in r.message for r in caplog.records
        ), f"Expected '{WORKSPACE_IDENTITY_REQUIRED}' in log records; got: {[r.message for r in caplog.records]}"


class TestVerifyTokenInvalidSignature:
    @pytest.mark.anyio
    async def test_verify_token_invalid_signature_returns_none(self):
        signing_key = _generate_rsa_key()  # key used to SIGN the token
        wrong_key = _generate_rsa_key()  # different key placed in JWKS
        kid = "kid-sig"
        s = _make_settings()
        token = _make_token(signing_key, kid, audience=s.google_oauth_client_id, hd=s.google_workspace_domain)
        # JWKS has wrong_key, not signing_key → signature verification fails
        jwks = _build_jwks_response((wrong_key, kid))
        provider = await _make_provider_with_jwks(jwks, s)

        # Force TTL to be large so the cache-bypass retry won't fetch fresh keys;
        # instead we pre-populate again with the same wrong key so the retry also fails.
        result = await provider.verify_token(token)

        assert result is None


class TestVerifyTokenUnknownKid:
    @pytest.mark.anyio
    async def test_verify_token_unknown_kid_returns_none(self):
        priv = _generate_rsa_key()
        kid_in_token = "kid-unknown"
        kid_in_jwks = "kid-different"
        s = _make_settings()
        token = _make_token(priv, kid_in_token, audience=s.google_oauth_client_id, hd=s.google_workspace_domain)
        # JWKS only contains a different kid
        jwks = _build_jwks_response((priv, kid_in_jwks))
        provider = await _make_provider_with_jwks(jwks, s)

        result = await provider.verify_token(token)

        assert result is None


class TestJWKSFetchFailure:
    @pytest.mark.anyio
    async def test_verify_token_jwks_fetch_failure_returns_none(self, caplog):
        import logging

        s = _make_settings()
        provider = JWTAuthProvider(s)

        priv = _generate_rsa_key()
        kid = "kid-net"
        token = _make_token(priv, kid, audience=s.google_oauth_client_id, hd=s.google_workspace_domain)

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=httpx.ConnectError("connection refused"))
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            with caplog.at_level(logging.ERROR, logger="app.jwt_auth"):
                result = await provider.verify_token(token)

        assert result is None
        assert any("JWKS fetch failed" in r.message for r in caplog.records)


class TestJWKSCacheBehaviour:
    @pytest.mark.anyio
    async def test_jwks_cache_hit_no_second_fetch(self):
        """Two verify_token calls within TTL must only trigger one JWKS fetch."""
        priv = _generate_rsa_key()
        kid = "kid-cache"
        s = _make_settings(jwks_ttl=3600)
        token = _make_token(priv, kid, audience=s.google_oauth_client_id, hd=s.google_workspace_domain)

        provider = JWTAuthProvider(s)
        fetch_count = 0

        async def fake_fetch_jwks() -> bool:
            nonlocal fetch_count
            fetch_count += 1
            # Directly populate the cache as the real method would
            from jwt.algorithms import RSAAlgorithm

            jwk = _public_key_to_jwk(priv, kid)
            public_key = RSAAlgorithm.from_jwk(jwk)
            provider._jwks_cache = {kid: public_key}
            provider._jwks_fetched_at = time.monotonic()
            return True

        provider._fetch_jwks = fake_fetch_jwks  # type: ignore[method-assign]

        await provider.verify_token(token)
        await provider.verify_token(token)

        assert fetch_count == 1, f"Expected 1 JWKS fetch, got {fetch_count}"

    @pytest.mark.anyio
    async def test_jwks_cache_miss_after_ttl_triggers_refetch(self):
        """After TTL expires a second verify_token call must trigger a second JWKS fetch."""
        priv = _generate_rsa_key()
        kid = "kid-ttl"
        s = _make_settings(jwks_ttl=1)  # 1-second TTL
        token = _make_token(priv, kid, audience=s.google_oauth_client_id, hd=s.google_workspace_domain)

        provider = JWTAuthProvider(s)
        fetch_count = 0

        async def fake_fetch_jwks() -> bool:
            nonlocal fetch_count
            fetch_count += 1
            from jwt.algorithms import RSAAlgorithm

            jwk = _public_key_to_jwk(priv, kid)
            public_key = RSAAlgorithm.from_jwk(jwk)
            provider._jwks_cache = {kid: public_key}
            provider._jwks_fetched_at = time.monotonic()
            return True

        provider._fetch_jwks = fake_fetch_jwks  # type: ignore[method-assign]

        await provider.verify_token(token)
        assert fetch_count == 1

        # Simulate TTL expiry by backdating the fetch timestamp
        provider._jwks_fetched_at -= 2.0  # 2 seconds ago > 1-second TTL

        await provider.verify_token(token)
        assert fetch_count == 2, f"Expected 2 JWKS fetches after TTL, got {fetch_count}"


class TestCacheBypassOnSignatureError:
    @pytest.mark.anyio
    async def test_invalid_signature_triggers_cache_bypass_and_retry(self):
        """Stale JWKS (wrong key) → signature error → force-refresh → correct key → success."""
        correct_key = _generate_rsa_key()
        stale_key = _generate_rsa_key()
        kid = "kid-rotate"
        s = _make_settings()
        token = _make_token(correct_key, kid, audience=s.google_oauth_client_id, hd=s.google_workspace_domain)

        provider = JWTAuthProvider(s)
        fetch_count = 0

        async def fake_fetch_jwks() -> bool:
            nonlocal fetch_count
            fetch_count += 1
            from jwt.algorithms import RSAAlgorithm

            if fetch_count == 1:
                # First fetch: return stale (wrong) key → will cause signature failure
                jwk = _public_key_to_jwk(stale_key, kid)
            else:
                # Second fetch (force-refresh): return the correct key
                jwk = _public_key_to_jwk(correct_key, kid)
            public_key = RSAAlgorithm.from_jwk(jwk)
            provider._jwks_cache = {kid: public_key}
            provider._jwks_fetched_at = time.monotonic()
            return True

        provider._fetch_jwks = fake_fetch_jwks  # type: ignore[method-assign]

        result = await provider.verify_token(token)

        assert result is not None, "Expected AccessToken after JWKS force-refresh"
        assert fetch_count == 2, f"Expected 2 JWKS fetches (initial + retry), got {fetch_count}"


class TestLargeToken:
    @pytest.mark.anyio
    async def test_large_token_logs_warning(self, caplog):
        """A token exceeding 8 KB should log a WARNING (but still attempt decode)."""
        import logging

        priv = _generate_rsa_key()
        kid = "kid-large"
        s = _make_settings()
        # Build token with massive extra claims to exceed 8 KB
        extra = {"padding": "x" * 9000}
        token = _make_token(
            priv, kid, audience=s.google_oauth_client_id, hd=s.google_workspace_domain, extra_claims=extra
        )
        jwks = _build_jwks_response((priv, kid))
        provider = await _make_provider_with_jwks(jwks, s)

        with caplog.at_level(logging.WARNING, logger="app.jwt_auth"):
            await provider.verify_token(token)

        assert any("exceeds" in r.message for r in caplog.records)


class TestWorkspaceIdentityErrorCode:
    def test_constant_value_is_stable(self):
        """WORKSPACE_IDENTITY_REQUIRED must equal 'workspace_identity_required'.

        Prevents accidental rename that would break Cloud Logging alert filters.
        """
        assert WORKSPACE_IDENTITY_REQUIRED == "workspace_identity_required"

    @pytest.mark.anyio
    async def test_other_rejection_paths_do_not_log_workspace_code(self, caplog):
        """Wrong-audience rejection must NOT emit the workspace_identity_required code."""
        import logging

        priv = _generate_rsa_key()
        kid = "kid-aud-excl"
        s = _make_settings()
        token = _make_token(
            priv,
            kid,
            audience="wrong-client-id.apps.googleusercontent.com",
            hd=s.google_workspace_domain,
        )
        jwks = _build_jwks_response((priv, kid))
        provider = await _make_provider_with_jwks(jwks, s)

        with caplog.at_level(logging.WARNING, logger="app.jwt_auth"):
            result = await provider.verify_token(token)

        assert result is None
        assert not any(
            WORKSPACE_IDENTITY_REQUIRED in r.message for r in caplog.records
        ), f"Expected '{WORKSPACE_IDENTITY_REQUIRED}' to be absent from non-hd rejection log; got: {[r.message for r in caplog.records]}"


class TestVerifyTokenGivesUpAfterFailedForceRefresh:
    @pytest.mark.anyio
    async def test_signature_error_with_no_new_key_after_refresh_returns_none(self):
        """Covers the 'give up' branch: a forced refresh that returns the same
        (still-wrong) key, or no key at all, must not retry forever.
        """
        signing_key = _generate_rsa_key()
        wrong_key = _generate_rsa_key()
        kid = "kid-giveup"
        s = _make_settings()
        token = _make_token(signing_key, kid, audience=s.google_oauth_client_id, hd=s.google_workspace_domain)
        # Every fetch (including the forced retry) returns the same wrong key.
        jwks = _build_jwks_response((wrong_key, kid))
        provider = await _make_provider_with_jwks(jwks, s)

        result = await provider.verify_token(token)

        assert result is None


class TestExtractKidDecodeError:
    def test_malformed_token_with_too_few_segments_returns_none_kid(self):
        s = _make_settings()
        provider = JWTAuthProvider(s)

        # A 2-segment token (missing the signature segment entirely) fails
        # even unverified-header parsing, exercising _extract_kid's own
        # DecodeError-swallowing branch.
        assert provider._extract_kid("aGVhZGVy.cGF5bG9hZA") is None


class TestDecodeTokenGenericErrorBranches:
    @pytest.mark.anyio
    async def test_malformed_signature_segment_is_a_decode_error_not_invalid_signature(self):
        """A syntactically-malformed (non-base64) signature segment raises
        DecodeError, not InvalidSignatureError -- a different branch in
        _decode_token than TestVerifyTokenInvalidSignature above, which uses a
        syntactically-valid signature that simply doesn't verify.
        """
        import base64
        import json

        priv = _generate_rsa_key()
        kid = "kid-decode-error"
        s = _make_settings()
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "RS256", "kid": kid}).encode()
        ).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(
            json.dumps({"aud": s.google_oauth_client_id, "exp": 9999999999, "sub": "s"}).encode()
        ).rstrip(b"=").decode()
        token = f"{header}.{payload}.!!!not-valid-base64!!!"

        jwks = _build_jwks_response((priv, kid))
        provider = await _make_provider_with_jwks(jwks, s)

        result = await provider.verify_token(token)

        assert result is None

    @pytest.mark.anyio
    async def test_immature_signature_error_falls_into_generic_pyjwt_error_branch(self):
        """An `nbf` claim in the future raises ImmatureSignatureError, a
        PyJWTError subtype not covered by the specific except clauses above
        it in _decode_token -- exercises the final catch-all branch.
        """
        priv = _generate_rsa_key()
        kid = "kid-nbf"
        s = _make_settings()
        now = int(time.time())
        token = _make_token(
            priv,
            kid,
            audience=s.google_oauth_client_id,
            hd=s.google_workspace_domain,
            extra_claims={"nbf": now + 1000},
        )
        jwks = _build_jwks_response((priv, kid))
        provider = await _make_provider_with_jwks(jwks, s)

        result = await provider.verify_token(token)

        assert result is None


class TestFetchJwksRealImplementation:
    """Exercises `_fetch_jwks`'s own real body (not the test-suite-wide stub
    every other test class installs) -- the success path, malformed-JWK
    skip, empty-response handling, HTTP status errors, and unexpected
    exceptions, via a mocked `httpx.AsyncClient`.
    """

    @staticmethod
    def _mock_async_client(mock_get):
        from unittest.mock import AsyncMock

        mock_client = AsyncMock()
        mock_client.get = mock_get
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        return mock_client

    @pytest.mark.anyio
    async def test_success_populates_cache_from_real_fetch_jwks(self):
        from unittest.mock import AsyncMock

        priv = _generate_rsa_key()
        kid = "kid-real-fetch"
        jwks = _build_jwks_response((priv, kid))

        response = MagicMock()
        response.raise_for_status = MagicMock()
        response.json.return_value = jwks
        mock_get = AsyncMock(return_value=response)

        s = _make_settings()
        provider = JWTAuthProvider(s)
        with patch("httpx.AsyncClient", return_value=self._mock_async_client(mock_get)):
            await provider._fetch_jwks()

        assert kid in provider._jwks_cache
        assert provider._jwks_fetched_at > 0

    @pytest.mark.anyio
    async def test_malformed_jwk_entry_is_skipped_with_warning(self, caplog):
        import logging
        from unittest.mock import AsyncMock

        priv = _generate_rsa_key()
        good_kid = "kid-good"
        good_jwks = _build_jwks_response((priv, good_kid))
        # A JWK entry that will fail RSAAlgorithm.from_jwk (missing n/e).
        good_jwks["keys"].append({"kty": "RSA", "kid": "kid-bad", "alg": "RS256", "use": "sig"})

        response = MagicMock()
        response.raise_for_status = MagicMock()
        response.json.return_value = good_jwks
        mock_get = AsyncMock(return_value=response)

        s = _make_settings()
        provider = JWTAuthProvider(s)
        with caplog.at_level(logging.WARNING, logger="app.jwt_auth"):
            with patch("httpx.AsyncClient", return_value=self._mock_async_client(mock_get)):
                await provider._fetch_jwks()

        assert good_kid in provider._jwks_cache
        assert "kid-bad" not in provider._jwks_cache
        assert any("skipping malformed JWK" in r.message for r in caplog.records)

    @pytest.mark.anyio
    async def test_zero_usable_keys_keeps_existing_cache(self, caplog):
        import logging
        from unittest.mock import AsyncMock

        from jwt.algorithms import RSAAlgorithm

        priv = _generate_rsa_key()
        kid = "kid-existing"

        s = _make_settings()
        provider = JWTAuthProvider(s)
        # Pre-populate directly (NOT via _make_provider_with_jwks, which
        # overrides provider._fetch_jwks with a stub -- this test needs the
        # real, unpatched _fetch_jwks bound method).
        existing_cache = {kid: RSAAlgorithm.from_jwk(_public_key_to_jwk(priv, kid))}
        provider._jwks_cache = existing_cache
        provider._jwks_fetched_at = time.monotonic()

        response = MagicMock()
        response.raise_for_status = MagicMock()
        response.json.return_value = {"keys": []}
        mock_get = AsyncMock(return_value=response)

        with caplog.at_level(logging.WARNING, logger="app.jwt_auth"):
            with patch("httpx.AsyncClient", return_value=self._mock_async_client(mock_get)):
                await provider._fetch_jwks()

        assert provider._jwks_cache is existing_cache
        assert any("0 usable keys" in r.message for r in caplog.records)

    @pytest.mark.anyio
    async def test_http_status_error_logs_and_returns(self, caplog):
        import logging
        from unittest.mock import AsyncMock

        import httpx as httpx_module

        response = MagicMock()
        error = httpx_module.HTTPStatusError(
            "server error", request=MagicMock(), response=MagicMock(status_code=500)
        )
        response.raise_for_status = MagicMock(side_effect=error)
        mock_get = AsyncMock(return_value=response)

        s = _make_settings()
        provider = JWTAuthProvider(s)
        with caplog.at_level(logging.ERROR, logger="app.jwt_auth"):
            with patch("httpx.AsyncClient", return_value=self._mock_async_client(mock_get)):
                await provider._fetch_jwks()

        assert provider._jwks_cache == {}
        assert any("JWKS fetch returned HTTP" in r.message for r in caplog.records)

    @pytest.mark.anyio
    async def test_unexpected_exception_logs_and_returns(self, caplog):
        import logging
        from unittest.mock import AsyncMock

        mock_get = AsyncMock(side_effect=RuntimeError("boom"))

        s = _make_settings()
        provider = JWTAuthProvider(s)
        with caplog.at_level(logging.ERROR, logger="app.jwt_auth"):
            with patch("httpx.AsyncClient", return_value=self._mock_async_client(mock_get)):
                await provider._fetch_jwks()

        assert provider._jwks_cache == {}
        assert any("JWKS fetch failed unexpectedly" in r.message for r in caplog.records)


class TestGetPublicKeyDoubleCheckedLockingReturnsFreshCacheAfterLockWait:
    @pytest.mark.anyio
    async def test_concurrent_calls_only_fetch_once(self):
        """Two concurrent _get_public_key calls for the same stale cache must
        only trigger one real fetch -- the second call's post-lock-acquire
        freshness re-check (line coverage for the "someone else already
        refreshed while we waited" branch) must short-circuit without
        fetching again.
        """
        import asyncio

        priv = _generate_rsa_key()
        kid = "kid-concurrent"
        s = _make_settings()
        provider = JWTAuthProvider(s)
        fetch_count = 0

        async def fake_fetch_jwks() -> bool:
            nonlocal fetch_count
            fetch_count += 1
            await asyncio.sleep(0.05)
            from jwt.algorithms import RSAAlgorithm

            jwk = _public_key_to_jwk(priv, kid)
            provider._jwks_cache = {kid: RSAAlgorithm.from_jwk(jwk)}
            provider._jwks_fetched_at = time.monotonic()
            return True

        provider._fetch_jwks = fake_fetch_jwks  # type: ignore[method-assign]

        results = await asyncio.gather(
            provider._get_public_key(kid),
            provider._get_public_key(kid),
        )

        assert all(r is not None for r in results)
        assert fetch_count == 1


class TestTokenExpiredErrorCode:
    def test_constant_value_is_stable(self):
        """TOKEN_EXPIRED must equal 'token_expired'.

        Prevents accidental rename that would break Cloud Logging alert filters.
        """
        assert TOKEN_EXPIRED == "token_expired"

    @pytest.mark.anyio
    async def test_other_rejection_paths_do_not_log_expired_code(self, caplog):
        """Wrong-audience rejection (not expired) must NOT emit the token_expired code."""
        import logging

        priv = _generate_rsa_key()
        kid = "kid-aud-notexp"
        s = _make_settings()
        token = _make_token(
            priv,
            kid,
            audience="wrong-client-id.apps.googleusercontent.com",
            hd=s.google_workspace_domain,
        )
        jwks = _build_jwks_response((priv, kid))
        provider = await _make_provider_with_jwks(jwks, s)

        with caplog.at_level(logging.WARNING, logger="app.jwt_auth"):
            result = await provider.verify_token(token)

        assert result is None
        assert not any(
            TOKEN_EXPIRED in r.message for r in caplog.records
        ), f"Expected '{TOKEN_EXPIRED}' to be absent from non-expired rejection log; got: {[r.message for r in caplog.records]}"


class TestCIServiceAccountWhitelist:
    """ (2026-09-25 rework): JWTAuthProvider accepts a token whose
    `email` claim matches an optional, non-empty configured whitelist
    (`google_oauth_service_account_email`) AND whose `email_verified` claim
    is strictly `True`, skipping the `hd` check for that one identity only.
    `aud` remains the single, unchanged primary audience — the whitelist
    never substitutes for or widens the `aud` check. Field name, env var, and
    the `email_verified is True` guard deliberately match
    service-account whitelist exactly
    (see app/jwt_auth.py's Design Decision docstring section).
    """

    CI_EMAIL = "ci-eval@example-project.iam.gserviceaccount.com"

    @pytest.mark.anyio
    async def test_verify_token_accepts_whitelisted_email_with_missing_hd(self):
        priv = _generate_rsa_key()
        kid = "kid-ci-nohd"
        s = _make_settings(service_account_email=self.CI_EMAIL)
        token = _make_token(
            priv,
            kid,
            audience=s.google_oauth_client_id,
            hd=None,
            extra_claims={"email": self.CI_EMAIL, "email_verified": True},
        )
        jwks = _build_jwks_response((priv, kid))
        provider = await _make_provider_with_jwks(jwks, s)

        result = await provider.verify_token(token)

        assert result is not None

    @pytest.mark.anyio
    async def test_verify_token_accepts_whitelisted_email_with_mismatched_hd(self):
        """Covers both 'missing' and 'wrong' hd -- not just the missing case."""
        priv = _generate_rsa_key()
        kid = "kid-ci-wronghd"
        s = _make_settings(service_account_email=self.CI_EMAIL)
        token = _make_token(
            priv,
            kid,
            audience=s.google_oauth_client_id,
            hd="some-other-domain.com",
            extra_claims={"email": self.CI_EMAIL, "email_verified": True},
        )
        jwks = _build_jwks_response((priv, kid))
        provider = await _make_provider_with_jwks(jwks, s)

        result = await provider.verify_token(token)

        assert result is not None

    @pytest.mark.anyio
    async def test_verify_token_rejects_non_whitelisted_email_with_missing_hd(self, caplog):
        import logging

        priv = _generate_rsa_key()
        kid = "kid-ci-unrelated"
        s = _make_settings(service_account_email=self.CI_EMAIL)
        token = _make_token(
            priv,
            kid,
            audience=s.google_oauth_client_id,
            hd=None,
            extra_claims={"email": "someone-else@example.com", "email_verified": True},
        )
        jwks = _build_jwks_response((priv, kid))
        provider = await _make_provider_with_jwks(jwks, s)

        with caplog.at_level(logging.WARNING, logger="app.jwt_auth"):
            result = await provider.verify_token(token)

        assert result is None
        assert any(
            WORKSPACE_IDENTITY_REQUIRED in r.message for r in caplog.records
        ), f"Expected '{WORKSPACE_IDENTITY_REQUIRED}' in log records; got: {[r.message for r in caplog.records]}"

    @pytest.mark.anyio
    async def test_rejected_when_email_matches_but_email_verified_false(self, caplog):
        """Anti-spoofing guard: matching email with email_verified=False must
        still hit the hd check.
        """
        import logging

        priv = _generate_rsa_key()
        kid = "kid-ci-unverified"
        s = _make_settings(service_account_email=self.CI_EMAIL)
        token = _make_token(
            priv,
            kid,
            audience=s.google_oauth_client_id,
            hd=None,
            extra_claims={"email": self.CI_EMAIL, "email_verified": False},
        )
        jwks = _build_jwks_response((priv, kid))
        provider = await _make_provider_with_jwks(jwks, s)

        with caplog.at_level(logging.WARNING, logger="app.jwt_auth"):
            result = await provider.verify_token(token)

        assert result is None
        assert any(
            WORKSPACE_IDENTITY_REQUIRED in r.message for r in caplog.records
        ), f"Expected '{WORKSPACE_IDENTITY_REQUIRED}' in log records; got: {[r.message for r in caplog.records]}"

    @pytest.mark.anyio
    async def test_rejected_when_email_matches_but_email_verified_absent(self, caplog):
        """Same guard, different absence shape: no email_verified key at all."""
        import logging

        priv = _generate_rsa_key()
        kid = "kid-ci-noverified-key"
        s = _make_settings(service_account_email=self.CI_EMAIL)
        token = _make_token(
            priv,
            kid,
            audience=s.google_oauth_client_id,
            hd=None,
            extra_claims={"email": self.CI_EMAIL},
        )
        jwks = _build_jwks_response((priv, kid))
        provider = await _make_provider_with_jwks(jwks, s)

        with caplog.at_level(logging.WARNING, logger="app.jwt_auth"):
            result = await provider.verify_token(token)

        assert result is None
        assert any(
            WORKSPACE_IDENTITY_REQUIRED in r.message for r in caplog.records
        ), f"Expected '{WORKSPACE_IDENTITY_REQUIRED}' in log records; got: {[r.message for r in caplog.records]}"

    @pytest.mark.anyio
    async def test_whitelist_unset_preserves_hd_required_behavior(self):
        """Regression: with the new field left at its default ("" / unset),
        a token with no `hd` is still rejected regardless of its `email`
        claim — proves FR8's backward-compatibility claim directly.
        """
        priv = _generate_rsa_key()
        kid = "kid-ci-unset"
        s = _make_settings()  # service_account_email left None -> default ""
        assert s.google_oauth_service_account_email == ""
        token = _make_token(
            priv,
            kid,
            audience=s.google_oauth_client_id,
            hd=None,
            extra_claims={"email": self.CI_EMAIL, "email_verified": True},
        )
        jwks = _build_jwks_response((priv, kid))
        provider = await _make_provider_with_jwks(jwks, s)

        result = await provider.verify_token(token)

        assert result is None

    @pytest.mark.anyio
    async def test_empty_string_whitelist_is_not_treated_as_matching_empty_email(self):
        """An explicitly empty-string whitelist must never itself be treated
        as matching a token whose `email` claim also happens to be empty.
        """
        priv = _generate_rsa_key()
        kid = "kid-ci-empty"
        s = _make_settings(service_account_email="")
        assert s.google_oauth_service_account_email == ""
        token = _make_token(
            priv,
            kid,
            audience=s.google_oauth_client_id,
            hd=None,
            extra_claims={"email": "", "email_verified": True},
        )
        jwks = _build_jwks_response((priv, kid))
        provider = await _make_provider_with_jwks(jwks, s)

        result = await provider.verify_token(token)

        assert result is None

    @pytest.mark.anyio
    async def test_normal_human_token_with_valid_hd_unaffected_by_whitelist_configured(self):
        priv = _generate_rsa_key()
        kid = "kid-ci-human"
        s = _make_settings(service_account_email=self.CI_EMAIL)
        token = _make_token(
            priv, kid, audience=s.google_oauth_client_id, hd=s.google_workspace_domain
        )
        jwks = _build_jwks_response((priv, kid))
        provider = await _make_provider_with_jwks(jwks, s)

        result = await provider.verify_token(token)

        assert result is not None

    @pytest.mark.anyio
    async def test_bypass_never_substitutes_for_audience_check(self, caplog):
        """FR5: a token whose `aud` doesn't match the primary audience is
        still rejected on `aud`, even if its `email`/`email_verified` match
        the whitelist.
        """
        import logging

        priv = _generate_rsa_key()
        kid = "kid-ci-wrongaud"
        s = _make_settings(service_account_email=self.CI_EMAIL)
        token = _make_token(
            priv,
            kid,
            audience="wrong-client-id.apps.googleusercontent.com",
            hd=None,
            extra_claims={"email": self.CI_EMAIL, "email_verified": True},
        )
        jwks = _build_jwks_response((priv, kid))
        provider = await _make_provider_with_jwks(jwks, s)

        with caplog.at_level(logging.WARNING, logger="app.jwt_auth"):
            result = await provider.verify_token(token)

        assert result is None
        assert any(
            "audience mismatch" in r.message for r in caplog.records
        ), f"Expected an audience-mismatch WARNING; got: {[r.message for r in caplog.records]}"

    @pytest.mark.anyio
    async def test_bypass_acceptance_logs_ci_service_account_identity_accepted(self, caplog):
        import logging

        priv = _generate_rsa_key()
        kid = "kid-ci-logline"
        s = _make_settings(service_account_email=self.CI_EMAIL)
        token = _make_token(
            priv,
            kid,
            audience=s.google_oauth_client_id,
            hd=None,
            extra_claims={"email": self.CI_EMAIL, "email_verified": True},
        )
        jwks = _build_jwks_response((priv, kid))
        provider = await _make_provider_with_jwks(jwks, s)

        with caplog.at_level(logging.INFO, logger="app.jwt_auth"):
            result = await provider.verify_token(token)

        assert result is not None
        assert any(
            CI_SERVICE_ACCOUNT_IDENTITY_ACCEPTED in r.message and self.CI_EMAIL in r.message
            for r in caplog.records
        ), (
            f"Expected '{CI_SERVICE_ACCOUNT_IDENTITY_ACCEPTED}' with matched email in log "
            f"records; got: {[r.message for r in caplog.records]}"
        )

    @pytest.mark.anyio
    async def test_expired_token_rejected_regardless_of_whitelist_match(self, caplog):
        """Spot-check: expiry short-circuits before the whitelist logic ever
        runs.
        """
        import logging

        priv = _generate_rsa_key()
        kid = "kid-ci-exp"
        s = _make_settings(service_account_email=self.CI_EMAIL)
        token = _make_token(
            priv,
            kid,
            audience=s.google_oauth_client_id,
            hd=None,
            exp_offset=-3600,
            extra_claims={"email": self.CI_EMAIL, "email_verified": True},
        )
        jwks = _build_jwks_response((priv, kid))
        provider = await _make_provider_with_jwks(jwks, s)

        with caplog.at_level(logging.WARNING, logger="app.jwt_auth"):
            result = await provider.verify_token(token)

        assert result is None
        assert any(TOKEN_EXPIRED in r.message for r in caplog.records)

    @pytest.mark.anyio
    async def test_invalid_signature_rejected_regardless_of_whitelist_match(self):
        """Spot-check: signature verification short-circuits before the
        whitelist logic ever runs.
        """
        signing_key = _generate_rsa_key()
        wrong_key = _generate_rsa_key()
        kid = "kid-ci-sig"
        s = _make_settings(service_account_email=self.CI_EMAIL)
        token = _make_token(
            signing_key,
            kid,
            audience=s.google_oauth_client_id,
            hd=None,
            extra_claims={"email": self.CI_EMAIL, "email_verified": True},
        )
        jwks = _build_jwks_response((wrong_key, kid))
        provider = await _make_provider_with_jwks(jwks, s)

        result = await provider.verify_token(token)

        assert result is None
