"""End-to-end integration tests for the MCP transport auth path.

Exercises the full stack:
  HTTP transport -> FastMCP RequireAuthMiddleware -> JWTAuthProvider.verify_token -> tool dispatch

Tokens are signed with a locally generated RSA key pair. The JWKS endpoint is
stubbed in-process so no outbound HTTP is made.

The auth-enabled instance is built with
`app.main.create_app(app_settings=Settings(google_oauth_client_id=...))`, so
the shared `app.main.mcp` singleton (auth-disabled by default) is never
mutated.
"""

import base64
import time
import uuid

import httpx
import jwt as pyjwt
import pytest
from fastmcp.utilities.tests import run_server_async

from app.config import Settings
from app.main import create_app

# ---------------------------------------------------------------------------
# Token/JWKS helpers (mirrors tests/test_jwt_auth.py's own private helpers)
# ---------------------------------------------------------------------------


def _generate_rsa_key():
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa

    return rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())


def _int_to_base64url(n: int) -> str:
    nb = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(nb).rstrip(b"=").decode()


def _public_key_to_jwk(key, kid: str) -> dict:
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
    service_account_email: str | None = None,
) -> Settings:
    s = Settings()
    s.google_oauth_client_id = client_id
    s.google_workspace_domain = workspace_domain
    if service_account_email is not None:
        s.google_oauth_service_account_email = service_account_email
    return s


def _make_token(
    private_key,
    kid: str,
    *,
    audience: str = "test-client-id.apps.googleusercontent.com",
    hd: str | None = "example.com",
    exp_offset: int = 3600,
    sub: str | None = None,
    extra_claims: dict | None = None,
) -> str:
    now = int(time.time())
    payload = {
        "iss": "https://accounts.google.com",
        "sub": sub or f"sub-{uuid.uuid4().hex}",
        "aud": audience,
        "iat": now,
        "exp": now + exp_offset,
        "email": "user@example.com",
    }
    if hd is not None:
        payload["hd"] = hd
    if extra_claims:
        payload.update(extra_claims)
    return pyjwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})


def _build_jwks_response(*pairs) -> dict:
    return {"keys": [_public_key_to_jwk(priv, kid) for priv, kid in pairs]}


def _stub_fetch_jwks_on_provider(provider, jwks: dict) -> None:
    """Patch provider._fetch_jwks in-place (instance attribute) so JWKS
    lookups never make real outbound requests. Populates the cache
    immediately so the first verify_token call is also covered.
    """
    from jwt.algorithms import RSAAlgorithm

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

    async def _stub_fetch_jwks() -> None:
        _populate()

    provider._fetch_jwks = _stub_fetch_jwks  # type: ignore[method-assign]


# ---------------------------------------------------------------------------
# MCP initialize request body (static -- only status code is asserted)
# ---------------------------------------------------------------------------

_MCP_INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "test-client", "version": "0.0.1"},
    },
}

# FastMCP streamable-http transport requires both media types in the Accept header.
_MCP_ACCEPT = "application/json, text/event-stream"


# ---------------------------------------------------------------------------
# Per-test live server: a fresh, independent, auth-enabled `create_app(...)`
# instance -- never the shared `app.main.mcp` singleton (see module docstring).
# ---------------------------------------------------------------------------


@pytest.fixture
async def auth_enabled_server():
    """Build a fresh auth-enabled FastMCP instance and start a real in-process
    HTTP server for it. Yields (server_url, jwt_auth_provider) so tests can
    both make requests and stub JWKS fetching on that exact instance's
    JWTAuthProvider object.
    """
    settings = _make_settings()
    app = create_app(app_settings=settings)
    provider = app.auth
    assert provider is not None, "create_app(app_settings=...) should build an enabled JWTAuthProvider"
    async with run_server_async(app, transport="streamable-http") as url:
        yield url, provider


# ---------------------------------------------------------------------------
# Positive path
# ---------------------------------------------------------------------------


class TestMCPAuthPositivePath:
    """A valid Workspace JWT (hd == example.com) must reach the tool layer."""

    @pytest.mark.anyio
    async def test_workspace_user_can_call_tool(self, auth_enabled_server):
        """POST /mcp initialize with a valid Workspace JWT -> HTTP 200."""
        server_url, provider = auth_enabled_server
        priv = _generate_rsa_key()
        kid = f"kid-pos-{uuid.uuid4().hex[:8]}"
        s = _make_settings()
        token = _make_token(priv, kid, audience=s.google_oauth_client_id, hd=s.google_workspace_domain)
        jwks = _build_jwks_response((priv, kid))

        _stub_fetch_jwks_on_provider(provider, jwks)
        async with httpx.AsyncClient() as client:
            response = await client.post(
                server_url,
                json=_MCP_INITIALIZE,
                headers={
                    "Content-Type": "application/json",
                    "Accept": _MCP_ACCEPT,
                    "Authorization": f"Bearer {token}",
                },
            )

        assert response.status_code == 200, (
            f"Expected 200 for valid Workspace JWT but got {response.status_code}. "
            f"Body: {response.text[:500]}"
        )


# ---------------------------------------------------------------------------
# Audit email threading
#
# Proves the email claim survives the full HTTP -> RequireAuthMiddleware ->
# JWTAuthProvider.verify_token -> tool-dispatch path into the audit row --
# the unit tests in tests/test_audit.py only prove app/audit.py's decorator
# logic given a pre-set auth_context_var, not that the real transport
# actually sets it. Lives here (not tests/test_audit.py) per : real
# HTTP via run_server_async is required to exercise RequireAuthMiddleware,
# and this file already has the RSA-key-pair/real-signed-token helpers this
# test reuses. Because run_server_async starts a genuine ASGI app,
# _audit_lifespan actually runs for this test (unlike the
# fastmcp.Client(mcp)-based tests elsewhere in this suite) -- safe in CI with
# no extra teardown, since start_audit_flusher() returns None with no ADC,
# short-circuiting both of _audit_lifespan's cancel-on-shutdown/final-drain
# guards ('s Risks table for the exact
# citation). Deque isolation comes from tests/conftest.py's repo-wide
# `_clear_audit_deque` autouse fixture, not a fixture local to this file.
# ---------------------------------------------------------------------------


class TestAuditEmailThreading:
    @pytest.mark.anyio
    async def test_authenticated_tool_call_threads_email_into_audit_row(self, auth_enabled_server):
        """Full initialize -> notifications/initialized -> tools/call
        sequence with a valid Workspace JWT -> the resulting _audit_deque
        row's userEmail matches the token's email claim exactly."""
        from app.audit import _audit_deque

        server_url, provider = auth_enabled_server
        priv = _generate_rsa_key()
        kid = f"kid-audit-{uuid.uuid4().hex[:8]}"
        s = _make_settings()
        token = _make_token(priv, kid, audience=s.google_oauth_client_id, hd=s.google_workspace_domain)
        jwks = _build_jwks_response((priv, kid))
        _stub_fetch_jwks_on_provider(provider, jwks)

        headers = {
            "Content-Type": "application/json",
            "Accept": _MCP_ACCEPT,
            "Authorization": f"Bearer {token}",
        }

        async with httpx.AsyncClient() as client:
            init_response = await client.post(server_url, json=_MCP_INITIALIZE, headers=headers)
            assert init_response.status_code == 200, (
                f"Expected 200 from initialize but got {init_response.status_code}. "
                f"Body: {init_response.text[:500]}"
            )
            session_id = init_response.headers.get("mcp-session-id")
            assert session_id, "Expected an Mcp-Session-Id response header from initialize"

            session_headers = dict(headers)
            session_headers["Mcp-Session-Id"] = session_id

            initialized_response = await client.post(
                server_url,
                json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                headers=session_headers,
            )
            assert initialized_response.status_code == 202, (
                f"Expected 202 from notifications/initialized but got "
                f"{initialized_response.status_code}. Body: {initialized_response.text[:500]}"
            )

            call_response = await client.post(
                server_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "ping", "arguments": {}},
                },
                headers=session_headers,
            )

        assert call_response.status_code == 200, (
            f"Expected 200 for the authenticated ping tool call but got "
            f"{call_response.status_code}. Body: {call_response.text[:500]}"
        )

        # The tool call reached app.audit.audit_tool_call's wrapper via the
        # real HTTP -> RequireAuthMiddleware -> JWTAuthProvider.verify_token
        # -> tool-dispatch path -- not a directly pre-set auth_context_var.
        assert len(_audit_deque) == 1
        row = _audit_deque[0]
        assert row["toolName"] == "ping"
        assert row["userEmail"] == "user@example.com"


# ---------------------------------------------------------------------------
# Negative path
# ---------------------------------------------------------------------------


class TestMCPAuthNegativePath:
    """Non-Workspace identities must be rejected with workspace_identity_required."""

    @pytest.mark.anyio
    async def test_gmail_identity_is_rejected_with_workspace_code(self, auth_enabled_server, caplog):
        """POST /mcp initialize with hd absent -> HTTP 401, workspace_identity_required in log."""
        import logging

        server_url, provider = auth_enabled_server
        priv = _generate_rsa_key()
        kid = f"kid-neg-nohd-{uuid.uuid4().hex[:8]}"
        s = _make_settings()
        # hd=None -> personal Google account (no hd claim at all)
        token = _make_token(priv, kid, audience=s.google_oauth_client_id, hd=None)
        jwks = _build_jwks_response((priv, kid))

        _stub_fetch_jwks_on_provider(provider, jwks)
        with caplog.at_level(logging.WARNING, logger="app.jwt_auth"):
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    server_url,
                    json=_MCP_INITIALIZE,
                    headers={
                        "Content-Type": "application/json",
                        "Accept": _MCP_ACCEPT,
                        "Authorization": f"Bearer {token}",
                    },
                )

        assert response.status_code == 401, (
            f"Expected 401 for missing-hd token but got {response.status_code}."
        )
        assert any(
            "workspace_identity_required" in r.message for r in caplog.records
        ), f"Expected 'workspace_identity_required' in log records; got: {[r.message for r in caplog.records]}"

    @pytest.mark.anyio
    async def test_gmail_hd_claim_is_rejected(self, auth_enabled_server, caplog):
        """POST /mcp initialize with hd='gmail.com' -> HTTP 401, workspace_identity_required in log."""
        import logging

        server_url, provider = auth_enabled_server
        priv = _generate_rsa_key()
        kid = f"kid-neg-gmail-{uuid.uuid4().hex[:8]}"
        s = _make_settings()
        token = _make_token(priv, kid, audience=s.google_oauth_client_id, hd="gmail.com")
        jwks = _build_jwks_response((priv, kid))

        _stub_fetch_jwks_on_provider(provider, jwks)
        with caplog.at_level(logging.WARNING, logger="app.jwt_auth"):
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    server_url,
                    json=_MCP_INITIALIZE,
                    headers={
                        "Content-Type": "application/json",
                        "Accept": _MCP_ACCEPT,
                        "Authorization": f"Bearer {token}",
                    },
                )

        assert response.status_code == 401, (
            f"Expected 401 for gmail.com hd token but got {response.status_code}."
        )
        assert any(
            "workspace_identity_required" in r.message for r in caplog.records
        ), f"Expected 'workspace_identity_required' in log records; got: {[r.message for r in caplog.records]}"

    @pytest.mark.anyio
    async def test_expired_token_is_rejected(self, auth_enabled_server, caplog):
        """POST /mcp initialize with an expired Workspace JWT -> HTTP 401, token_expired in log."""
        import logging

        server_url, provider = auth_enabled_server
        priv = _generate_rsa_key()
        kid = f"kid-neg-exp-{uuid.uuid4().hex[:8]}"
        s = _make_settings()
        token = _make_token(
            priv,
            kid,
            audience=s.google_oauth_client_id,
            hd=s.google_workspace_domain,
            exp_offset=-3600,  # expired 1 hour ago
        )
        jwks = _build_jwks_response((priv, kid))

        _stub_fetch_jwks_on_provider(provider, jwks)
        with caplog.at_level(logging.WARNING, logger="app.jwt_auth"):
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    server_url,
                    json=_MCP_INITIALIZE,
                    headers={
                        "Content-Type": "application/json",
                        "Accept": _MCP_ACCEPT,
                        "Authorization": f"Bearer {token}",
                    },
                )

        assert response.status_code == 401, (
            f"Expected 401 for expired token but got {response.status_code}."
        )
        assert any(
            "token_expired" in r.message for r in caplog.records
        ), f"Expected 'token_expired' in log records; got: {[r.message for r in caplog.records]}"

    @pytest.mark.anyio
    async def test_wrong_domain_is_rejected_with_workspace_code(self, auth_enabled_server, caplog):
        """POST /mcp initialize with hd='othercorp.com' -> 401, workspace_identity_required in log."""
        import logging

        server_url, provider = auth_enabled_server
        priv = _generate_rsa_key()
        kid = f"kid-neg-domain-{uuid.uuid4().hex[:8]}"
        s = _make_settings()
        token = _make_token(priv, kid, audience=s.google_oauth_client_id, hd="othercorp.com")
        jwks = _build_jwks_response((priv, kid))

        _stub_fetch_jwks_on_provider(provider, jwks)
        with caplog.at_level(logging.WARNING, logger="app.jwt_auth"):
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    server_url,
                    json=_MCP_INITIALIZE,
                    headers={
                        "Content-Type": "application/json",
                        "Accept": _MCP_ACCEPT,
                        "Authorization": f"Bearer {token}",
                    },
                )

        assert response.status_code == 401
        assert any(
            "workspace_identity_required" in r.message for r in caplog.records
        ), f"Expected 'workspace_identity_required' for wrong-domain rejection; got: {[r.message for r in caplog.records]}"

    @pytest.mark.anyio
    async def test_wrong_audience_does_not_log_workspace_code(self, auth_enabled_server, caplog):
        """Wrong-aud rejection must NOT emit workspace_identity_required (confirms specificity)."""
        import logging

        server_url, provider = auth_enabled_server
        priv = _generate_rsa_key()
        kid = f"kid-neg-aud-{uuid.uuid4().hex[:8]}"
        s = _make_settings()
        token = _make_token(
            priv,
            kid,
            audience="wrong-client-id.apps.googleusercontent.com",
            hd=s.google_workspace_domain,
        )
        jwks = _build_jwks_response((priv, kid))

        _stub_fetch_jwks_on_provider(provider, jwks)
        with caplog.at_level(logging.WARNING, logger="app.jwt_auth"):
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    server_url,
                    json=_MCP_INITIALIZE,
                    headers={
                        "Content-Type": "application/json",
                        "Accept": _MCP_ACCEPT,
                        "Authorization": f"Bearer {token}",
                    },
                )

        assert response.status_code == 401
        assert not any(
            "workspace_identity_required" in r.message for r in caplog.records
        ), f"Expected 'workspace_identity_required' to be ABSENT from wrong-aud rejection; got: {[r.message for r in caplog.records]}"

    @pytest.mark.anyio
    async def test_missing_bearer_token_returns_401(self, auth_enabled_server):
        """No Authorization header -> 401 from RequireAuthMiddleware (verify_token not called)."""
        server_url, _provider = auth_enabled_server
        async with httpx.AsyncClient() as client:
            response = await client.post(
                server_url,
                json=_MCP_INITIALIZE,
                headers={
                    "Content-Type": "application/json",
                    "Accept": _MCP_ACCEPT,
                },
            )
        assert response.status_code == 401, (
            f"Expected 401 when Authorization header is absent but got {response.status_code}."
        )

    # -----------------------------------------------------------------
    # Malformed Authorization header shape
    #
    # The tests above only vary the JWT's *claims*. These two vary the
    # header's own shape, which is rejected at a different layer:
    # `mcp.server.auth.middleware.bearer_auth.BearerAuthBackend.authenticate`
    # (source-verified this session) short-circuits with
    # `if not auth_header or not auth_header.lower().startswith("bearer "):
    # return None` -- so a wrong scheme (e.g. "Basic ...") never reaches
    # `JWTAuthProvider.verify_token` at all, while "Bearer " followed by an
    # empty string *does* reach it (and is rejected there, by
    # `app/jwt_auth.py`'s own decode-error handling). Both are genuinely
    # distinct branches from "no header at all" and were previously untested
    # over the real HTTP transport.
    # -----------------------------------------------------------------

    @pytest.mark.anyio
    async def test_wrong_auth_scheme_returns_401(self, auth_enabled_server):
        """Authorization: Basic ... (wrong scheme) -> 401, rejected by the SDK's
        BearerAuthBackend before JWTAuthProvider.verify_token is ever invoked."""
        server_url, _provider = auth_enabled_server
        async with httpx.AsyncClient() as client:
            response = await client.post(
                server_url,
                json=_MCP_INITIALIZE,
                headers={
                    "Content-Type": "application/json",
                    "Accept": _MCP_ACCEPT,
                    "Authorization": "Basic dXNlcjpwYXNz",
                },
            )
        assert response.status_code == 401, (
            f"Expected 401 for a non-Bearer Authorization scheme but got {response.status_code}."
        )

    @pytest.mark.anyio
    async def test_bearer_scheme_with_malformed_token_returns_401(self, auth_enabled_server):
        """Authorization: Bearer <not-a-JWT> -> 401, this time reaching
        JWTAuthProvider.verify_token() itself (kid-extraction/decode error),
        not merely the SDK's own header-shape short-circuit. (A literal empty
        token, "Authorization: Bearer " with nothing after it, cannot be sent
        over real HTTP at all -- httpx/h11 reject a header value with
        trailing whitespace as an illegal header value before the request
        ever leaves the client, confirmed live this session -- so a
        non-JWT-shaped token is the closest reachable equivalent that still
        exercises this exact branch.)"""
        server_url, provider = auth_enabled_server
        # Stub JWKS fetching so the kid-not-found path never makes a real
        # outbound call to Google -- same convention as every other test in
        # this class.
        priv = _generate_rsa_key()
        kid = f"kid-neg-malformed-{uuid.uuid4().hex[:8]}"
        _stub_fetch_jwks_on_provider(provider, _build_jwks_response((priv, kid)))

        async with httpx.AsyncClient() as client:
            response = await client.post(
                server_url,
                json=_MCP_INITIALIZE,
                headers={
                    "Content-Type": "application/json",
                    "Accept": _MCP_ACCEPT,
                    "Authorization": "Bearer not-a-real-jwt",
                },
            )
        assert response.status_code == 401, (
            f"Expected 401 for a malformed (non-JWT) bearer token but got {response.status_code}."
        )


# ---------------------------------------------------------------------------
# MCP-transport-path scoping regression
# ---------------------------------------------------------------------------


class TestNonMCPRoutesUnaffectedByJWTGate:
    """The JWT gate (`RequireAuthMiddleware`, wrapped by FastMCP only around
    the `/mcp` route) must not extend to the pre-auth OAuth/`.well-known`
    custom routes -- these are the surface that issues/validates the JWT
    itself and must remain reachable with no/garbage Authorization header.

    Both variants below assert the *specific* mechanism (the real route
    handler's own response), not merely "status != 401": a bare "not 401"
    assertion could pass for the wrong reason
    (e.g. a misconfigured route that 503s regardless of auth). Asserting the
    handler's exact contract in both the unconfigured (503) and configured
    (200) cases proves the handler was actually reached rather than
    short-circuited by `RequireAuthMiddleware`.
    """

    @pytest.mark.anyio
    async def test_well_known_route_reachable_without_token_oauth_unconfigured(
        self, monkeypatch
    ):
        """Garbage Authorization header, `oauth_base_url` unset -> the handler's
        own 503 (`_oauth_not_configured()`'s exact contract), never
        `RequireAuthMiddleware`'s 401.
        """
        import app.oauth_server as oauth_server

        # The app itself is auth-ENABLED (google_oauth_client_id set) so this
        # test actually exercises a JWT-gated instance, not an auth-disabled one.
        app_settings = _make_settings()

        # oauth_server.py reads its own module-level `settings` (imported at
        # module scope from app.config), independent of app_settings above --
        # patch it directly to control the unconfigured/configured state.
        unconfigured = _make_settings()
        unconfigured.oauth_base_url = ""
        monkeypatch.setattr(oauth_server, "settings", unconfigured)

        app = create_app(app_settings=app_settings)
        async with run_server_async(app, transport="streamable-http") as server_url:
            base_url = server_url.removesuffix("/mcp")
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{base_url}/.well-known/oauth-protected-resource",
                    headers={"Authorization": "Bearer this-is-garbage-not-a-real-token"},
                )

        assert response.status_code == 503, (
            f"Expected the route handler's own 503 (_oauth_not_configured) but got "
            f"{response.status_code}. A 401 here would mean RequireAuthMiddleware "
            f"incorrectly intercepted a non-MCP route. Body: {response.text[:500]}"
        )
        assert response.json() == {"error": "oauth_not_configured"}

    @pytest.mark.anyio
    async def test_well_known_route_reachable_without_token_oauth_configured(
        self, monkeypatch
    ):
        """No Authorization header at all, `oauth_base_url` set -> the
        handler's own 200 metadata response, never `RequireAuthMiddleware`'s
        401 -- positively proves the handler was reached (not merely that it
        didn't error), completing the pair with the 503 case above.
        """
        import app.oauth_server as oauth_server

        app_settings = _make_settings()

        configured = _make_settings()
        configured.oauth_base_url = "https://bq-dataplex-mcp.example.com"
        monkeypatch.setattr(oauth_server, "settings", configured)

        app = create_app(app_settings=app_settings)
        async with run_server_async(app, transport="streamable-http") as server_url:
            base_url = server_url.removesuffix("/mcp")
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{base_url}/.well-known/oauth-protected-resource"
                )

        assert response.status_code == 200, (
            f"Expected the route handler's own 200 metadata response but got "
            f"{response.status_code}. A 401 here would mean RequireAuthMiddleware "
            f"incorrectly intercepted a non-MCP route. Body: {response.text[:500]}"
        )
        body = response.json()
        assert body["resource"] == "https://bq-dataplex-mcp.example.com/mcp"


# ---------------------------------------------------------------------------
# DCR -> authorize -> callback -> token -> authenticated tool call (Exit
# Criterion, per //): the handshake itself is driven by
# direct calls to app.oauth_server's handler functions, then the
# resulting access_token is used against this same auth-enabled instance's
# real HTTP server to prove it's accepted by JWTAuthProvider/RequireAuthMiddleware.
# ---------------------------------------------------------------------------


class TestExitCriterionHandshakeThenAuthenticatedToolCall:
    @pytest.mark.anyio
    async def test_handshake_then_ping_via_real_http_succeeds(self, monkeypatch):
        import app.oauth_server as oauth_server
        from tests._oauth_store_fake import FakeOAuthStore

        base_url_placeholder = "https://bq-dataplex-mcp.example.com"
        client_redirect_uri = "https://claude.ai/api/mcp/auth_callback"

        s = _make_settings()
        s.oauth_base_url = base_url_placeholder
        s.google_oauth_client_secret = "test-client-secret"

        fake_store = FakeOAuthStore()
        monkeypatch.setattr(oauth_server, "store", fake_store)
        monkeypatch.setattr(oauth_server, "settings", s)
        monkeypatch.setattr("app.google_auth.settings", s)

        app = create_app(app_settings=s)
        provider = app.auth
        assert provider is not None

        # --- Step 1: DCR ---
        import secrets as _secrets

        client_id = _secrets.token_urlsafe(24)
        await fake_store.save_client(
            client_id,
            redirect_uris=[client_redirect_uri],
            client_name="Claude",
            ttl_seconds=90 * 24 * 3600,
        )

        # --- Step 2: /oauth/authorize ---
        import hashlib
        import urllib.parse

        from starlette.requests import Request

        def _make_get_request(path: str, query: dict[str, str]) -> Request:
            qs = urllib.parse.urlencode(query).encode()
            scope = {
                "type": "http",
                "method": "GET",
                "path": path,
                "query_string": qs,
                "headers": [],
                "server": ("test", 80),
                "client": ("test", 123),
            }

            async def receive():
                return {"type": "http.disconnect"}

            return Request(scope, receive)

        code_verifier = _secrets.token_urlsafe(64)
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

        authorize_request = _make_get_request(
            "/oauth/authorize",
            {
                "client_id": client_id,
                "redirect_uri": client_redirect_uri,
                "response_type": "code",
                "state": "client-csrf-state",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            },
        )
        authorize_response = await oauth_server.oauth_authorize(authorize_request)
        assert authorize_response.status_code == 302
        assert len(fake_store.transactions) == 1
        (txn_id, _txn), = fake_store.transactions.items()

        # --- Step 3: /oauth/callback (direct handler call), mocked Google exchange ---
        priv = _generate_rsa_key()
        kid = f"kid-exit-{uuid.uuid4().hex[:8]}"
        our_id_token = _make_token(
            priv, kid, audience=s.google_oauth_client_id, hd=s.google_workspace_domain
        )

        def _mock_post(*_args, **_kwargs):
            from unittest.mock import MagicMock

            resp = MagicMock()
            resp.ok = True
            resp.json.return_value = {
                "access_token": "ya29.mock",
                "id_token": our_id_token,
                "token_type": "Bearer",
                "expires_in": 3599,
                "refresh_token": "1//mock-google-refresh-token",
            }
            return resp

        monkeypatch.setattr("app.google_auth.requests.post", _mock_post)

        callback_request = _make_get_request(
            "/oauth/callback", {"state": txn_id, "code": "google-auth-code"}
        )
        callback_response = await oauth_server.oauth_callback(callback_request)
        assert callback_response.status_code == 302
        callback_location = callback_response.headers["location"]
        our_code = urllib.parse.parse_qs(urllib.parse.urlparse(callback_location).query)["code"][0]

        # --- Step 4: /oauth/token (direct handler call) ---
        def _make_post_form_request(path: str, form: dict[str, str]) -> Request:
            body = urllib.parse.urlencode(form).encode()
            scope = {
                "type": "http",
                "method": "POST",
                "path": path,
                "query_string": b"",
                "headers": [(b"content-type", b"application/x-www-form-urlencoded")],
                "server": ("test", 80),
                "client": ("test", 123),
            }
            sent = {"done": False}

            async def receive():
                if sent["done"]:
                    return {"type": "http.disconnect"}
                sent["done"] = True
                return {"type": "http.request", "body": body, "more_body": False}

            return Request(scope, receive)

        token_request = _make_post_form_request(
            "/oauth/token",
            {
                "grant_type": "authorization_code",
                "code": our_code,
                "redirect_uri": client_redirect_uri,
                "code_verifier": code_verifier,
                "client_id": client_id,
            },
        )
        token_response = await oauth_server.oauth_token(token_request)
        assert token_response.status_code == 200
        import json

        token_body = json.loads(token_response.body)
        access_token = token_body["access_token"]
        assert access_token == our_id_token

        # --- Step 5: confirm the access_token is accepted on a
        # subsequent authenticated MCP tool call via a REAL HTTP server, not
        # fastmcp.Client(...) -- see module docstring.
        _stub_fetch_jwks_on_provider(provider, _build_jwks_response((priv, kid)))
        async with run_server_async(app, transport="streamable-http") as server_url:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    server_url,
                    json=_MCP_INITIALIZE,
                    headers={
                        "Content-Type": "application/json",
                        "Accept": _MCP_ACCEPT,
                        "Authorization": f"Bearer {access_token}",
                    },
                )
        assert response.status_code == 200, (
            f"Expected 200 for the handshake's own access_token but got "
            f"{response.status_code}. Body: {response.text[:500]}"
        )


# ---------------------------------------------------------------------------
#  (2026-09-24 rework): whitelisted CI service-account identity skips
# the `hd` check for that one configured `email` only -- `aud` remains the
# single, unchanged primary audience (no second accepted audience). See
# module docstring for why run_server_async + httpx.AsyncClient is required
# here, not fastmcp.Client(...).
# ---------------------------------------------------------------------------


class TestCIServiceAccountBypass:
    """Field name (`google_oauth_service_account_email`) and the
    `email_verified is True` guard match the reference implementation's
     (Revision 2) implementation exactly -- see app/jwt_auth.py's
    Design Decision docstring section.
    """

    CI_EMAIL = "ci-eval@example-project.iam.gserviceaccount.com"

    @pytest.mark.anyio
    async def test_mcp_request_accepted_for_whitelisted_email_without_hd(self):
        """A token with no `hd` claim but whose `email` matches the
        configured whitelist, with `email_verified` strictly True, is
        accepted -> HTTP 200 -- the behavior change this suite
        delivers."""
        s = _make_settings(service_account_email=self.CI_EMAIL)
        app = create_app(app_settings=s)
        provider = app.auth
        assert provider is not None

        priv = _generate_rsa_key()
        kid = f"kid-ci-nohd-{uuid.uuid4().hex[:8]}"
        token = _make_token(
            priv,
            kid,
            audience=s.google_oauth_client_id,
            hd=None,
            extra_claims={"email": self.CI_EMAIL, "email_verified": True},
        )
        _stub_fetch_jwks_on_provider(provider, _build_jwks_response((priv, kid)))

        async with run_server_async(app, transport="streamable-http") as server_url:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    server_url,
                    json=_MCP_INITIALIZE,
                    headers={
                        "Content-Type": "application/json",
                        "Accept": _MCP_ACCEPT,
                        "Authorization": f"Bearer {token}",
                    },
                )

        assert response.status_code == 200, (
            f"Expected 200 for a whitelisted-email token with no hd but got "
            f"{response.status_code}. Body: {response.text[:500]}"
        )

    @pytest.mark.anyio
    async def test_mcp_request_rejected_for_non_whitelisted_email_without_hd(self):
        """A token with no `hd` claim and an `email` that does not match the
        whitelist is still rejected -> HTTP 401 (the whitelist narrows to
        exactly one identity, it does not widen acceptance to any SA-shaped
        token)."""
        s = _make_settings(service_account_email=self.CI_EMAIL)
        app = create_app(app_settings=s)
        provider = app.auth
        assert provider is not None

        priv = _generate_rsa_key()
        kid = f"kid-ci-unrelated-{uuid.uuid4().hex[:8]}"
        token = _make_token(
            priv,
            kid,
            audience=s.google_oauth_client_id,
            hd=None,
            extra_claims={"email": "someone-else@example.com", "email_verified": True},
        )
        _stub_fetch_jwks_on_provider(provider, _build_jwks_response((priv, kid)))

        async with run_server_async(app, transport="streamable-http") as server_url:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    server_url,
                    json=_MCP_INITIALIZE,
                    headers={
                        "Content-Type": "application/json",
                        "Accept": _MCP_ACCEPT,
                        "Authorization": f"Bearer {token}",
                    },
                )

        assert response.status_code == 401, (
            f"Expected 401 for a non-whitelisted email with no hd but got "
            f"{response.status_code}. Body: {response.text[:500]}"
        )

    @pytest.mark.anyio
    async def test_mcp_request_rejected_for_whitelisted_email_when_email_not_verified(self):
        """A token whose `email` matches the whitelist but whose
        `email_verified` claim is not strictly True is still rejected ->
        HTTP 401 (anti-spoofing)."""
        s = _make_settings(service_account_email=self.CI_EMAIL)
        app = create_app(app_settings=s)
        provider = app.auth
        assert provider is not None

        priv = _generate_rsa_key()
        kid = f"kid-ci-unverified-{uuid.uuid4().hex[:8]}"
        token = _make_token(
            priv,
            kid,
            audience=s.google_oauth_client_id,
            hd=None,
            extra_claims={"email": self.CI_EMAIL, "email_verified": False},
        )
        _stub_fetch_jwks_on_provider(provider, _build_jwks_response((priv, kid)))

        async with run_server_async(app, transport="streamable-http") as server_url:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    server_url,
                    json=_MCP_INITIALIZE,
                    headers={
                        "Content-Type": "application/json",
                        "Accept": _MCP_ACCEPT,
                        "Authorization": f"Bearer {token}",
                    },
                )

        assert response.status_code == 401, (
            f"Expected 401 for a whitelisted email with email_verified=False but got "
            f"{response.status_code}. Body: {response.text[:500]}"
        )

    @pytest.mark.anyio
    async def test_mcp_request_still_accepted_for_normal_human_token_when_whitelist_configured(
        self,
    ):
        """Regression, real HTTP layer: a normal human token with a valid
        `hd` is still accepted once the whitelist is also configured."""
        s = _make_settings(service_account_email=self.CI_EMAIL)
        app = create_app(app_settings=s)
        provider = app.auth
        assert provider is not None

        priv = _generate_rsa_key()
        kid = f"kid-ci-human-{uuid.uuid4().hex[:8]}"
        token = _make_token(priv, kid, audience=s.google_oauth_client_id, hd=s.google_workspace_domain)
        _stub_fetch_jwks_on_provider(provider, _build_jwks_response((priv, kid)))

        async with run_server_async(app, transport="streamable-http") as server_url:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    server_url,
                    json=_MCP_INITIALIZE,
                    headers={
                        "Content-Type": "application/json",
                        "Accept": _MCP_ACCEPT,
                        "Authorization": f"Bearer {token}",
                    },
                )

        assert response.status_code == 200, (
            f"Expected 200 for a valid human token but got "
            f"{response.status_code}. Body: {response.text[:500]}"
        )
