"""Real-HTTP coverage of MCP protocol 2026-07-28 and legacy versions.

Prod runs `stateless_http=True` (see `app.main.main`) behind the JWT gate.
mcp 1.x answered any `mcp-protocol-version` it did not know -- including
2026-07-28 -- with a silent HTTP 400 (`_validate_protocol_version`). fastmcp
4 / mcp 2.x serves it, so these tests pin that behaviour on the exact prod
shape: an auth-enabled app, stateless transport, real uvicorn socket.

A 2026-07-28 request is a self-contained POST: no `initialize`, the version,
client info and capabilities travel in `params._meta`, and `Mcp-Method` (plus
`Mcp-Name` for `tools/call`) must mirror the body.

Not covered here: `run_server_async` has no `stateless_http` knob, so this
module starts uvicorn itself rather than reusing the fixture in
`tests/test_mcp_auth_integration.py` (whose helpers it does reuse).
"""

import asyncio
import logging
import uuid

import httpx
import pytest
import uvicorn
from fastmcp.utilities.tests import find_available_port
from starlette.middleware import Middleware

from app import oauth_server
from app.audit import _audit_deque
from app.main import create_app
from app.rejection_log import LOG_SENTINEL, McpRejectionLogger
from tests.test_mcp_auth_integration import (
    _build_jwks_response,
    _generate_rsa_key,
    _make_settings,
    _make_token,
    _stub_fetch_jwks_on_provider,
)

_ACCEPT = "application/json, text/event-stream"
_BASE_URL = "https://bq-dataplex-mcp.example.com"
_PRM_URL = f"{_BASE_URL}/.well-known/oauth-protected-resource/mcp"
_MODERN = "2026-07-28"
_META = {
    "io.modelcontextprotocol/protocolVersion": _MODERN,
    "io.modelcontextprotocol/clientInfo": {"name": "test-client", "version": "0.0.1"},
    "io.modelcontextprotocol/clientCapabilities": {},
}
_PING = {"name": "ping", "arguments": {}}
_EXPECTED_TOOLS = {
    "ping",
    "list_datasets",
    "list_tables",
    "get_table_metadata",
    "get_data_lineage",
    "get_data_quality_results",
    "execute_sql",
}


def _modern_request(method: str, params: dict | None = None) -> tuple[dict, dict]:
    headers = {"mcp-protocol-version": _MODERN, "mcp-method": method}
    if method == "tools/call":
        headers["mcp-name"] = params["name"]
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": {**(params or {}), "_meta": _META}}
    return headers, body


def _legacy_call() -> dict:
    return {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": _PING}


@pytest.fixture
async def stateless_auth_server(monkeypatch):
    """Yields (url, valid_token, non_workspace_token) for an auth-enabled,
    stateless `create_app(...)` served on a real port, configured like prod
    (`oauth_base_url` set) so 401 challenges carry `resource_metadata`."""
    settings = _make_settings()
    settings.oauth_base_url = _BASE_URL
    monkeypatch.setattr(oauth_server.settings, "oauth_base_url", _BASE_URL)
    app = create_app(app_settings=settings)
    private_key = _generate_rsa_key()
    kid = f"kid-proto-{uuid.uuid4().hex[:8]}"
    _stub_fetch_jwks_on_provider(app.auth, _build_jwks_response((private_key, kid)))
    valid = _make_token(
        private_key, kid, audience=settings.google_oauth_client_id, hd=settings.google_workspace_domain
    )
    non_workspace = _make_token(
        private_key,
        kid,
        audience=settings.google_oauth_client_id,
        hd=None,
        extra_claims={"email": "someone@gmail.com"},
    )

    port = find_available_port()
    asgi_app = app.http_app(
        path="/mcp",
        transport="streamable-http",
        stateless_http=True,
        middleware=[Middleware(McpRejectionLogger)],
    )
    server = uvicorn.Server(
        uvicorn.Config(asgi_app, host="127.0.0.1", port=port, log_level="error", access_log=False)
    )
    task = asyncio.create_task(server.serve())
    for _ in range(100):
        if server.started:
            break
        await asyncio.sleep(0.1)
    assert server.started, "uvicorn did not start"
    try:
        yield f"http://127.0.0.1:{port}/mcp", valid, non_workspace
    finally:
        server.should_exit = True
        await task


def _headers(token: str | None = None, **extra: str) -> dict:
    headers = {"content-type": "application/json", "accept": _ACCEPT, **extra}
    if token:
        headers["authorization"] = f"Bearer {token}"
    return headers


class TestModernProtocol:
    @pytest.mark.anyio
    async def test_tools_call_ping_returns_200_and_audits_email(self, stateless_auth_server):
        """The replayed-400 regression (AC-6): a 2026-07-28 tools/call used to
        be rejected with HTTP 400 before reaching the tool layer."""
        url, token, _ = stateless_auth_server
        extra, body = _modern_request("tools/call", _PING)
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.post(url, headers=_headers(token, **extra), json=body)

        assert response.status_code == 200, response.text[:300]
        result = response.json()["result"]
        assert result["isError"] is False
        assert len(_audit_deque) == 1
        assert _audit_deque[0]["toolName"] == "ping"
        assert _audit_deque[0]["userEmail"] == "user@example.com"

    @pytest.mark.anyio
    async def test_tools_list_exposes_all_seven_tools(self, stateless_auth_server):
        url, token, _ = stateless_auth_server
        extra, body = _modern_request("tools/list")
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.post(url, headers=_headers(token, **extra), json=body)

        assert response.status_code == 200, response.text[:300]
        assert {tool["name"] for tool in response.json()["result"]["tools"]} == _EXPECTED_TOOLS

    @pytest.mark.anyio
    async def test_header_without_meta_envelope_is_a_jsonrpc_error_not_a_crash(self, stateless_auth_server):
        """A 2026-07-28 header with no `params._meta` is malformed under the
        new protocol; pin that it is a clean, client-visible JSON-RPC error."""
        url, token, _ = stateless_auth_server
        body = {"jsonrpc": "2.0", "id": 3, "method": "tools/list"}
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.post(
                url,
                headers=_headers(token, **{"mcp-protocol-version": _MODERN, "mcp-method": "tools/list"}),
                json=body,
            )

        assert response.status_code == 400
        assert response.json()["error"]["code"] == -32602
        assert "_meta" in response.json()["error"]["message"]

    @pytest.mark.anyio
    async def test_missing_token_is_rejected(self, stateless_auth_server):
        url, _, _ = stateless_auth_server
        extra, body = _modern_request("tools/call", _PING)
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.post(url, headers=_headers(**extra), json=body)

        assert response.status_code == 401
        assert response.headers["www-authenticate"].startswith("Bearer")

    @pytest.mark.anyio
    async def test_non_workspace_token_is_rejected_and_not_audited(self, stateless_auth_server):
        url, _, non_workspace = stateless_auth_server
        extra, body = _modern_request("tools/call", _PING)
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.post(url, headers=_headers(non_workspace, **extra), json=body)

        assert response.status_code == 401
        assert len(_audit_deque) == 0


class TestLegacyProtocolStateless:
    @pytest.mark.anyio
    @pytest.mark.parametrize("version", ["2025-06-18", "2025-11-25"])
    async def test_stateless_tools_call_succeeds_and_audits_email(self, stateless_auth_server, version):
        url, token, _ = stateless_auth_server
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.post(
                url,
                headers=_headers(token, **{"mcp-protocol-version": version}),
                json=_legacy_call(),
            )

        assert response.status_code == 200, response.text[:300]
        assert len(_audit_deque) == 1
        assert _audit_deque[0]["userEmail"] == "user@example.com"

    @pytest.mark.anyio
    async def test_missing_token_is_rejected(self, stateless_auth_server):
        url, _, _ = stateless_auth_server
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.post(url, headers=_headers(), json=_legacy_call())

        assert response.status_code == 401


class TestUnauthorizedChallenge:
    """fastmcp 4 only puts `resource_metadata` in the 401 challenge when the
    auth provider serves the RFC 9728 route itself. Clients use it to start
    OAuth discovery, and prod's only access gate is app OAuth."""

    @pytest.mark.anyio
    @pytest.mark.parametrize("protocol", ["legacy", "modern"])
    async def test_missing_token_challenge_advertises_resource_metadata(self, stateless_auth_server, protocol):
        url, _, _ = stateless_auth_server
        if protocol == "modern":
            extra, body = _modern_request("tools/call", _PING)
        else:
            extra, body = {}, _legacy_call()
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.post(url, headers=_headers(**extra), json=body)

        assert response.status_code == 401
        assert f'resource_metadata="{_PRM_URL}"' in response.headers["www-authenticate"]

    @pytest.mark.anyio
    @pytest.mark.parametrize("token", ["not-a-jwt", "expired"])
    async def test_invalid_token_challenge_has_error_and_resource_metadata(self, stateless_auth_server, token):
        url, _, _ = stateless_auth_server
        if token == "expired":
            settings = _make_settings()
            key = _generate_rsa_key()
            token = _make_token(key, "unknown-kid", audience=settings.google_oauth_client_id, exp_offset=-100)
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.post(url, headers=_headers(token), json=_legacy_call())

        assert response.status_code == 401
        challenge = response.headers["www-authenticate"]
        assert 'error="invalid_token"' in challenge
        assert f'resource_metadata="{_PRM_URL}"' in challenge

    @pytest.mark.anyio
    async def test_advertised_metadata_url_is_public_and_correct(self, stateless_auth_server):
        """The hint must not point at a 404/401: fetch its path with no token."""
        url, _, _ = stateless_auth_server
        origin = url.removesuffix("/mcp")
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.get(f"{origin}/.well-known/oauth-protected-resource/mcp")

        assert response.status_code == 200
        body = response.json()
        assert body["resource"] == f"{_BASE_URL}/mcp"
        assert body["authorization_servers"] == [_BASE_URL]


class TestRejectionLogging:
    """Wired exactly as `main()` wires it: every protocol-layer rejection on
    /mcp leaves one greppable WARNING (AC-8) and never leaks credentials (INV-3)."""

    @staticmethod
    def _lines(caplog) -> list[str]:
        return [r.getMessage() for r in caplog.records if LOG_SENTINEL in r.getMessage()]

    @pytest.mark.anyio
    async def test_header_without_meta_is_logged_with_code_ua_and_version(self, stateless_auth_server, caplog):
        caplog.set_level(logging.WARNING)
        url, token, _ = stateless_auth_server
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.post(
                url,
                headers=_headers(
                    token, **{"mcp-protocol-version": _MODERN, "mcp-method": "tools/list", "user-agent": "probe/9"}
                ),
                json={"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
            )

        assert response.status_code == 400
        [line] = self._lines(caplog)
        assert "status=400" in line
        assert "rpc_error_code=-32602" in line
        assert "ua='probe/9'" in line
        assert f"protocol_version='{_MODERN}'" in line
        assert token not in line
        assert "Bearer" not in line

    @pytest.mark.anyio
    async def test_successful_calls_401s_and_get_405_are_not_logged(self, stateless_auth_server, caplog):
        caplog.set_level(logging.WARNING)
        url, token, _ = stateless_auth_server
        extra, body = _modern_request("tools/call", _PING)
        async with httpx.AsyncClient(timeout=15) as client:
            ok = await client.post(url, headers=_headers(token, **extra), json=body)
            unauthorized = await client.post(url, headers=_headers(**extra), json=body)
            get = await client.get(
                url, headers={"accept": "text/event-stream", "authorization": f"Bearer {token}"}
            )

        assert (ok.status_code, unauthorized.status_code, get.status_code) == (200, 401, 405)
        assert self._lines(caplog) == []


class TestGetMcp:
    @pytest.mark.anyio
    async def test_get_returns_405_instead_of_hanging_an_sse_stream(self, stateless_auth_server):
        """Stateless mode has no server-initiated messages; a GET must not hold
        a long-lived SSE stream open."""
        url, token, _ = stateless_auth_server
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.get(
                url, headers={"accept": "text/event-stream", "authorization": f"Bearer {token}"}
            )

        assert response.status_code == 405
