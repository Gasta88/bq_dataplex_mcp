"""Integration tests for app/oauth_server.py: discovery metadata, Dynamic
Client Registration, and the Authorization Code + PKCE handshake proxied to
Google.

Routes are exercised through the real ASGI app
(`app.main.create_app().http_app(...)`), so route registration and the
`RequireAuthMiddleware` bypass are covered, not just the handler functions.
`app.oauth_server.store` is replaced with an in-memory fake, so no real
Firestore/ADC credentials are needed.
"""

import base64
import hashlib
import logging
import secrets
import time
import urllib.parse
from unittest.mock import MagicMock

import app.oauth_server as oauth_server
import pytest
from httpx import ASGITransport, AsyncClient
from tests._oauth_store_fake import FakeOAuthStore

_BASE_URL = "https://bq-dataplex-mcp.example.com"
_CLIENT_REDIRECT_URI = "https://mcp-client.example.com/callback"


def _generate_rsa_key():
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa

    return rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())


def _make_token(private_key, kid, *, audience="x", hd="example.com"):
    import jwt as pyjwt

    now = int(time.time())
    payload = {
        "iss": "https://accounts.google.com",
        "sub": "12345678901234567890",
        "aud": audience,
        "iat": now,
        "exp": now + 3600,
        "email": "user@example.com",
    }
    if hd is not None:
        payload["hd"] = hd
    return pyjwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _mock_google_token_response(id_token: str, *, refresh_token: str | None = None) -> MagicMock:
    resp = MagicMock()
    resp.ok = True
    body = {
        "access_token": "ya29.mock-access-token",
        "id_token": id_token,
        "token_type": "Bearer",
        "expires_in": 3599,
    }
    if refresh_token is not None:
        body["refresh_token"] = refresh_token
    resp.json.return_value = body
    return resp


@pytest.fixture
def fake_store(monkeypatch):
    store = FakeOAuthStore()
    monkeypatch.setattr(oauth_server, "store", store)
    return store


@pytest.fixture
def configured_settings(monkeypatch):
    """Patch the module-local `settings` name in every module that needs test
    values, matching `tests/test_google_auth.py`'s established pattern.

    Deliberately does NOT rely on `app.oauth_server.settings`/
    `app.google_auth.settings` being the same object as a freshly-imported
    `app.config.settings` -- each module reads its own module-level `settings`
    reference, so each is patched independently.
    """
    from app.config import Settings

    s = Settings()
    s.oauth_base_url = _BASE_URL
    s.google_oauth_client_id = "test-client-id.apps.googleusercontent.com"
    s.google_oauth_client_secret = "test-client-secret"
    s.google_workspace_domain = "example.com"
    monkeypatch.setattr(oauth_server, "settings", s)
    monkeypatch.setattr("app.google_auth.settings", s)
    return s


@pytest.fixture
def oauth_app(configured_settings, fake_store):
    from app.main import create_app

    app = create_app(configured_settings)
    return app.http_app(transport="streamable-http")


@pytest.fixture
async def client(oauth_app):
    async with AsyncClient(transport=ASGITransport(app=oauth_app), base_url="http://test") as c:
        yield c


async def _register_client(client) -> str:
    resp = await client.post(
        "/oauth/register",
        json={"redirect_uris": [_CLIENT_REDIRECT_URI], "client_name": "test-mcp-client"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["client_id"]


async def _login_and_get_refresh_token(
    client, fake_store, monkeypatch, *, hd: str | None = "example.com"
) -> str:
    """Drive a full authorize -> callback -> token round trip and return the
    server-issued refresh_token from the /oauth/token response.
    """
    client_id = await _register_client(client)
    code_verifier, code_challenge = _pkce_pair()

    resp = await client.get(
        "/oauth/authorize",
        params={
            "client_id": client_id,
            "redirect_uri": _CLIENT_REDIRECT_URI,
            "response_type": "code",
            "state": "s",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        },
    )
    (txn_id, _), = fake_store.transactions.items()

    priv = _generate_rsa_key()
    id_token = _make_token(priv, "kid-1", audience="x", hd=hd)
    with monkeypatch.context() as m:
        m.setattr(
            "app.google_auth.requests.post",
            lambda *a, **k: _mock_google_token_response(
                id_token, refresh_token="1//mock-google-refresh-token"
            ),
        )
        resp = await client.get("/oauth/callback", params={"state": txn_id, "code": "gcode"})
    our_code = urllib.parse.parse_qs(urllib.parse.urlparse(resp.headers["location"]).query)["code"][0]

    resp = await client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": our_code,
            "redirect_uri": _CLIENT_REDIRECT_URI,
            "code_verifier": code_verifier,
            "client_id": client_id,
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["refresh_token"]


# ---------------------------------------------------------------------------
# Discovery metadata
# ---------------------------------------------------------------------------


class TestDiscoveryMetadata:
    @pytest.mark.anyio
    async def test_protected_resource_metadata(self, client):
        resp = await client.get("/.well-known/oauth-protected-resource/mcp")
        assert resp.status_code == 200
        body = resp.json()
        assert body["resource"] == f"{_BASE_URL}/mcp"
        # mcp 2.x models these as plain strings (no trailing-"/" normalization);
        # must stay identical to the AS metadata `issuer` (RFC 9728/8414).
        assert body["authorization_servers"] == [_BASE_URL]
        assert body["resource_name"] == "bq-dataplex-mcp"

    @pytest.mark.anyio
    async def test_authorization_server_metadata(self, client):
        resp = await client.get("/.well-known/oauth-authorization-server")
        assert resp.status_code == 200
        body = resp.json()
        assert body["authorization_endpoint"] == f"{_BASE_URL}/oauth/authorize"
        assert body["token_endpoint"] == f"{_BASE_URL}/oauth/token"
        assert body["registration_endpoint"] == f"{_BASE_URL}/oauth/register"
        assert body["revocation_endpoint"] == f"{_BASE_URL}/oauth/revoke"
        assert body["code_challenge_methods_supported"] == ["S256"]
        assert body["grant_types_supported"] == ["authorization_code", "refresh_token"]

    @pytest.mark.anyio
    async def test_metadata_returns_503_when_oauth_not_configured(self, fake_store, monkeypatch):
        from app.config import Settings
        from app.main import create_app

        unconfigured = Settings()
        unconfigured.oauth_base_url = ""
        monkeypatch.setattr(oauth_server, "settings", unconfigured)
        app_ = create_app().http_app(transport="streamable-http")
        async with AsyncClient(transport=ASGITransport(app=app_), base_url="http://test") as c:
            resp = await c.get("/.well-known/oauth-authorization-server")
        assert resp.status_code == 503


# ---------------------------------------------------------------------------
# Dynamic Client Registration
# ---------------------------------------------------------------------------


class TestDynamicClientRegistration:
    @pytest.mark.anyio
    async def test_valid_registration_returns_201_with_client_id(self, client):
        resp = await client.post(
            "/oauth/register", json={"redirect_uris": [_CLIENT_REDIRECT_URI]}
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["client_id"]
        assert body["redirect_uris"] == [_CLIENT_REDIRECT_URI]
        assert body["token_endpoint_auth_method"] == "none"
        assert "refresh_token" in body["grant_types"]

    @pytest.mark.anyio
    async def test_missing_redirect_uris_returns_400(self, client):
        resp = await client.post("/oauth/register", json={})
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_client_metadata"

    @pytest.mark.anyio
    async def test_non_https_non_localhost_redirect_uri_returns_400(self, client):
        resp = await client.post(
            "/oauth/register", json={"redirect_uris": ["http://evil.example.com/callback"]}
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_redirect_uri"

    @pytest.mark.anyio
    async def test_localhost_http_redirect_uri_is_allowed(self, client):
        resp = await client.post(
            "/oauth/register", json={"redirect_uris": ["http://localhost:51234/callback"]}
        )
        assert resp.status_code == 201


# ---------------------------------------------------------------------------
# Full authorize -> callback -> token round trip
# ---------------------------------------------------------------------------


class TestFullRoundTrip:
    @pytest.mark.anyio
    async def test_positive_round_trip_issues_google_id_token(self, client, fake_store, monkeypatch):
        client_id = await _register_client(client)
        code_verifier, code_challenge = _pkce_pair()

        # Step 1: /oauth/authorize -> redirect to Google, transaction persisted.
        resp = await client.get(
            "/oauth/authorize",
            params={
                "client_id": client_id,
                "redirect_uri": _CLIENT_REDIRECT_URI,
                "response_type": "code",
                "state": "client-csrf-state",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            },
        )
        assert resp.status_code == 302
        assert "accounts.google.com" in resp.headers["location"]
        assert len(fake_store.transactions) == 1
        (txn_id, txn), = fake_store.transactions.items()
        assert txn["client_state"] == "client-csrf-state"

        # Step 2: Google redirects to /oauth/callback with our txn_id as `state`.
        priv = _generate_rsa_key()
        id_token = _make_token(
            priv, "kid-1", audience="test-client-id.apps.googleusercontent.com", hd="example.com"
        )
        google_refresh_token = "1//mock-google-refresh-token"
        with monkeypatch.context() as m:
            m.setattr(
                "app.google_auth.requests.post",
                lambda *a, **k: _mock_google_token_response(
                    id_token, refresh_token=google_refresh_token
                ),
            )
            resp = await client.get(
                "/oauth/callback", params={"state": txn_id, "code": "google-auth-code"}
            )
        assert resp.status_code == 302
        assert txn_id not in fake_store.transactions  # consumed
        assert resp.headers["location"].startswith(_CLIENT_REDIRECT_URI)
        location = urllib.parse.urlparse(resp.headers["location"])
        callback_qs = urllib.parse.parse_qs(location.query)
        assert callback_qs["state"] == ["client-csrf-state"]
        our_code = callback_qs["code"][0]

        # Step 3: MCP client exchanges our_code + its own code_verifier at /oauth/token.
        resp = await client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": our_code,
                "redirect_uri": _CLIENT_REDIRECT_URI,
                "code_verifier": code_verifier,
                "client_id": client_id,
            },
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["access_token"] == id_token
        assert body["token_type"] == "Bearer"
        assert "refresh_token" in body
        assert body["refresh_token"] != google_refresh_token  # our opaque wrapper, not Google's
        stored = fake_store.refresh_tokens[body["refresh_token"]]
        assert stored["google_refresh_token"] == google_refresh_token
        assert stored["client_id"] == client_id
        # The one-time code (which carried Google's refresh token in transit)
        # is deleted on consumption, not just marked used.
        assert our_code not in fake_store.codes

    @pytest.mark.anyio
    async def test_round_trip_without_google_refresh_token_still_succeeds(
        self, client, fake_store, monkeypatch
    ):
        """Google can omit refresh_token (e.g. an already-granted org-level
        consent). Login must still succeed -- refresh support is additive.
        """
        client_id = await _register_client(client)
        code_verifier, code_challenge = _pkce_pair()

        resp = await client.get(
            "/oauth/authorize",
            params={
                "client_id": client_id,
                "redirect_uri": _CLIENT_REDIRECT_URI,
                "response_type": "code",
                "state": "s",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            },
        )
        (txn_id, _), = fake_store.transactions.items()

        priv = _generate_rsa_key()
        id_token = _make_token(priv, "kid-1", audience="x", hd="example.com")
        with monkeypatch.context() as m:
            m.setattr(
                "app.google_auth.requests.post",
                lambda *a, **k: _mock_google_token_response(id_token),  # no refresh_token
            )
            resp = await client.get("/oauth/callback", params={"state": txn_id, "code": "gcode"})
        our_code = urllib.parse.parse_qs(urllib.parse.urlparse(resp.headers["location"]).query)["code"][0]

        resp = await client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": our_code,
                "redirect_uri": _CLIENT_REDIRECT_URI,
                "code_verifier": code_verifier,
                "client_id": client_id,
            },
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert "refresh_token" not in body
        assert fake_store.refresh_tokens == {}

    @pytest.mark.anyio
    async def test_pkce_mismatch_returns_invalid_grant(self, client, fake_store, monkeypatch):
        client_id = await _register_client(client)
        _correct_verifier, code_challenge = _pkce_pair()
        wrong_verifier, _ = _pkce_pair()

        resp = await client.get(
            "/oauth/authorize",
            params={
                "client_id": client_id,
                "redirect_uri": _CLIENT_REDIRECT_URI,
                "response_type": "code",
                "state": "s",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            },
        )
        (txn_id, _), = fake_store.transactions.items()

        priv = _generate_rsa_key()
        id_token = _make_token(priv, "kid-1", audience="x", hd="example.com")
        with monkeypatch.context() as m:
            m.setattr(
                "app.google_auth.requests.post",
                lambda *a, **k: _mock_google_token_response(id_token),
            )
            resp = await client.get("/oauth/callback", params={"state": txn_id, "code": "gcode"})
        our_code = urllib.parse.parse_qs(urllib.parse.urlparse(resp.headers["location"]).query)["code"][0]

        resp = await client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": our_code,
                "redirect_uri": _CLIENT_REDIRECT_URI,
                "code_verifier": wrong_verifier,
                "client_id": client_id,
            },
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_grant"

    @pytest.mark.anyio
    async def test_reused_code_returns_invalid_grant_on_second_exchange(
        self, client, fake_store, monkeypatch
    ):
        client_id = await _register_client(client)
        code_verifier, code_challenge = _pkce_pair()

        await client.get(
            "/oauth/authorize",
            params={
                "client_id": client_id,
                "redirect_uri": _CLIENT_REDIRECT_URI,
                "response_type": "code",
                "state": "s",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            },
        )
        (txn_id, _), = fake_store.transactions.items()

        priv = _generate_rsa_key()
        id_token = _make_token(priv, "kid-1", audience="x", hd="example.com")
        with monkeypatch.context() as m:
            m.setattr(
                "app.google_auth.requests.post",
                lambda *a, **k: _mock_google_token_response(id_token),
            )
            resp = await client.get("/oauth/callback", params={"state": txn_id, "code": "gcode"})
        our_code = urllib.parse.parse_qs(urllib.parse.urlparse(resp.headers["location"]).query)["code"][0]

        token_kwargs = {
            "grant_type": "authorization_code",
            "code": our_code,
            "redirect_uri": _CLIENT_REDIRECT_URI,
            "code_verifier": code_verifier,
            "client_id": client_id,
        }
        first = await client.post("/oauth/token", data=token_kwargs)
        assert first.status_code == 200

        second = await client.post("/oauth/token", data=token_kwargs)
        assert second.status_code == 400
        assert second.json()["error"] == "invalid_grant"

    @pytest.mark.anyio
    async def test_hd_mismatch_at_callback_returns_html_403_and_logs_workspace_code(
        self, client, fake_store, monkeypatch, caplog
    ):
        client_id = await _register_client(client)
        _verifier, code_challenge = _pkce_pair()

        await client.get(
            "/oauth/authorize",
            params={
                "client_id": client_id,
                "redirect_uri": _CLIENT_REDIRECT_URI,
                "response_type": "code",
                "state": "s",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            },
        )
        (txn_id, _), = fake_store.transactions.items()

        priv = _generate_rsa_key()
        # Personal Gmail identity — no Workspace hd claim.
        id_token = _make_token(priv, "kid-1", audience="x", hd=None)
        with monkeypatch.context() as m:
            m.setattr(
                "app.google_auth.requests.post",
                lambda *a, **k: _mock_google_token_response(id_token),
            )
            with caplog.at_level(logging.WARNING, logger="app.oauth_server"):
                resp = await client.get(
                    "/oauth/callback", params={"state": txn_id, "code": "gcode"}
                )

        assert resp.status_code == 403
        assert "text/html" in resp.headers["content-type"]
        assert "example.com" in resp.text
        assert any("workspace_identity_required" in r.message for r in caplog.records)
        assert txn_id not in fake_store.transactions

    @pytest.mark.anyio
    async def test_abandoned_flow_creates_no_orphaned_refresh_token(
        self, client, fake_store, monkeypatch
    ):
        """Google can return a refresh_token at /oauth/callback, but if the
        MCP client never completes the /oauth/token exchange (e.g. abandons
        the flow), no oauth_refresh_tokens document should be created --
        minting only happens after store.consume_code succeeds.
        """
        client_id = await _register_client(client)
        _verifier, code_challenge = _pkce_pair()

        await client.get(
            "/oauth/authorize",
            params={
                "client_id": client_id,
                "redirect_uri": _CLIENT_REDIRECT_URI,
                "response_type": "code",
                "state": "s",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            },
        )
        (txn_id, _), = fake_store.transactions.items()

        priv = _generate_rsa_key()
        id_token = _make_token(priv, "kid-1", audience="x", hd="example.com")
        with monkeypatch.context() as m:
            m.setattr(
                "app.google_auth.requests.post",
                lambda *a, **k: _mock_google_token_response(
                    id_token, refresh_token="1//mock-google-refresh-token"
                ),
            )
            resp = await client.get("/oauth/callback", params={"state": txn_id, "code": "gcode"})
        assert resp.status_code == 302
        # Client never calls /oauth/token — flow abandoned here.
        assert fake_store.refresh_tokens == {}


# ---------------------------------------------------------------------------
# grant_type=refresh_token: silent re-auth without browser interaction
# ---------------------------------------------------------------------------


class TestRefreshTokenGrant:
    @pytest.mark.anyio
    async def test_refresh_round_trip_issues_fresh_access_token(
        self, client, fake_store, monkeypatch
    ):
        refresh_token = await _login_and_get_refresh_token(client, fake_store, monkeypatch)

        priv = _generate_rsa_key()
        fresh_id_token = _make_token(priv, "kid-2", audience="x", hd="example.com")
        with monkeypatch.context() as m:
            m.setattr(
                "app.google_auth.requests.post",
                lambda *a, **k: _mock_google_token_response(fresh_id_token),
            )
            resp = await client.post(
                "/oauth/token",
                data={"grant_type": "refresh_token", "refresh_token": refresh_token},
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["access_token"] == fresh_id_token
        assert body["token_type"] == "Bearer"
        assert "expires_in" in body
        # A new refresh_token is minted on every refresh (token rotation per OAuth 2.1).
        assert "refresh_token" in body
        new_refresh_token = body["refresh_token"]
        assert new_refresh_token != refresh_token
        # New token is stored; old token is still present (grace window) but will expire soon.
        assert new_refresh_token in fake_store.refresh_tokens
        assert refresh_token in fake_store.refresh_tokens

    @pytest.mark.anyio
    async def test_store_unavailable_returns_503_and_keeps_refresh_token(
        self, client, fake_store, monkeypatch
    ):
        refresh_token = await _login_and_get_refresh_token(client, fake_store, monkeypatch)

        async def _down(_token):
            raise oauth_server.StoreUnavailable("get_refresh_token")

        monkeypatch.setattr(fake_store, "get_refresh_token", _down)
        resp = await client.post(
            "/oauth/token",
            data={"grant_type": "refresh_token", "refresh_token": refresh_token},
        )
        assert resp.status_code == 503
        assert resp.json()["error"] == "temporarily_unavailable"
        assert resp.headers["retry-after"] == "2"
        assert refresh_token in fake_store.refresh_tokens

    @pytest.mark.anyio
    async def test_rotated_google_refresh_token_is_persisted(self, client, fake_store, monkeypatch):
        """Google doesn't always rotate the refresh token on exchange, but
        when it does, the stored value must be updated -- otherwise every
        subsequent silent refresh would fail with the stale secret.
        """
        refresh_token = await _login_and_get_refresh_token(client, fake_store, monkeypatch)
        original_google_refresh_token = fake_store.refresh_tokens[refresh_token]["google_refresh_token"]

        priv = _generate_rsa_key()
        fresh_id_token = _make_token(priv, "kid-2", audience="x", hd="example.com")
        rotated_google_refresh_token = "1//rotated-google-refresh-token"
        with monkeypatch.context() as m:
            m.setattr(
                "app.google_auth.requests.post",
                lambda *a, **k: _mock_google_token_response(
                    fresh_id_token, refresh_token=rotated_google_refresh_token
                ),
            )
            resp = await client.post(
                "/oauth/token",
                data={"grant_type": "refresh_token", "refresh_token": refresh_token},
            )
        assert resp.status_code == 200, resp.text
        # Our server-issued refresh token is rotated; look up the new one from the response.
        new_refresh_token = resp.json()["refresh_token"]
        stored = fake_store.refresh_tokens[new_refresh_token]
        assert stored["google_refresh_token"] == rotated_google_refresh_token
        assert stored["google_refresh_token"] != original_google_refresh_token

    @pytest.mark.anyio
    async def test_revoke_racing_refresh_does_not_500(self, client, fake_store, monkeypatch):
        """A concurrent /oauth/revoke landing between our read of the refresh
        record and the post-exchange save-new/expire-old writes must not turn an
        already-successful Google exchange into a 500 for the caller.
        """
        refresh_token = await _login_and_get_refresh_token(client, fake_store, monkeypatch)

        priv = _generate_rsa_key()
        fresh_id_token = _make_token(priv, "kid-2", audience="x", hd="example.com")

        def _revoke_mid_flight(*a, **k):
            fake_store.refresh_tokens.pop(refresh_token, None)
            return _mock_google_token_response(
                fresh_id_token, refresh_token="1//rotated-during-race"
            )

        with monkeypatch.context() as m:
            m.setattr("app.google_auth.requests.post", _revoke_mid_flight)
            resp = await client.post(
                "/oauth/token",
                data={"grant_type": "refresh_token", "refresh_token": refresh_token},
            )
        assert resp.status_code == 200, resp.text
        assert resp.json()["access_token"] == fresh_id_token
        # A new refresh token was minted even though the old one was revoked mid-flight.
        new_refresh_token = resp.json()["refresh_token"]
        assert new_refresh_token in fake_store.refresh_tokens

    @pytest.mark.anyio
    async def test_unknown_refresh_token_returns_400_invalid_grant(self, client, fake_store):
        resp = await client.post(
            "/oauth/token",
            data={"grant_type": "refresh_token", "refresh_token": "garbage-token-value"},
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_grant"

    @pytest.mark.anyio
    async def test_expired_refresh_token_returns_400_invalid_grant(self, client, fake_store):
        fake_store.refresh_tokens["expired-token"] = {
            "client_id": "some-client",
            "google_refresh_token": "1//expired",
            "created_at": time.time() - 1000,
            "expires_at": time.time() - 1,
        }
        resp = await client.post(
            "/oauth/token",
            data={"grant_type": "refresh_token", "refresh_token": "expired-token"},
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_grant"

    @pytest.mark.anyio
    async def test_revoked_refresh_token_rejected_on_next_refresh(
        self, client, fake_store, monkeypatch
    ):
        refresh_token = await _login_and_get_refresh_token(client, fake_store, monkeypatch)

        priv = _generate_rsa_key()
        fresh_id_token = _make_token(priv, "kid-2", audience="x", hd="example.com")
        with monkeypatch.context() as m:
            m.setattr(
                "app.google_auth.requests.post",
                lambda *a, **k: _mock_google_token_response(fresh_id_token),
            )
            first = await client.post(
                "/oauth/token",
                data={"grant_type": "refresh_token", "refresh_token": refresh_token},
            )
        assert first.status_code == 200

        revoke_resp = await client.post("/oauth/revoke", data={"token": refresh_token})
        assert revoke_resp.status_code == 200

        with monkeypatch.context() as m:
            m.setattr(
                "app.google_auth.requests.post",
                lambda *a, **k: _mock_google_token_response(fresh_id_token),
            )
            second = await client.post(
                "/oauth/token",
                data={"grant_type": "refresh_token", "refresh_token": refresh_token},
            )
        assert second.status_code == 400
        assert second.json()["error"] == "invalid_grant"

    @pytest.mark.anyio
    async def test_refresh_with_hd_mismatch_is_rejected(self, client, fake_store, monkeypatch, caplog):
        refresh_token = await _login_and_get_refresh_token(client, fake_store, monkeypatch)

        priv = _generate_rsa_key()
        # Account has since left the Workspace domain (or is a personal Gmail).
        wrong_domain_id_token = _make_token(priv, "kid-2", audience="x", hd="not-example.com")
        with monkeypatch.context() as m:
            m.setattr(
                "app.google_auth.requests.post",
                lambda *a, **k: _mock_google_token_response(wrong_domain_id_token),
            )
            with caplog.at_level(logging.WARNING, logger="app.oauth_server"):
                resp = await client.post(
                    "/oauth/token",
                    data={"grant_type": "refresh_token", "refresh_token": refresh_token},
                )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_grant"
        assert "application/json" in resp.headers["content-type"]
        assert any("workspace_identity_required" in r.message for r in caplog.records)
        # Dead record is cleaned up when hd mismatch occurs (deprovisioned user).
        assert refresh_token not in fake_store.refresh_tokens

    @pytest.mark.anyio
    async def test_missing_refresh_token_field_returns_400_invalid_request(self, client, fake_store):
        resp = await client.post("/oauth/token", data={"grant_type": "refresh_token"})
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_request"

    @pytest.mark.anyio
    async def test_google_error_on_refresh_returns_400_invalid_grant(
        self, client, fake_store, monkeypatch
    ):
        refresh_token = await _login_and_get_refresh_token(client, fake_store, monkeypatch)

        error_resp = MagicMock()
        error_resp.ok = False
        error_resp.status_code = 400
        error_resp.json.return_value = {
            "error": "invalid_grant",
            "error_description": "Token has been expired or revoked.",
        }
        with monkeypatch.context() as m:
            m.setattr("app.google_auth.requests.post", lambda *a, **k: error_resp)
            resp = await client.post(
                "/oauth/token",
                data={"grant_type": "refresh_token", "refresh_token": refresh_token},
            )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_grant"
        # Dead record is cleaned up (not kept for full TTL).
        assert refresh_token not in fake_store.refresh_tokens

    @pytest.mark.anyio
    async def test_transient_error_on_refresh_returns_503_and_keeps_token(
        self, client, fake_store, monkeypatch
    ):
        """Transient failures (network, 5xx, non-JSON response) must NOT delete
        the refresh token record, so the client can retry silently.
        """
        refresh_token = await _login_and_get_refresh_token(client, fake_store, monkeypatch)

        def _network_error(*a, **k):
            import requests

            raise requests.RequestException("Network timeout")

        with monkeypatch.context() as m:
            m.setattr("app.google_auth.requests.post", _network_error)
            resp = await client.post(
                "/oauth/token",
                data={"grant_type": "refresh_token", "refresh_token": refresh_token},
            )
        assert resp.status_code == 503
        assert resp.json()["error"] == "temporarily_unavailable"
        # Record is still present and usable for retry.
        assert refresh_token in fake_store.refresh_tokens

    @pytest.mark.anyio
    async def test_preserved_expiry_across_token_rotation(
        self, client, fake_store, monkeypatch
    ):
        """Token rotation must preserve the original login's expiry, not reset
        the TTL clock to a fresh 90 days.
        """
        refresh_token = await _login_and_get_refresh_token(client, fake_store, monkeypatch)
        original_record = fake_store.refresh_tokens[refresh_token]
        original_expires_at = original_record["expires_at"]

        priv = _generate_rsa_key()
        fresh_id_token = _make_token(priv, "kid-2", audience="x", hd="example.com")
        with monkeypatch.context() as m:
            m.setattr(
                "app.google_auth.requests.post",
                lambda *a, **k: _mock_google_token_response(fresh_id_token),
            )
            resp = await client.post(
                "/oauth/token",
                data={"grant_type": "refresh_token", "refresh_token": refresh_token},
            )
        assert resp.status_code == 200, resp.text
        new_refresh_token = resp.json()["refresh_token"]
        new_record = fake_store.refresh_tokens[new_refresh_token]
        assert new_record["expires_at"] == original_expires_at

    @pytest.mark.anyio
    async def test_preserved_expiry_across_multiple_rotations(
        self, client, fake_store, monkeypatch
    ):
        """Lineage expiry must survive multiple token rotations, not collapse
        on the second rotation due to grace-window shortening.
        """
        refresh_token_1 = await _login_and_get_refresh_token(client, fake_store, monkeypatch)
        original_record = fake_store.refresh_tokens[refresh_token_1]
        original_expires_at = original_record["expires_at"]

        priv = _generate_rsa_key()
        fresh_id_token_1 = _make_token(priv, "kid-2", audience="x", hd="example.com")
        with monkeypatch.context() as m:
            m.setattr(
                "app.google_auth.requests.post",
                lambda *a, **k: _mock_google_token_response(fresh_id_token_1),
            )
            resp = await client.post(
                "/oauth/token",
                data={"grant_type": "refresh_token", "refresh_token": refresh_token_1},
            )
        assert resp.status_code == 200, resp.text
        refresh_token_2 = resp.json()["refresh_token"]

        fresh_id_token_2 = _make_token(priv, "kid-3", audience="x", hd="example.com")
        with monkeypatch.context() as m:
            m.setattr(
                "app.google_auth.requests.post",
                lambda *a, **k: _mock_google_token_response(fresh_id_token_2),
            )
            resp = await client.post(
                "/oauth/token",
                data={"grant_type": "refresh_token", "refresh_token": refresh_token_2},
            )
        assert resp.status_code == 200, resp.text
        refresh_token_3 = resp.json()["refresh_token"]
        final_record = fake_store.refresh_tokens[refresh_token_3]
        assert final_record["expires_at"] == original_expires_at

    @pytest.mark.anyio
    async def test_google_503_with_json_body_is_transient_keeps_token(
        self, client, fake_store, monkeypatch
    ):
        """A Google 503 (or other 5xx) with a JSON error body must be treated
        as transient, not terminal, so the token is kept for retry (not deleted).
        """
        refresh_token = await _login_and_get_refresh_token(client, fake_store, monkeypatch)

        error_resp = MagicMock()
        error_resp.ok = False
        error_resp.status_code = 503
        error_resp.json.return_value = {
            "error": "server_error",
            "error_description": "Google temporarily unavailable.",
        }
        with monkeypatch.context() as m:
            m.setattr("app.google_auth.requests.post", lambda *a, **k: error_resp)
            resp = await client.post(
                "/oauth/token",
                data={"grant_type": "refresh_token", "refresh_token": refresh_token},
            )

        assert resp.status_code == 503, resp.text
        assert resp.json()["error"] == "temporarily_unavailable"
        assert refresh_token in fake_store.refresh_tokens

    @pytest.mark.anyio
    async def test_google_200_with_error_body_is_terminal_deletes_token(
        self, client, fake_store, monkeypatch
    ):
        """Google's token endpoint is expected to use 4xx for errors (RFC 6749
        §5.2), but the codebase already defends elsewhere (exchange_code_for_tokens)
        against a 2xx response that still carries a structured "error" body. That
        case must be treated as terminal (delete + 400), not transient (503).
        """
        refresh_token = await _login_and_get_refresh_token(client, fake_store, monkeypatch)

        error_resp = MagicMock()
        error_resp.ok = True
        error_resp.status_code = 200
        error_resp.json.return_value = {
            "error": "invalid_grant",
            "error_description": "Token has been expired or revoked.",
        }
        with monkeypatch.context() as m:
            m.setattr("app.google_auth.requests.post", lambda *a, **k: error_resp)
            resp = await client.post(
                "/oauth/token",
                data={"grant_type": "refresh_token", "refresh_token": refresh_token},
            )

        assert resp.status_code == 400, resp.text
        assert resp.json()["error"] == "invalid_grant"
        assert refresh_token not in fake_store.refresh_tokens


# ---------------------------------------------------------------------------
# /oauth/revoke (RFC 7009-shaped) -- the explicit "kill switch"
# ---------------------------------------------------------------------------


class TestRevoke:
    @pytest.mark.anyio
    async def test_revoke_unknown_token_still_returns_200(self, client, fake_store):
        resp = await client.post("/oauth/revoke", data={"token": "never-issued-token"})
        assert resp.status_code == 200

    @pytest.mark.anyio
    async def test_revoke_known_token_removes_it_from_store(self, client, fake_store, monkeypatch):
        refresh_token = await _login_and_get_refresh_token(client, fake_store, monkeypatch)
        assert refresh_token in fake_store.refresh_tokens

        resp = await client.post("/oauth/revoke", data={"token": refresh_token})
        assert resp.status_code == 200
        assert refresh_token not in fake_store.refresh_tokens

    @pytest.mark.anyio
    async def test_revoke_calls_google_upstream(self, client, fake_store, monkeypatch):
        """Verify that revoke calls Google's revoke endpoint with the stored
        Google refresh token, not just deletes the local record.
        """
        refresh_token = await _login_and_get_refresh_token(client, fake_store, monkeypatch)
        stored = fake_store.refresh_tokens[refresh_token]
        google_refresh_token = stored["google_refresh_token"]

        revoke_calls = []

        def mock_revoke(*args, **kwargs):
            revoke_calls.append((args, kwargs))
            resp = MagicMock()
            resp.ok = True
            return resp

        with monkeypatch.context() as m:
            m.setattr("app.google_auth.requests.post", mock_revoke)
            resp = await client.post("/oauth/revoke", data={"token": refresh_token})

        assert resp.status_code == 200
        assert refresh_token not in fake_store.refresh_tokens
        assert len(revoke_calls) == 1
        call_args, call_kwargs = revoke_calls[0]
        assert call_kwargs.get("data", {}).get("token") == google_refresh_token

    @pytest.mark.anyio
    async def test_revoke_reaches_google_even_for_locally_expired_token(
        self, client, fake_store, monkeypatch
    ):
        """A refresh-token document can be locally expired (grace window
        elapsed, or pending the ~24h native TTL sweep) while still physically
        present in Firestore. Revocation is a "kill switch" and must still
        reach Google's revoke endpoint in that case.
        """
        refresh_token = await _login_and_get_refresh_token(client, fake_store, monkeypatch)
        google_refresh_token = fake_store.refresh_tokens[refresh_token]["google_refresh_token"]
        fake_store.refresh_tokens[refresh_token]["expires_at"] = time.time() - 1
        assert await fake_store.get_refresh_token(refresh_token) is None

        revoke_calls = []

        def mock_revoke(*args, **kwargs):
            revoke_calls.append((args, kwargs))
            resp = MagicMock()
            resp.ok = True
            return resp

        with monkeypatch.context() as m:
            m.setattr("app.google_auth.requests.post", mock_revoke)
            resp = await client.post("/oauth/revoke", data={"token": refresh_token})

        assert resp.status_code == 200
        assert refresh_token not in fake_store.refresh_tokens
        assert len(revoke_calls) == 1
        call_args, call_kwargs = revoke_calls[0]
        assert call_kwargs.get("data", {}).get("token") == google_refresh_token


# ---------------------------------------------------------------------------
# Auth-bypass regression: none of the new routes should be JWT-gated
# ---------------------------------------------------------------------------


class TestOAuthRoutesAuthBypass:
    """A 401 on any of these would mean RequireAuthMiddleware intercepted the
    route -- these must all be pre-auth.
    """

    @pytest.mark.anyio
    async def test_well_known_routes_not_401(self, client):
        for path in (
            "/.well-known/oauth-protected-resource/mcp",
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-authorization-server",
        ):
            resp = await client.get(path)
            assert resp.status_code != 401, f"{path} returned 401 — JWT auth intercepted it"

    @pytest.mark.anyio
    async def test_register_not_401(self, client):
        resp = await client.post("/oauth/register", json={"redirect_uris": [_CLIENT_REDIRECT_URI]})
        assert resp.status_code != 401

    @pytest.mark.anyio
    async def test_authorize_not_401(self, client):
        resp = await client.get("/oauth/authorize", params={"client_id": "nonexistent"})
        assert resp.status_code != 401

    @pytest.mark.anyio
    async def test_callback_not_401(self, client):
        resp = await client.get("/oauth/callback", params={"state": "nonexistent"})
        assert resp.status_code != 401

    @pytest.mark.anyio
    async def test_token_not_401(self, client):
        resp = await client.post(
            "/oauth/token",
            data={"grant_type": "authorization_code", "code": "nonexistent"},
        )
        assert resp.status_code != 401

    @pytest.mark.anyio
    async def test_revoke_not_401(self, client):
        resp = await client.post("/oauth/revoke", data={"token": "nonexistent"})
        assert resp.status_code != 401
