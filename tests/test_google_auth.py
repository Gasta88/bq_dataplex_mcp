"""Unit tests for app/google_auth.py: PKCE, authorization URL building, token
exchange, refresh, and error handling."""

from __future__ import annotations

import hashlib
import urllib.parse
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers to inject fake OAuth settings without touching process env permanently
# ---------------------------------------------------------------------------


def _patch_settings(client_id: str = "test-client-id", client_secret: str = "test-client-secret"):
    """Return a context manager that patches app.config.settings with fake OAuth creds."""
    return patch(
        "app.google_auth.settings",
        google_oauth_client_id=client_id,
        google_oauth_client_secret=client_secret,
    )


# ---------------------------------------------------------------------------
# OAuthError
# ---------------------------------------------------------------------------


class TestOAuthError:
    def test_is_exception(self):
        from app.google_auth import OAuthError

        err = OAuthError("boom", upstream_response={"error": "invalid_grant"})
        assert isinstance(err, Exception)
        assert str(err) == "boom"
        assert err.upstream_response == {"error": "invalid_grant"}

    def test_upstream_response_defaults_to_none(self):
        from app.google_auth import OAuthError

        err = OAuthError("simple error")
        assert err.upstream_response is None


# ---------------------------------------------------------------------------
# build_authorization_url
# ---------------------------------------------------------------------------


class TestBuildAuthorizationUrl:
    REDIRECT_URI = "https://bq-dataplex-mcp.example.com/oauth/callback"

    def test_returns_url_containing_accounts_google_com(self):
        from app.google_auth import build_authorization_url

        with _patch_settings():
            result = build_authorization_url(self.REDIRECT_URI)
        assert "accounts.google.com" in result["url"]

    def test_url_contains_client_id(self):
        from app.google_auth import build_authorization_url

        with _patch_settings(client_id="my-client-id-abc"):
            result = build_authorization_url(self.REDIRECT_URI)
        parsed = urllib.parse.urlparse(result["url"])
        qs = urllib.parse.parse_qs(parsed.query)
        assert qs["client_id"] == ["my-client-id-abc"]

    def test_url_contains_response_type_code(self):
        from app.google_auth import build_authorization_url

        with _patch_settings():
            result = build_authorization_url(self.REDIRECT_URI)
        parsed = urllib.parse.urlparse(result["url"])
        qs = urllib.parse.parse_qs(parsed.query)
        assert qs["response_type"] == ["code"]

    def test_url_contains_openid_and_email_scope(self):
        from app.google_auth import build_authorization_url

        with _patch_settings():
            result = build_authorization_url(self.REDIRECT_URI)
        parsed = urllib.parse.urlparse(result["url"])
        qs = urllib.parse.parse_qs(parsed.query)
        scopes = set(qs["scope"][0].split())
        assert "openid" in scopes
        assert "email" in scopes

    def test_url_contains_offline_access_type(self):
        from app.google_auth import build_authorization_url

        with _patch_settings():
            result = build_authorization_url(self.REDIRECT_URI)
        parsed = urllib.parse.urlparse(result["url"])
        qs = urllib.parse.parse_qs(parsed.query)
        assert qs["access_type"] == ["offline"]

    def test_url_contains_prompt_consent(self):
        from app.google_auth import build_authorization_url

        with _patch_settings():
            result = build_authorization_url(self.REDIRECT_URI)
        parsed = urllib.parse.urlparse(result["url"])
        qs = urllib.parse.parse_qs(parsed.query)
        assert qs["prompt"] == ["consent"]

    def test_url_contains_code_challenge_pkce(self):
        from app.google_auth import build_authorization_url

        with _patch_settings():
            result = build_authorization_url(self.REDIRECT_URI)
        parsed = urllib.parse.urlparse(result["url"])
        qs = urllib.parse.parse_qs(parsed.query)
        assert "code_challenge" in qs
        assert qs["code_challenge_method"] == ["S256"]

    def test_code_challenge_matches_verifier(self):
        """The S256 challenge must be sha256(verifier) base64url-encoded without padding."""
        import base64

        from app.google_auth import build_authorization_url

        with _patch_settings():
            result = build_authorization_url(self.REDIRECT_URI)
        verifier = result["code_verifier"]
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        expected_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        assert result["code_challenge"] == expected_challenge

    def test_state_is_returned(self):
        from app.google_auth import build_authorization_url

        with _patch_settings():
            result = build_authorization_url(self.REDIRECT_URI, state="my-csrf-token")
        assert result["state"] == "my-csrf-token"

    def test_auto_generated_state_when_none(self):
        from app.google_auth import build_authorization_url

        with _patch_settings():
            result = build_authorization_url(self.REDIRECT_URI)
        assert result["state"]  # non-empty
        assert isinstance(result["state"], str)

    def test_caller_supplied_code_verifier_is_used(self):
        from app.google_auth import build_authorization_url

        verifier = "a" * 43  # minimum length per RFC 7636
        with _patch_settings():
            result = build_authorization_url(self.REDIRECT_URI, code_verifier=verifier)
        assert result["code_verifier"] == verifier

    def test_raises_oauth_error_when_client_id_missing(self):
        from app.google_auth import OAuthError, build_authorization_url

        with _patch_settings(client_id=""):
            with pytest.raises(OAuthError, match="GOOGLE_OAUTH_CLIENT_ID"):
                build_authorization_url(self.REDIRECT_URI)

    def test_raises_oauth_error_when_client_secret_missing(self):
        """Client secret is required by _require_oauth_config even for URL building."""
        from app.google_auth import OAuthError, build_authorization_url

        with _patch_settings(client_secret=""):
            with pytest.raises(OAuthError, match="GOOGLE_OAUTH_CLIENT_SECRET"):
                build_authorization_url(self.REDIRECT_URI)


# ---------------------------------------------------------------------------
# exchange_code_for_tokens
# ---------------------------------------------------------------------------


class TestExchangeCodeForTokens:
    REDIRECT_URI = "https://bq-dataplex-mcp.example.com/oauth/callback"
    CODE = "4/0Ab_abc123"
    VERIFIER = "test-code-verifier-string"

    def _mock_success_response(self, extra: dict | None = None) -> MagicMock:
        body = {
            "access_token": "ya29.mock-access-token",
            "id_token": "eyJhbGciOiJSUzI1NiJ9.mock",
            "token_type": "Bearer",
            "expires_in": 3599,
        }
        if extra:
            body.update(extra)
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = body
        return mock_resp

    def _mock_error_response(self, status: int = 400, body: dict | None = None) -> MagicMock:
        default_body = {"error": "invalid_grant", "error_description": "Code was already redeemed."}
        mock_resp = MagicMock()
        mock_resp.ok = False
        mock_resp.status_code = status
        mock_resp.json.return_value = body or default_body
        return mock_resp

    def test_returns_dict_with_access_token_and_id_token(self):
        from app.google_auth import exchange_code_for_tokens

        with _patch_settings():
            with patch("app.google_auth.requests.post", return_value=self._mock_success_response()):
                result = exchange_code_for_tokens(self.CODE, self.REDIRECT_URI, self.VERIFIER)
        assert "access_token" in result
        assert "id_token" in result

    def test_access_token_value_matches_upstream(self):
        from app.google_auth import exchange_code_for_tokens

        with _patch_settings():
            with patch("app.google_auth.requests.post", return_value=self._mock_success_response()):
                result = exchange_code_for_tokens(self.CODE, self.REDIRECT_URI, self.VERIFIER)
        assert result["access_token"] == "ya29.mock-access-token"

    def test_raises_oauth_error_on_upstream_error_response(self):
        from app.google_auth import OAuthError, exchange_code_for_tokens

        with _patch_settings():
            with patch("app.google_auth.requests.post", return_value=self._mock_error_response()):
                with pytest.raises(OAuthError) as exc_info:
                    exchange_code_for_tokens(self.CODE, self.REDIRECT_URI, self.VERIFIER)
        assert exc_info.value.upstream_response is not None
        assert "invalid_grant" in str(exc_info.value)

    def test_raises_oauth_error_error_key_in_otherwise_ok_response(self):
        """Google can return HTTP 200 with an 'error' key on certain failures."""
        from app.google_auth import OAuthError, exchange_code_for_tokens

        body_with_error = {"error": "invalid_client", "error_description": "The OAuth client was not found."}
        mock_resp = MagicMock()
        mock_resp.ok = True  # HTTP 200 but has error key
        mock_resp.json.return_value = body_with_error
        with _patch_settings():
            with patch("app.google_auth.requests.post", return_value=mock_resp):
                with pytest.raises(OAuthError, match="invalid_client"):
                    exchange_code_for_tokens(self.CODE, self.REDIRECT_URI, self.VERIFIER)

    def test_raises_oauth_error_when_client_not_configured(self):
        from app.google_auth import OAuthError, exchange_code_for_tokens

        with _patch_settings(client_id=""):
            with pytest.raises(OAuthError, match="GOOGLE_OAUTH_CLIENT_ID"):
                exchange_code_for_tokens(self.CODE, self.REDIRECT_URI, self.VERIFIER)

    def test_raises_oauth_error_on_network_failure(self):
        import requests as req_lib

        from app.google_auth import OAuthError, exchange_code_for_tokens

        with _patch_settings():
            with patch("app.google_auth.requests.post", side_effect=req_lib.RequestException("timeout")):
                with pytest.raises(OAuthError, match="Token endpoint request failed"):
                    exchange_code_for_tokens(self.CODE, self.REDIRECT_URI, self.VERIFIER)

    def test_raises_oauth_error_when_tokens_missing_from_response(self):
        """If access_token or id_token is absent the function must raise rather than return partial data."""
        from app.google_auth import OAuthError, exchange_code_for_tokens

        incomplete_body = {"token_type": "Bearer", "expires_in": 3599}  # no access_token, no id_token
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = incomplete_body
        with _patch_settings():
            with patch("app.google_auth.requests.post", return_value=mock_resp):
                with pytest.raises(OAuthError, match="missing expected keys"):
                    exchange_code_for_tokens(self.CODE, self.REDIRECT_URI, self.VERIFIER)

    def test_redirect_uri_mismatch_propagated(self):
        """A redirect_uri_mismatch error from Google must be surfaced, not swallowed."""
        from app.google_auth import OAuthError, exchange_code_for_tokens

        error_body = {
            "error": "redirect_uri_mismatch",
            "error_description": "The redirect URI in the request did not match a registered redirect URI.",
        }
        mock_resp = MagicMock()
        mock_resp.ok = False
        mock_resp.status_code = 400
        mock_resp.json.return_value = error_body
        with _patch_settings():
            with patch("app.google_auth.requests.post", return_value=mock_resp):
                with pytest.raises(OAuthError, match="redirect_uri_mismatch"):
                    exchange_code_for_tokens(self.CODE, self.REDIRECT_URI, self.VERIFIER)


# ---------------------------------------------------------------------------
# exchange_refresh_token_for_tokens
# ---------------------------------------------------------------------------


class TestExchangeRefreshTokenForTokens:
    REFRESH_TOKEN = "1//mock-google-refresh-token"

    def _mock_success_response(self, extra: dict | None = None) -> MagicMock:
        body = {
            "access_token": "ya29.mock-access-token",
            "id_token": "eyJhbGciOiJSUzI1NiJ9.mock",
            "token_type": "Bearer",
            "expires_in": 3599,
        }
        if extra:
            body.update(extra)
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = body
        return mock_resp

    def test_returns_dict_with_id_token(self):
        from app.google_auth import exchange_refresh_token_for_tokens

        with _patch_settings():
            with patch("app.google_auth.requests.post", return_value=self._mock_success_response()):
                result = exchange_refresh_token_for_tokens(self.REFRESH_TOKEN)
        assert "id_token" in result

    def test_sends_refresh_token_grant_with_expected_params(self):
        from app.google_auth import exchange_refresh_token_for_tokens

        with _patch_settings(client_id="my-client-id", client_secret="my-client-secret"):
            with patch(
                "app.google_auth.requests.post", return_value=self._mock_success_response()
            ) as mock_post:
                exchange_refresh_token_for_tokens(self.REFRESH_TOKEN)
        _, kwargs = mock_post.call_args
        sent = kwargs["data"]
        assert sent["grant_type"] == "refresh_token"
        assert sent["refresh_token"] == self.REFRESH_TOKEN
        assert sent["client_id"] == "my-client-id"
        assert sent["client_secret"] == "my-client-secret"

    def test_raises_oauth_error_on_upstream_error_response(self):
        from app.google_auth import OAuthError, exchange_refresh_token_for_tokens

        mock_resp = MagicMock()
        mock_resp.ok = False
        mock_resp.status_code = 400
        mock_resp.json.return_value = {
            "error": "invalid_grant",
            "error_description": "Token has been expired or revoked.",
        }
        with _patch_settings():
            with patch("app.google_auth.requests.post", return_value=mock_resp):
                with pytest.raises(OAuthError, match="invalid_grant") as excinfo:
                    exchange_refresh_token_for_tokens(self.REFRESH_TOKEN)
        assert excinfo.value.status_code == 400

    def test_error_key_in_otherwise_ok_response_synthesizes_terminal_status_code(self):
        """Google can return HTTP 200 with an 'error' key (defended against
        elsewhere for exchange_code_for_tokens). The raised OAuthError must
        carry a 4xx-class status_code so callers classifying terminal vs.
        transient refresh failures treat this as a definitive rejection,
        not a transient one that gets retried forever.
        """
        from app.google_auth import OAuthError, exchange_refresh_token_for_tokens

        mock_resp = MagicMock()
        mock_resp.ok = True  # HTTP 200 but has an error key
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "error": "invalid_grant",
            "error_description": "Token has been expired or revoked.",
        }
        with _patch_settings():
            with patch("app.google_auth.requests.post", return_value=mock_resp):
                with pytest.raises(OAuthError, match="invalid_grant") as excinfo:
                    exchange_refresh_token_for_tokens(self.REFRESH_TOKEN)
        assert excinfo.value.status_code == 400

    def test_raises_oauth_error_when_id_token_missing_from_response(self):
        from app.google_auth import OAuthError, exchange_refresh_token_for_tokens

        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = {"access_token": "ya29.x", "token_type": "Bearer"}
        with _patch_settings():
            with patch("app.google_auth.requests.post", return_value=mock_resp):
                with pytest.raises(OAuthError, match="missing expected key"):
                    exchange_refresh_token_for_tokens(self.REFRESH_TOKEN)

    def test_raises_oauth_error_when_client_not_configured(self):
        from app.google_auth import OAuthError, exchange_refresh_token_for_tokens

        with _patch_settings(client_id=""):
            with pytest.raises(OAuthError, match="GOOGLE_OAUTH_CLIENT_ID"):
                exchange_refresh_token_for_tokens(self.REFRESH_TOKEN)

    def test_raises_oauth_error_on_network_failure(self):
        import requests as req_lib

        from app.google_auth import OAuthError, exchange_refresh_token_for_tokens

        with _patch_settings():
            with patch("app.google_auth.requests.post", side_effect=req_lib.RequestException("timeout")):
                with pytest.raises(OAuthError, match="Refresh token endpoint request failed"):
                    exchange_refresh_token_for_tokens(self.REFRESH_TOKEN)
