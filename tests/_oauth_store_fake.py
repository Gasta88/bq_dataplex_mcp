"""In-memory fake for app.oauth_store.

Exposes the same async function signatures as `app.oauth_store`, so it can be
monkeypatched in as `app.oauth_server.store` without real Firestore/ADC
credentials.
"""

import time
from typing import Any


class FakeOAuthStore:
    def __init__(self) -> None:
        self.clients: dict[str, dict[str, Any]] = {}
        self.transactions: dict[str, dict[str, Any]] = {}
        self.codes: dict[str, dict[str, Any]] = {}
        self.refresh_tokens: dict[str, dict[str, Any]] = {}

    @staticmethod
    def _not_expired(doc: dict[str, Any]) -> bool:
        return doc.get("expires_at", 0) > time.time()

    async def save_client(
        self, client_id: str, *, redirect_uris: list[str], client_name: str | None, ttl_seconds: int
    ) -> None:
        now = time.time()
        self.clients[client_id] = {
            "redirect_uris": redirect_uris,
            "client_name": client_name,
            "created_at": now,
            "expires_at": now + ttl_seconds,
        }

    async def get_client(self, client_id: str) -> dict[str, Any] | None:
        doc = self.clients.get(client_id)
        if doc is None or not self._not_expired(doc):
            return None
        return doc

    async def save_transaction(
        self,
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
        self.transactions[txn_id] = {
            "client_id": client_id,
            "client_redirect_uri": client_redirect_uri,
            "client_state": client_state,
            "code_challenge": code_challenge,
            "google_code_verifier": google_code_verifier,
            "created_at": now,
            "expires_at": now + ttl_seconds,
        }

    async def get_transaction(self, txn_id: str) -> dict[str, Any] | None:
        doc = self.transactions.get(txn_id)
        if doc is None or not self._not_expired(doc):
            return None
        return doc

    async def delete_transaction(self, txn_id: str) -> None:
        self.transactions.pop(txn_id, None)

    async def save_code(
        self,
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
        self.codes[code] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "id_token": id_token,
            "expires_in": expires_in,
            "google_refresh_token": google_refresh_token,
            "created_at": now,
            "expires_at": now + ttl_seconds,
        }

    async def consume_code(self, code: str) -> dict[str, Any] | None:
        doc = self.codes.get(code)
        if doc is None or not self._not_expired(doc):
            return None
        del self.codes[code]
        return doc

    async def save_refresh_token(
        self,
        refresh_token: str,
        *,
        client_id: str,
        google_refresh_token: str,
        ttl_seconds: int,
        expires_at: float | None = None,
    ) -> None:
        now = time.time()
        resolved_expires_at = expires_at if expires_at is not None else now + ttl_seconds
        self.refresh_tokens[refresh_token] = {
            "client_id": client_id,
            "google_refresh_token": google_refresh_token,
            "created_at": now,
            "expires_at": resolved_expires_at,
            "lineage_expires_at": resolved_expires_at,
        }

    async def get_refresh_token(self, refresh_token: str) -> dict[str, Any] | None:
        doc = self.refresh_tokens.get(refresh_token)
        if doc is None or not self._not_expired(doc):
            return None
        return doc

    async def get_refresh_token_for_revoke(self, refresh_token: str) -> dict[str, Any] | None:
        return self.refresh_tokens.get(refresh_token)

    async def delete_refresh_token(self, refresh_token: str) -> None:
        self.refresh_tokens.pop(refresh_token, None)

    async def expire_refresh_token_soon(
        self, refresh_token: str, grace_seconds: int = 30
    ) -> None:
        doc = self.refresh_tokens.get(refresh_token)
        if doc is not None:
            doc["expires_at"] = time.time() + grace_seconds
