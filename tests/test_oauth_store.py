"""Unit tests for app/oauth_store.py, the Firestore-backed OAuth state store.

Covers the lazy `firestore.AsyncClient` singleton, `_not_expired`, and each
collection's CRUD/TTL-rejection behavior against an in-memory fake of
`google.cloud.firestore.AsyncClient`, so no real Firestore credentials are
needed. This is a lower-level double than `tests/_oauth_store_fake.py`.
"""

from __future__ import annotations

import asyncio
import time

import pytest
from google.api_core.exceptions import NotFound, ServiceUnavailable

import app.oauth_store as oauth_store


class _FakeSnapshot:
    def __init__(self, data: dict | None) -> None:
        self._data = data

    @property
    def exists(self) -> bool:
        return self._data is not None

    def to_dict(self) -> dict | None:
        return self._data


class _FakeDocRef:
    def __init__(self, store: dict, key: str) -> None:
        self._store = store
        self._key = key

    async def get(self, transaction=None) -> _FakeSnapshot:
        return _FakeSnapshot(self._store.get(self._key))

    async def set(self, doc: dict) -> None:
        self._store[self._key] = dict(doc)

    async def delete(self) -> None:
        self._store.pop(self._key, None)

    async def update(self, fields: dict) -> None:
        if self._key not in self._store:
            raise NotFound("doc not found")
        self._store[self._key].update(fields)


class _FakeCollection:
    def __init__(self) -> None:
        self.docs: dict[str, dict] = {}

    def document(self, doc_id: str) -> _FakeDocRef:
        return _FakeDocRef(self.docs, doc_id)


class _FakeTransaction:
    def delete(self, doc_ref: _FakeDocRef) -> None:
        doc_ref._store.pop(doc_ref._key, None)


class _FakeFirestoreClient:
    """Stand-in for `google.cloud.firestore.AsyncClient`."""

    instances_created = 0

    def __init__(self, *args, **kwargs) -> None:
        _FakeFirestoreClient.instances_created += 1
        self.init_kwargs = kwargs
        self._collections: dict[str, _FakeCollection] = {}

    def collection(self, name: str) -> _FakeCollection:
        return self._collections.setdefault(name, _FakeCollection())

    def transaction(self) -> _FakeTransaction:
        return _FakeTransaction()


@pytest.fixture(autouse=True)
def _reset_lazy_client(monkeypatch):
    """Resets oauth_store's module-level lazy singleton and swaps the real
    `firestore.AsyncClient` for the fake, so `_get_client()`'s real
    construction logic (project/database kwargs) is exercised but never
    touches real Firestore/ADC.
    """
    monkeypatch.setattr(oauth_store, "_client", None)
    _FakeFirestoreClient.instances_created = 0
    monkeypatch.setattr(oauth_store.firestore, "AsyncClient", _FakeFirestoreClient)
    # Also patch async_transactional to an identity decorator -- the fake
    # transaction object above provides just enough surface (a synchronous
    # `.delete(doc_ref)`) for consume_code's transactional function body.
    monkeypatch.setattr(oauth_store.firestore, "async_transactional", lambda fn: fn)
    yield


def test_not_expired_true_for_future_expiry():
    assert oauth_store._not_expired({"expires_at": time.time() + 100})


def test_not_expired_false_for_past_expiry():
    assert not oauth_store._not_expired({"expires_at": time.time() - 100})


def test_not_expired_false_when_expires_at_missing():
    assert not oauth_store._not_expired({})


def test_get_client_is_a_lazy_singleton_constructed_once():
    first = oauth_store._get_client()
    second = oauth_store._get_client()
    assert first is second
    assert _FakeFirestoreClient.instances_created == 1


def test_get_client_passes_project_and_database_kwargs(monkeypatch):
    monkeypatch.setattr(oauth_store.settings, "gcp_project", "example-project")
    monkeypatch.setattr(oauth_store.settings, "firestore_database_id", "bq-dataplex-mcp-oauth")
    client = oauth_store._get_client()
    assert client.init_kwargs == {"project": "example-project", "database": "bq-dataplex-mcp-oauth"}


def test_get_client_defaults_database_to_default_string_when_unset(monkeypatch):
    monkeypatch.setattr(oauth_store.settings, "firestore_database_id", "")
    client = oauth_store._get_client()
    assert client.init_kwargs["database"] == "(default)"


class TestClientRegistration:
    @pytest.mark.anyio
    async def test_save_and_get_client_round_trip(self):
        await oauth_store.save_client(
            "client-1", redirect_uris=["https://a.example.com/cb"], client_name="Test", ttl_seconds=100
        )
        result = await oauth_store.get_client("client-1")
        assert result is not None
        assert result["redirect_uris"] == ["https://a.example.com/cb"]
        assert result["client_name"] == "Test"

    @pytest.mark.anyio
    async def test_get_client_returns_none_for_unknown_id(self):
        assert await oauth_store.get_client("nonexistent") is None

    @pytest.mark.anyio
    async def test_get_client_returns_none_when_expired(self):
        await oauth_store.save_client(
            "client-expired", redirect_uris=["https://a.example.com/cb"], client_name=None, ttl_seconds=-1
        )
        assert await oauth_store.get_client("client-expired") is None


class TestTransactions:
    @pytest.mark.anyio
    async def test_save_get_delete_transaction_round_trip(self):
        await oauth_store.save_transaction(
            "txn-1",
            client_id="c1",
            client_redirect_uri="https://a.example.com/cb",
            client_state="s1",
            code_challenge="chal",
            google_code_verifier="verifier",
            ttl_seconds=600,
        )
        txn = await oauth_store.get_transaction("txn-1")
        assert txn is not None
        assert txn["client_id"] == "c1"

        await oauth_store.delete_transaction("txn-1")
        assert await oauth_store.get_transaction("txn-1") is None

    @pytest.mark.anyio
    async def test_get_transaction_returns_none_when_expired(self):
        await oauth_store.save_transaction(
            "txn-expired",
            client_id="c1",
            client_redirect_uri="https://a.example.com/cb",
            client_state=None,
            code_challenge="chal",
            google_code_verifier="verifier",
            ttl_seconds=-1,
        )
        assert await oauth_store.get_transaction("txn-expired") is None


class TestCodes:
    @pytest.mark.anyio
    async def test_consume_code_is_single_use(self):
        await oauth_store.save_code(
            "code-1",
            client_id="c1",
            redirect_uri="https://a.example.com/cb",
            code_challenge="chal",
            id_token="idtok",
            expires_in=3599,
            ttl_seconds=60,
            google_refresh_token="grt",
        )
        first = await oauth_store.consume_code("code-1")
        assert first is not None
        assert first["id_token"] == "idtok"

        second = await oauth_store.consume_code("code-1")
        assert second is None

    @pytest.mark.anyio
    async def test_consume_code_returns_none_for_unknown_code(self):
        assert await oauth_store.consume_code("never-issued") is None

    @pytest.mark.anyio
    async def test_consume_code_returns_none_when_expired_and_does_not_delete_it(self):
        await oauth_store.save_code(
            "code-expired",
            client_id="c1",
            redirect_uri="https://a.example.com/cb",
            code_challenge="chal",
            id_token="idtok",
            expires_in=0,
            ttl_seconds=-1,
            google_refresh_token=None,
        )
        assert await oauth_store.consume_code("code-expired") is None


class TestRefreshTokens:
    @pytest.mark.anyio
    async def test_save_and_get_refresh_token_round_trip(self):
        await oauth_store.save_refresh_token(
            "rt-1", client_id="c1", google_refresh_token="grt", ttl_seconds=1000
        )
        record = await oauth_store.get_refresh_token("rt-1")
        assert record is not None
        assert record["google_refresh_token"] == "grt"
        assert record["lineage_expires_at"] == record["expires_at"]

    @pytest.mark.anyio
    async def test_save_refresh_token_preserves_explicit_expires_at(self):
        fixed_expiry = time.time() + 12345
        await oauth_store.save_refresh_token(
            "rt-lineage",
            client_id="c1",
            google_refresh_token="grt",
            ttl_seconds=1000,
            expires_at=fixed_expiry,
        )
        record = await oauth_store.get_refresh_token("rt-lineage")
        assert record["expires_at"] == fixed_expiry

    @pytest.mark.anyio
    async def test_get_refresh_token_returns_none_when_expired(self):
        await oauth_store.save_refresh_token(
            "rt-expired", client_id="c1", google_refresh_token="grt", ttl_seconds=-1
        )
        assert await oauth_store.get_refresh_token("rt-expired") is None

    @pytest.mark.anyio
    async def test_get_refresh_token_for_revoke_ignores_local_expiry(self):
        await oauth_store.save_refresh_token(
            "rt-expired-2", client_id="c1", google_refresh_token="grt", ttl_seconds=-1
        )
        # get_refresh_token treats it as absent...
        assert await oauth_store.get_refresh_token("rt-expired-2") is None
        # ...but get_refresh_token_for_revoke still finds it (kill-switch semantics).
        record = await oauth_store.get_refresh_token_for_revoke("rt-expired-2")
        assert record is not None
        assert record["google_refresh_token"] == "grt"

    @pytest.mark.anyio
    async def test_get_refresh_token_for_revoke_returns_none_for_unknown_token(self):
        assert await oauth_store.get_refresh_token_for_revoke("never-issued") is None

    @pytest.mark.anyio
    async def test_delete_refresh_token_removes_it(self):
        await oauth_store.save_refresh_token(
            "rt-delete", client_id="c1", google_refresh_token="grt", ttl_seconds=1000
        )
        await oauth_store.delete_refresh_token("rt-delete")
        assert await oauth_store.get_refresh_token("rt-delete") is None

    @pytest.mark.anyio
    async def test_expire_refresh_token_soon_shortens_expiry(self):
        await oauth_store.save_refresh_token(
            "rt-grace", client_id="c1", google_refresh_token="grt", ttl_seconds=90 * 24 * 3600
        )
        await oauth_store.expire_refresh_token_soon("rt-grace", grace_seconds=30)
        record = await oauth_store.get_refresh_token("rt-grace")
        assert record is not None
        assert record["expires_at"] <= time.time() + 31

    @pytest.mark.anyio
    async def test_expire_refresh_token_soon_swallows_not_found_for_already_deleted_token(self):
        # No exception raised even though the token was never saved.
        await oauth_store.expire_refresh_token_soon("never-existed", grace_seconds=30)


class TestBoundedCalls:
    @pytest.fixture(autouse=True)
    def _short_timeout(self, monkeypatch):
        monkeypatch.setattr(oauth_store.settings, "firestore_timeout_seconds", 0.05)

    @pytest.mark.anyio
    async def test_hung_get_raises_store_unavailable_within_budget(self, monkeypatch):
        async def _hang(self, transaction=None):
            await asyncio.sleep(30)

        monkeypatch.setattr(_FakeDocRef, "get", _hang)
        started = time.monotonic()
        with pytest.raises(oauth_store.StoreUnavailable):
            await oauth_store.get_refresh_token("rt-hang")
        assert time.monotonic() - started < 1

    @pytest.mark.anyio
    async def test_transient_error_is_retried_once_then_succeeds(self, monkeypatch):
        await oauth_store.save_refresh_token(
            "rt-retry", client_id="c1", google_refresh_token="grt", ttl_seconds=1000
        )
        real_get = _FakeDocRef.get
        calls = {"n": 0}

        async def _flaky(self, transaction=None):
            calls["n"] += 1
            if calls["n"] == 1:
                raise ServiceUnavailable("stream removed")
            return await real_get(self, transaction)

        monkeypatch.setattr(_FakeDocRef, "get", _flaky)
        record = await oauth_store.get_refresh_token("rt-retry")
        assert record is not None
        assert calls["n"] == 2

    @pytest.mark.anyio
    async def test_persistent_transient_error_raises_store_unavailable(self, monkeypatch):
        async def _always_down(self, transaction=None):
            raise ServiceUnavailable("down")

        monkeypatch.setattr(_FakeDocRef, "get", _always_down)
        with pytest.raises(oauth_store.StoreUnavailable):
            await oauth_store.get_refresh_token("rt-down")

    @pytest.mark.anyio
    async def test_consume_code_timeout_raises_and_does_not_consume(self, monkeypatch):
        await oauth_store.save_code(
            "code-1",
            client_id="c1",
            redirect_uri="https://x",
            code_challenge="cc",
            id_token="idt",
            expires_in=3600,
            ttl_seconds=600,
        )
        real_get = _FakeDocRef.get

        async def _hang(self, transaction=None):
            await asyncio.sleep(30)

        monkeypatch.setattr(_FakeDocRef, "get", _hang)
        with pytest.raises(oauth_store.StoreUnavailable):
            await oauth_store.consume_code("code-1")
        monkeypatch.setattr(_FakeDocRef, "get", real_get)
        assert await oauth_store.consume_code("code-1") is not None
