"""Unit tests for `app.rejection_log.McpRejectionLogger`.

ASGI-level, no server. Real-HTTP coverage lives in
`tests/test_mcp_protocol_versions.py`, whose fixture mirrors `main()`'s wiring.
"""

import json
import logging

import pytest

from app.rejection_log import LOG_SENTINEL, McpRejectionLogger

_LOGGER = "app.rejection_log"
_SECRET_TOKEN = "eyJ.super-secret-token.sig"
_REQUEST_BODY_MARKER = "request-body-marker-do-not-log"


def _scope(
    path: str = "/mcp",
    method: str = "POST",
    headers: list[tuple[bytes, bytes]] | None = None,
    query: bytes = b"",
    scope_type: str = "http",
) -> dict:
    return {
        "type": scope_type,
        "path": path,
        "method": method,
        "query_string": query,
        "headers": headers
        or [
            (b"user-agent", b"claude-test/1.0"),
            (b"mcp-protocol-version", b"2026-07-28"),
            (b"authorization", f"Bearer {_SECRET_TOKEN}".encode()),
        ],
    }


def _responder(status: int, body: bytes = b"", chunk_size: int | None = None):
    chunks = [body] if chunk_size is None else [body[i : i + chunk_size] for i in range(0, len(body), chunk_size)]

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": status, "headers": []})
        if not chunks:
            await send({"type": "http.response.body", "body": b"", "more_body": False})
        for index, chunk in enumerate(chunks):
            await send({"type": "http.response.body", "body": chunk, "more_body": index < len(chunks) - 1})

    return app


async def _drive(app, scope) -> list[dict]:
    sent: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": _REQUEST_BODY_MARKER.encode(), "more_body": False}

    async def send(message):
        sent.append(message)

    await McpRejectionLogger(app)(scope, receive, send)
    return sent


def _rpc_error(code: int, message: str = "boom") -> bytes:
    return json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": code, "message": message}}).encode()


def _rejections(caplog) -> list[logging.LogRecord]:
    return [r for r in caplog.records if LOG_SENTINEL in r.getMessage()]


class TestLogsRejections:
    @pytest.mark.anyio
    async def test_400_logs_one_warning_with_status_code_ua_and_protocol_version(self, caplog):
        caplog.set_level(logging.WARNING, logger=_LOGGER)

        await _drive(_responder(400, _rpc_error(-32602)), _scope())

        [record] = _rejections(caplog)
        message = record.getMessage()
        assert record.levelno == logging.WARNING
        assert "status=400" in message
        assert "reason='Bad Request'" in message
        assert "rpc_error_code=-32602" in message
        assert "method=POST" in message
        assert "ua='claude-test/1.0'" in message
        assert "protocol_version='2026-07-28'" in message

    @pytest.mark.anyio
    @pytest.mark.parametrize("status", [403, 406, 415, 500])
    async def test_other_error_statuses_are_logged(self, caplog, status):
        caplog.set_level(logging.WARNING, logger=_LOGGER)

        await _drive(_responder(status, b"plain text, not json"), _scope())

        [record] = _rejections(caplog)
        assert f"status={status}" in record.getMessage()
        assert "rpc_error_code=None" in record.getMessage()

    @pytest.mark.anyio
    async def test_missing_headers_log_none_instead_of_failing(self, caplog):
        caplog.set_level(logging.WARNING, logger=_LOGGER)

        await _drive(_responder(400, _rpc_error(-32600)), _scope(headers=[(b"accept", b"*/*")]))

        [record] = _rejections(caplog)
        assert "ua=None" in record.getMessage()
        assert "protocol_version=None" in record.getMessage()

    @pytest.mark.anyio
    async def test_logs_once_when_body_arrives_in_chunks(self, caplog):
        caplog.set_level(logging.WARNING, logger=_LOGGER)

        await _drive(_responder(400, _rpc_error(-32700), chunk_size=7), _scope())

        [record] = _rejections(caplog)
        assert "rpc_error_code=-32700" in record.getMessage()

    @pytest.mark.anyio
    async def test_oversized_body_is_still_logged_without_a_code(self, caplog):
        caplog.set_level(logging.WARNING, logger=_LOGGER)

        await _drive(_responder(400, _rpc_error(-32602, "x" * 5000)), _scope())

        [record] = _rejections(caplog)
        assert "status=400" in record.getMessage()
        assert "rpc_error_code=None" in record.getMessage()

    @pytest.mark.anyio
    async def test_logs_when_the_app_raises_after_starting_an_error_response(self, caplog):
        caplog.set_level(logging.WARNING, logger=_LOGGER)

        async def app(scope, receive, send):
            await send({"type": "http.response.start", "status": 500, "headers": []})
            raise RuntimeError("downstream failure")

        with pytest.raises(RuntimeError):
            await _drive(app, _scope())

        [record] = _rejections(caplog)
        assert "status=500" in record.getMessage()


class TestDoesNotLog:
    @pytest.mark.anyio
    @pytest.mark.parametrize("status", [200, 202, 304])
    async def test_success_statuses(self, caplog, status):
        caplog.set_level(logging.WARNING, logger=_LOGGER)

        await _drive(_responder(status, b"ok"), _scope())

        assert _rejections(caplog) == []

    @pytest.mark.anyio
    async def test_401_is_left_to_the_jwt_auth_logger(self, caplog):
        caplog.set_level(logging.WARNING, logger=_LOGGER)

        await _drive(_responder(401, b""), _scope())

        assert _rejections(caplog) == []

    @pytest.mark.anyio
    async def test_405_get_probes_are_not_logged(self, caplog):
        caplog.set_level(logging.WARNING, logger=_LOGGER)

        await _drive(_responder(405, b""), _scope(method="GET"))

        assert _rejections(caplog) == []

    @pytest.mark.anyio
    async def test_other_paths_are_ignored(self, caplog):
        caplog.set_level(logging.WARNING, logger=_LOGGER)

        await _drive(_responder(400, _rpc_error(-32600)), _scope(path="/oauth/token"))

        assert _rejections(caplog) == []

    @pytest.mark.anyio
    async def test_non_http_scopes_pass_straight_through(self, caplog):
        caplog.set_level(logging.WARNING, logger=_LOGGER)
        seen = {}

        async def app(scope, receive, send):
            seen["type"] = scope["type"]

        await McpRejectionLogger(app)({"type": "lifespan"}, None, None)

        assert seen == {"type": "lifespan"}
        assert _rejections(caplog) == []


class TestInv3NoSensitiveDataInLogs:
    @pytest.mark.anyio
    async def test_log_excludes_authorization_query_request_body_and_error_message(self, caplog):
        caplog.set_level(logging.DEBUG, logger=_LOGGER)

        await _drive(
            _responder(400, _rpc_error(-32602, f"input_value={_REQUEST_BODY_MARKER}")),
            _scope(query=b"api_key=query-string-secret"),
        )

        text = "\n".join(r.getMessage() for r in caplog.records)
        assert LOG_SENTINEL in text
        for forbidden in (_SECRET_TOKEN, "Bearer", "query-string-secret", _REQUEST_BODY_MARKER, "input_value"):
            assert forbidden not in text

    @pytest.mark.anyio
    async def test_hostile_header_values_cannot_break_the_log_line(self, caplog):
        caplog.set_level(logging.WARNING, logger=_LOGGER)
        hostile = b"evil\nmcp_transport_rejection status=200 " + b"A" * 500

        await _drive(
            _responder(400, _rpc_error(-32600)),
            _scope(headers=[(b"user-agent", hostile), (b"mcp-protocol-version", hostile)]),
        )

        [record] = _rejections(caplog)
        assert "\n" not in record.getMessage()
        assert len(record.getMessage()) < 700


class TestResponseIsUntouched:
    @pytest.mark.anyio
    async def test_messages_are_forwarded_unchanged_and_in_order(self):
        body = _rpc_error(-32602)

        sent = await _drive(_responder(400, body, chunk_size=10), _scope())

        assert sent[0] == {"type": "http.response.start", "status": 400, "headers": []}
        assert b"".join(m["body"] for m in sent[1:]) == body
        assert sent[-1]["more_body"] is False
