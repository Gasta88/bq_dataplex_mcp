"""Greppable WARNING log for protocol-layer rejections on `/mcp`.

Requests rejected below the tool layer (bad protocol version, malformed
JSON-RPC, missing `params._meta`, ...) never reach the audit decorator, and
Cloud Run request logs show only a status and a byte count. `McpRejectionLogger`
is a pure ASGI middleware that emits one plain-text line per rejection, so
`textPayload=~"mcp_transport_rejection"` answers which client sent what and why
it was refused.

Excluded on purpose:
  - 401: already logged by `app.jwt_auth`.
  - 405: stateless mode answers every `GET /mcp` with 405.

The line never contains the `Authorization` header, the request body, or the
query string. Only the JSON-RPC error code is read from the response.
"""

import json
import logging
from http import HTTPStatus

from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger(__name__)

LOG_SENTINEL = "mcp_transport_rejection"

_EXCLUDED_STATUSES = frozenset({401, 405})
_MAX_BODY_BYTES_FOR_CODE = 2048
_MAX_HEADER_CHARS = 200


def _header(scope: Scope, name: bytes) -> str | None:
    for key, value in scope.get("headers", []):
        if key == name:
            return value.decode("latin-1")[:_MAX_HEADER_CHARS]
    return None


def _reason(status: int) -> str:
    try:
        return HTTPStatus(status).phrase
    except ValueError:
        return "Unknown"


def _rpc_error_code(body: bytes) -> int | None:
    try:
        error = json.loads(body).get("error")
    except (ValueError, AttributeError):
        return None
    code = error.get("code") if isinstance(error, dict) else None
    return code if isinstance(code, int) else None


class McpRejectionLogger:
    def __init__(self, app: ASGIApp, path: str = "/mcp") -> None:
        self.app = app
        self.path = path

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["path"] != self.path:
            await self.app(scope, receive, send)
            return

        status = 0
        body = bytearray()
        body_overflowed = False
        logged = False

        def log_once() -> None:
            nonlocal logged
            if logged or status < 400 or status in _EXCLUDED_STATUSES:
                return
            logged = True
            code = None if body_overflowed else _rpc_error_code(bytes(body))
            logger.warning(
                "%s status=%s reason=%r rpc_error_code=%s method=%s ua=%r protocol_version=%r",
                LOG_SENTINEL,
                status,
                _reason(status),
                code,
                scope.get("method"),
                _header(scope, b"user-agent"),
                _header(scope, b"mcp-protocol-version"),
            )

        async def send_wrapper(message: Message) -> None:
            nonlocal status, body_overflowed
            if message["type"] == "http.response.start":
                status = message["status"]
            elif message["type"] == "http.response.body" and status >= 400:
                chunk = message.get("body", b"")
                if len(body) + len(chunk) > _MAX_BODY_BYTES_FOR_CODE:
                    body_overflowed = True
                else:
                    body.extend(chunk)
                if not message.get("more_body", False):
                    log_once()
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            log_once()
