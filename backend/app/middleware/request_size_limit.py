"""Limit request body size before multipart form parsing consumes it."""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any


class _RequestBodyTooLarge(Exception):
    """Raised when a streamed request body exceeds the configured limit."""


class RequestBodySizeLimitMiddleware:
    """Enforce a streaming request-body limit on selected HTTP paths.

    The middleware checks Content-Length when available and also counts actual
    body bytes as ASGI receives them, so chunked requests cannot bypass the cap.
    It does not buffer the entire request body in memory.
    """

    def __init__(
        self,
        app: Any,
        max_body_size: int,
        paths: Iterable[str] = ("/api/analyze",),
    ) -> None:
        if max_body_size <= 0:
            raise ValueError("max_body_size must be positive")
        self.app = app
        self.max_body_size = max_body_size
        self.paths = frozenset(paths)

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http" or scope.get("path") not in self.paths:
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        content_length = headers.get(b"content-length")
        if content_length is not None:
            try:
                declared_size = int(content_length)
            except (TypeError, ValueError):
                # Do not trust a malformed header; enforce the streaming cap.
                declared_size = None
            if declared_size is not None and declared_size > self.max_body_size:
                await self._send_too_large(send)
                return

        received_size = 0
        response_started = False

        async def limited_receive() -> dict[str, Any]:
            nonlocal received_size
            message = await receive()
            if message.get("type") == "http.request":
                received_size += len(message.get("body", b""))
                if received_size > self.max_body_size:
                    raise _RequestBodyTooLarge
            return message

        async def tracking_send(message: dict[str, Any]) -> None:
            nonlocal response_started
            if message.get("type") == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _RequestBodyTooLarge:
            # The exception occurs while the request body is being consumed,
            # before normal request handlers should have started a response.
            if not response_started:
                await self._send_too_large(send)

    async def _send_too_large(self, send: Any) -> None:
        body = json.dumps({"detail": "Request body exceeds the maximum allowed size."}).encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        })
        await send({
            "type": "http.response.body",
            "body": body,
            "more_body": False,
        })
