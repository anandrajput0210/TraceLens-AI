from __future__ import annotations

import asyncio
import json

from app.middleware.request_size_limit import RequestBodySizeLimitMiddleware


def _run_asgi(middleware, *, path="/api/analyze", headers=None, messages=None):
    sent = []
    app_called = []
    incoming = list(messages or [])

    async def receive():
        if incoming:
            return incoming.pop(0)
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    async def inner(scope, inner_receive, inner_send):
        app_called.append(True)
        while True:
            message = await inner_receive()
            if message.get("type") == "http.disconnect":
                break
            if message.get("type") == "http.request" and not message.get("more_body", False):
                break
        body = b"{}"
        await inner_send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
        await inner_send({"type": "http.response.body", "body": body, "more_body": False})

    middleware.app = inner
    scope = {
        "type": "http",
        "method": "POST",
        "path": path,
        "headers": headers or [],
    }
    asyncio.run(middleware(scope, receive, send))
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    body_message = next(m for m in sent if m["type"] == "http.response.body")
    return status, json.loads(body_message["body"].decode()), app_called


def test_rejects_declared_content_length_before_calling_app():
    middleware = RequestBodySizeLimitMiddleware(lambda *args: None, max_body_size=8)
    status, body, app_called = _run_asgi(
        middleware,
        headers=[(b"content-length", b"9")],
        messages=[{"type": "http.request", "body": b"123456789", "more_body": False}],
    )
    assert status == 413
    assert body["detail"] == "Request body exceeds the maximum allowed size."
    assert not app_called


def test_rejects_chunked_body_over_limit():
    middleware = RequestBodySizeLimitMiddleware(lambda *args: None, max_body_size=8)
    status, body, app_called = _run_asgi(
        middleware,
        messages=[
            {"type": "http.request", "body": b"123456", "more_body": True},
            {"type": "http.request", "body": b"789", "more_body": False},
        ],
    )
    assert status == 413
    assert body["detail"] == "Request body exceeds the maximum allowed size."
    assert app_called


def test_allows_body_at_limit():
    middleware = RequestBodySizeLimitMiddleware(lambda *args: None, max_body_size=8)
    status, body, app_called = _run_asgi(
        middleware,
        messages=[{"type": "http.request", "body": b"12345678", "more_body": False}],
    )
    assert status == 200
    assert body == {}
    assert app_called


def test_does_not_apply_limit_to_other_paths():
    middleware = RequestBodySizeLimitMiddleware(lambda *args: None, max_body_size=8)
    status, body, app_called = _run_asgi(
        middleware,
        path="/api/health",
        messages=[{"type": "http.request", "body": b"123456789", "more_body": False}],
    )
    assert status == 200
    assert body == {}
    assert app_called
