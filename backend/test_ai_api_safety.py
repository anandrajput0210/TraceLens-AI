import logging

from fastapi.testclient import TestClient

from app.api import ai as ai_api
from app.main import app


SECRET_MARKER = "private-internal-error-marker-secret"


def _raise_runtime_error(_finding):
    raise RuntimeError(SECRET_MARKER)


def _raise_unexpected_error(_finding):
    raise ValueError(SECRET_MARKER)


def test_ai_api_does_not_expose_runtime_error_details(monkeypatch, caplog):
    monkeypatch.setattr(ai_api, "explain_finding", _raise_runtime_error)

    with caplog.at_level(logging.WARNING):
        response = TestClient(app).post(
            "/api/ai/explain",
            json={"finding": {"title": "Example finding"}},
        )

    assert response.status_code == 503
    assert SECRET_MARKER not in response.text
    assert SECRET_MARKER not in caplog.text
    assert response.json()["detail"] == "AI service unavailable"


def test_ai_api_does_not_expose_unexpected_error_details(monkeypatch, caplog):
    monkeypatch.setattr(ai_api, "explain_finding", _raise_unexpected_error)

    with caplog.at_level(logging.ERROR):
        response = TestClient(app).post(
            "/api/ai/explain",
            json={"finding": {"title": "Example finding"}},
        )

    assert response.status_code == 500
    assert SECRET_MARKER not in response.text
    assert SECRET_MARKER not in caplog.text
    assert response.json()["detail"] == "AI reasoning service failed."
