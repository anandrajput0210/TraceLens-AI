import json
from types import SimpleNamespace

import pytest

from app.services import ai_service


DEFAULT_MODEL = "gemini-3.5-flash-lite"


def _install_fake_client(monkeypatch, captured):
    class FakeModels:
        def generate_content(self, **kwargs):
            captured.update(kwargs)
            return SimpleNamespace(
                text=json.dumps({
                    "summary": "Synthetic summary",
                    "impact": "Synthetic impact",
                    "recommendation": "Synthetic recommendation",
                })
            )

    class FakeClient:
        def __init__(self, api_key=None, **kwargs):
            captured["api_key"] = api_key
            self.models = FakeModels()

    monkeypatch.setenv("GEMINI_API_KEY", "synthetic-test-key")
    monkeypatch.setattr(ai_service.genai, "Client", FakeClient)


def test_default_model_uses_documented_default(monkeypatch):
    captured = {}
    monkeypatch.delenv("TRACELENS_AI_MODEL", raising=False)
    _install_fake_client(monkeypatch, captured)

    result = ai_service.explain_finding({"title": "Synthetic test finding"})

    assert captured["model"] == DEFAULT_MODEL
    assert result["summary"] == "Synthetic summary"
    assert captured["api_key"] == "synthetic-test-key"


def test_model_can_be_configured_per_environment(monkeypatch):
    captured = {}
    monkeypatch.setenv("TRACELENS_AI_MODEL", "account-approved-model")
    _install_fake_client(monkeypatch, captured)

    ai_service.explain_finding({"title": "Synthetic test finding"})

    assert captured["model"] == "account-approved-model"


def test_missing_gemini_key_fails_without_calling_provider(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    called = {"value": False}

    def fake_client(**kwargs):
        called["value"] = True
        raise AssertionError("Gemini should not be called without a key")

    monkeypatch.setattr(ai_service.genai, "Client", fake_client)

    with pytest.raises(RuntimeError, match="GEMINI_API_KEY is not configured"):
        ai_service.explain_finding({"title": "Synthetic test finding"})

    assert called["value"] is False
