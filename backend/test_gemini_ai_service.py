import json
from types import SimpleNamespace
import pytest
from app.services import ai_service

class FakeModels:
    def __init__(self, response=None, error=None):
        self.response, self.error, self.kwargs = response, error, None
    def generate_content(self, **kwargs):
        self.kwargs = kwargs
        if self.error:
            raise self.error
        return self.response

class FakeClient:
    def __init__(self, models):
        self.models = models

def test_requires_gemini_api_key(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="GEMINI_API_KEY is not configured"):
        ai_service.explain_finding({"id": "demo"})

def test_uses_configured_model_and_parses_json(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")
    monkeypatch.setenv("TRACELENS_AI_MODEL", "gemini-test-model")
    models = FakeModels(response=SimpleNamespace(text=json.dumps({"summary":"Demo summary","impact":"Demo impact","recommendation":"Demo fix"})))
    monkeypatch.setattr(ai_service.genai, "Client", lambda **kwargs: FakeClient(models))
    result = ai_service.explain_finding({"id":"demo"})
    assert result["summary"] == "Demo summary"
    assert models.kwargs["model"] == "gemini-test-model"
    assert models.kwargs["config"].response_mime_type == "application/json"

def test_defaults_to_gemini_flash(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")
    monkeypatch.delenv("TRACELENS_AI_MODEL", raising=False)
    models = FakeModels(response=SimpleNamespace(text='{"summary":"ok"}'))
    monkeypatch.setattr(ai_service.genai, "Client", lambda **kwargs: FakeClient(models))
    ai_service.explain_finding({"id":"demo"})
    assert models.kwargs["model"] == "gemini-3.5-flash-lite"

def test_provider_error_is_sanitized(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")
    models = FakeModels(error=RuntimeError("sensitive provider details"))
    monkeypatch.setattr(ai_service.genai, "Client", lambda **kwargs: FakeClient(models))
    with pytest.raises(RuntimeError, match="AI service unavailable") as exc:
        ai_service.explain_finding({"id":"demo"})
    assert "sensitive provider details" not in str(exc.value)

def test_invalid_json_is_sanitized(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")
    models = FakeModels(response=SimpleNamespace(text="not json"))
    monkeypatch.setattr(ai_service.genai, "Client", lambda **kwargs: FakeClient(models))
    with pytest.raises(RuntimeError, match="AI returned an invalid JSON response"):
        ai_service.explain_finding({"id":"demo"})
