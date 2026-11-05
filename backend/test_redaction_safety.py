import pytest

from app.utils.redaction import MASK, redact_evidence


@pytest.mark.parametrize(
    ("evidence", "secret"),
    [
        (
            'PASSWORD = "quotedSecret_Value_123"',
            "quotedSecret_Value_123",
        ),
        (
            "PASSWORD=unquotedSecret_Value_456",
            "unquotedSecret_Value_456",
        ),
        (
            '{"client_secret": "jsonSecret_Value_789"}',
            "jsonSecret_Value_789",
        ),
        (
            "Authorization: Bearer ghp_SyntheticToken123456",
            "ghp_SyntheticToken123456",
        ),
        (
            "MONGO_URI=mongodb+srv://demo:MongoDbPass123@cluster.example/db",
            "MongoDbPass123",
        ),
        (
            "REDIS_URL=redis://demo:RedisPass123@cache.example:6379/0",
            "RedisPass123",
        ),
    ],
)
def test_sensitive_values_are_redacted(evidence, secret):
    redacted = redact_evidence(evidence)

    assert secret not in redacted
    assert MASK in redacted


def test_postgres_password_is_redacted():
    evidence = (
        "DATABASE_URL=postgresql://demo:PostgresPass123"
        "@db.example/app"
    )

    redacted = redact_evidence(evidence)

    assert "PostgresPass123" not in redacted
    assert MASK in redacted


def test_multiple_secrets_on_one_line_are_redacted():
    evidence = (
        'PASSWORD="firstSyntheticSecret123"; '
        "API_TOKEN=secondSyntheticToken456"
    )

    redacted = redact_evidence(evidence)

    assert "firstSyntheticSecret123" not in redacted
    assert "secondSyntheticToken456" not in redacted

def test_unlabelled_high_entropy_literal_is_redacted():
    secret = "aB7$xQ9!mK2@pL8#zR5"
    evidence = f'random_value = "{secret}"'

    redacted = redact_evidence(evidence)

    assert secret not in redacted
    assert MASK in redacted


def test_environment_variable_reference_is_preserved():
    evidence = 'API_TOKEN = os.getenv("API_TOKEN")'

    assert redact_evidence(evidence) == evidence


def test_scanner_error_does_not_expose_secret(tmp_path, monkeypatch):
    from app.scanner import engine as scanner_engine_module
    from app.scanner.engine import ScannerEngine
    from app.services.repository_service import discover_files

    secret = "scannerLeakSecret123456"
    source = tmp_path / "config.py"
    source.write_text(
        f'PASSWORD = "{secret}"\n',
        encoding="utf-8",
    )

    files = discover_files(str(tmp_path))

    def broken_scanner(*args, **kwargs):
        raise RuntimeError(f'PASSWORD = "{secret}"')

    monkeypatch.setattr(
        scanner_engine_module,
        "scan_hardcoded_credentials",
        broken_scanner,
    )

    engine = ScannerEngine()
    engine.scan_repository(str(tmp_path), files)

    assert secret not in repr(engine.errors)


def test_analysis_failure_does_not_expose_secret(
    tmp_path,
    monkeypatch,
):
    from app.services import analysis_service

    secret = "analysisLeakSecret123456"
    repository = tmp_path / "repository"
    repository.mkdir()

    def broken_discovery(*args, **kwargs):
        raise RuntimeError(f'PASSWORD = "{secret}"')

    monkeypatch.setattr(
        analysis_service,
        "discover_files",
        broken_discovery,
    )

    analysis_id = analysis_service.create_analysis(
        str(repository)
    )
    analysis_service.run_analysis(
        analysis_id,
        str(repository),
        repository.name,
    )

    result = analysis_service.ANALYSES[analysis_id]

    assert result["status"] == "failed"
    assert secret not in repr(result)


def test_ai_explanation_redacts_input_and_output(monkeypatch):
    import json
    from types import SimpleNamespace

    from app.services import ai_service

    captured = {}
    input_secret = "aiInputSecret123456"
    output_secret = "aiOutputSecret123456"

    class FakeModels:
        def generate_content(self, **kwargs):
            captured.update(kwargs)
            return SimpleNamespace(
                text=json.dumps({
                    "summary": f'Found API_TOKEN = "{output_secret}"',
                    "impact": "Synthetic test response",
                    "recommendation": "Rotate the exposed credential",
                })
            )

    class FakeClient:
        def __init__(self, api_key=None, **kwargs):
            captured["api_key"] = api_key
            self.models = FakeModels()

    monkeypatch.setenv("GEMINI_API_KEY", "synthetic-test-key")
    monkeypatch.setattr(ai_service.genai, "Client", FakeClient)

    finding = {
        "id": "F-TEST",
        "evidence": f'API_TOKEN = "{input_secret}"',
        "password": "nestedStructuredSecret123",
    }

    result = ai_service.explain_finding(finding)

    assert input_secret not in captured["contents"]
    assert "nestedStructuredSecret123" not in captured["contents"]
    assert "[REDACTED]" in captured["contents"]
    assert output_secret not in json.dumps(result)
    assert "[REDACTED]" in json.dumps(result)


def test_redaction_does_not_remove_safe_environment_reference():
    evidence = 'API_TOKEN = os.getenv("API_TOKEN")'

    assert redact_evidence(evidence) == evidence


def test_redaction_marker_is_readable():
    assert MASK == "[REDACTED]"
    assert "ΓÇó" not in MASK
