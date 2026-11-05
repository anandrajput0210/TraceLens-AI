import pytest

from app.main import get_allowed_origins


def test_cors_origins_default_to_local_development(monkeypatch):
    monkeypatch.delenv("TRACELENS_ALLOWED_ORIGINS", raising=False)

    assert get_allowed_origins() == [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]


def test_cors_origins_are_read_from_environment(monkeypatch):
    monkeypatch.setenv(
        "TRACELENS_ALLOWED_ORIGINS",
        "https://app.example.com/, https://admin.example.com",
    )

    assert get_allowed_origins() == [
        "https://app.example.com",
        "https://admin.example.com",
    ]


def test_cors_wildcard_is_rejected_with_credentials(monkeypatch):
    monkeypatch.setenv("TRACELENS_ALLOWED_ORIGINS", "*")

    with pytest.raises(ValueError, match="Wildcard CORS origins are not allowed"):
        get_allowed_origins()


def test_cors_invalid_origin_is_rejected(monkeypatch):
    monkeypatch.setenv("TRACELENS_ALLOWED_ORIGINS", "https://example.com/app")

    with pytest.raises(ValueError, match="only HTTP"):
        get_allowed_origins()
