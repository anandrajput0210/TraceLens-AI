from fastapi.testclient import TestClient

from app.api import analyze
from app.main import app
import pytest

from app.services import github_service

def test_oversized_upload_is_rejected(monkeypatch):
    monkeypatch.setattr(
        analyze,
        "MAX_UPLOAD_SIZE",
        8,
    )

    client = TestClient(app)

    response = client.post(
        "/api/analyze",
        files={
            "repository": (
                "large.zip",
                b"123456789",
                "application/zip",
            )
        },
    )

    assert response.status_code == 413
    assert response.json()["detail"] == (
        "Uploaded ZIP exceeds the maximum allowed upload size."
    )


def test_invalid_zip_returns_controlled_error():
    client = TestClient(app)

    response = client.post(
        "/api/analyze",
        files={
            "repository": (
                "invalid.zip",
                b"this is not a ZIP archive",
                "application/zip",
            )
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "The supplied archive is not a valid ZIP file."
    )


def test_unexpected_github_error_does_not_leak_details(
    monkeypatch,
):
    def failing_download(*args, **kwargs):
        raise RuntimeError("private-internal-error-marker")

    monkeypatch.setattr(
        analyze,
        "download_github_repository",
        failing_download,
    )

    client = TestClient(app)

    response = client.post(
        "/api/analyze",
        data={
            "github_url": (
                "https://github.com/octocat/Hello-World"
            )
        },
    )

    assert response.status_code == 500
    assert "private-internal-error-marker" not in response.text
    assert response.json()["detail"] == (
        "Unable to process the repository. "
        "Check the ZIP file or GitHub URL and try again."
    )

def test_invalid_github_content_length_is_sanitized(
    monkeypatch,
    tmp_path,
):
    class FakeResponse:
        headers = {"Content-Length": "not-a-number"}

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

    monkeypatch.setattr(
        github_service,
        "get_default_branch",
        lambda owner, repo: "main",
    )

    monkeypatch.setattr(
        github_service.urllib.request,
        "urlopen",
        lambda *args, **kwargs: FakeResponse(),
    )

    with pytest.raises(ValueError) as exc_info:
        github_service.download_github_repository(
            "https://github.com/example/repo",
            str(tmp_path / "repository.zip"),
        )

    assert exc_info.value.args[0] == (
        "GitHub repository returned an invalid Content-Length header."
    )
