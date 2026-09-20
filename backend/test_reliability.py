import io
import pytest
import app.scanner.engine as scanner_engine_module
from pathlib import Path
from fastapi.testclient import TestClient
from app.main import app
from zipfile import ZipFile
from app.services.analysis_service import (
    ANALYSES,
    create_analysis,
    run_analysis,
)
from app.services.archive_service import safe_extract_zip
from app.scanner.engine import ScannerEngine
from app.services.repository_service import discover_files
from app.risk.scoring import calculate_context_risk
from unittest.mock import patch

from app.services.github_service import (
    download_github_repository,
    get_default_branch,
    parse_github_url,
)
def test_empty_repository_does_not_crash(tmp_path):
    repository_path = tmp_path / "empty_repo"

    repository_path.mkdir()

    files = discover_files(str(repository_path))

    engine = ScannerEngine()

    findings = engine.scan_repository(
        str(repository_path),
        files,
    )

    assert files == []
    assert findings == []

def test_nonexistent_repository_is_rejected(tmp_path):
    repository_path = tmp_path / "does_not_exist"

    with pytest.raises(FileNotFoundError, match="Repository path does not exist"):
        discover_files(str(repository_path))

def test_file_scan_does_not_crash(tmp_path):
    test_file = tmp_path / "test_app.py"

    test_file.write_text(
        'PASSWORD = "test_password_123"\n',
        encoding="utf-8",
    )

    files = discover_files(str(tmp_path))

    engine = ScannerEngine()

    findings = engine.scan_repository(
        str(tmp_path),
        files,
    )

    assert isinstance(files, list)
    assert isinstance(findings, list)
def test_scanner_component_failure_does_not_crash(tmp_path, monkeypatch):
    test_file = tmp_path / "test_app.py"

    test_file.write_text(
        'PASSWORD = "test_password_123"\n',
        encoding="utf-8",
    )

    files = discover_files(str(tmp_path))

    def broken_scanner(*args, **kwargs):
        raise RuntimeError("Simulated scanner failure")

    monkeypatch.setattr(
        scanner_engine_module,
        "scan_hardcoded_credentials",
        broken_scanner,
    )

    engine = ScannerEngine()

    findings = engine.scan_repository(
        str(tmp_path),
        files,
    )

    assert isinstance(findings, list)
def test_obvious_credential_is_not_duplicated_as_high_entropy(tmp_path):
    test_file = tmp_path / "secrets.py"

    test_file.write_text(
        'API_TOKEN = "super_secret_password_123"\n',
        encoding="utf-8",
    )

    files = discover_files(str(tmp_path))

    engine = ScannerEngine()

    findings = engine.scan_repository(
        str(tmp_path),
        files,
    )

    token_findings = [
        finding
        for finding in findings
        if finding.file.replace("\\", "/") == "secrets.py"
    ]

    rule_ids = [
        finding.rule_id
        for finding in token_findings
    ]

    assert "SEC-001" in rule_ids
    assert "SEC-002" not in rule_ids
from app.scanner.secrets import scan_hardcoded_credentials

def test_ai_failure_returns_controlled_error(monkeypatch):
    from app.api import ai

    def failing_explain_finding(finding):
        raise RuntimeError("AI service unavailable")

    monkeypatch.setattr(
    ai,
    "explain_finding",
    failing_explain_finding,
)

    client = TestClient(app)

    response = client.post(
        "/api/ai/explain",
        json={
            "finding": {
                "id": "F001",
                "rule_id": "SEC-001",
                "title": "Potential hardcoded credential",
                "file": "config.py",
                "line": 10,
                "base_severity": "HIGH",
                "context_score": 85,
            }
        },
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "AI service unavailable"
def test_normal_zip_extracts_safely(tmp_path):
    zip_path = tmp_path / "repo.zip"
    extract_dir = tmp_path / "extracted"

    with ZipFile(zip_path, "w") as archive:
        archive.writestr(
            "project/app.py",
            'print("hello")',
        )

    result = safe_extract_zip(
        str(zip_path),
        str(extract_dir),
    )

    assert Path(result).exists()
    assert (Path(result) / "app.py").exists()


def test_zip_path_traversal_is_rejected(tmp_path):
    zip_path = tmp_path / "malicious.zip"
    extract_dir = tmp_path / "extracted"

    with ZipFile(zip_path, "w") as archive:
        archive.writestr(
            "../../outside.txt",
            "malicious content",
        )

    with pytest.raises(ValueError, match="Unsafe ZIP path"):
        safe_extract_zip(
            str(zip_path),
            str(extract_dir),
        )

    assert not (tmp_path / "outside.txt").exists()


def test_oversized_zip_file_is_rejected(tmp_path):
    zip_path = tmp_path / "large.zip"
    extract_dir = tmp_path / "extracted"

    large_content = b"A" * 1_000_001

    with ZipFile(zip_path, "w") as archive:
        archive.writestr(
            "large.txt",
            large_content,
        )

    with pytest.raises(ValueError, match="File too large"):
        safe_extract_zip(
            str(zip_path),
            str(extract_dir),
        )
def test_zip_total_size_limit_is_rejected(tmp_path):
    zip_path = tmp_path / "large_total.zip"
    extract_dir = tmp_path / "extracted"

    content = b"A" * 1_000_000

    with ZipFile(zip_path, "w") as archive:
        for index in range(51):
            archive.writestr(
                f"file_{index}.bin",
                content,
            )

    with pytest.raises(
        ValueError,
        match="maximum extraction size",
    ):
        safe_extract_zip(
            str(zip_path),
            str(extract_dir),
        )


def test_zip_file_count_limit_is_rejected(tmp_path):
    zip_path = tmp_path / "too_many_files.zip"
    extract_dir = tmp_path / "extracted"

    with ZipFile(zip_path, "w") as archive:
        for index in range(5001):
            archive.writestr(
                f"file_{index}.txt",
                "test",
            )

    with pytest.raises(
        ValueError,
        match="too many files",
    ):
        safe_extract_zip(
            str(zip_path),
            str(extract_dir),
        )
def test_analyze_rejects_non_zip_upload():
    client = TestClient(app)

    response = client.post(
        "/api/analyze",
        files={
            "repository": (
                "repository.txt",
                b"not a zip file",
                "text/plain",
            )
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "Only ZIP repositories are supported."
    )


def test_analyze_requires_repository_upload():
    client = TestClient(app)

    response = client.post(
        "/api/analyze",
    )

    assert response.status_code == 400

def test_get_analysis_returns_404_for_unknown_id():
    client = TestClient(app)

    response = client.get(
        "/api/analyze/nonexistent-analysis-id"
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Analysis not found."


def test_analyze_rejects_unsafe_zip():
    client = TestClient(app)

    zip_buffer = io.BytesIO()

    with ZipFile(zip_buffer, "w") as archive:
        archive.writestr(
            "../../outside.txt",
            "malicious content",
        )

    zip_buffer.seek(0)

    response = client.post(
        "/api/analyze",
        files={
            "repository": (
                "malicious.zip",
                zip_buffer,
                "application/zip",
            )
        },
    )

    assert response.status_code == 400
    assert "Unsafe ZIP path" in response.json()["detail"]
def test_analysis_pipeline_completes(tmp_path):
    repository = tmp_path / "demo_repo"
    repository.mkdir()

    source_file = repository / "config.py"
    source_file.write_text(
        'API_TOKEN = "super_secret_password_123"\n',
        encoding="utf-8",
    )

    analysis_id = create_analysis(
        str(repository)
    )

    run_analysis(
        analysis_id,
        str(repository),
        repository.name,
    )

    result = ANALYSES[analysis_id]

    assert result["status"] == "completed"
    assert result["progress"] == 100
    assert result["files_analyzed"] == 1
    assert result["findings_count"] >= 1
    assert result["overall_score"] > 0
    assert len(result["findings"]) >= 1
def test_analysis_becomes_partial_when_scanner_fails(
    tmp_path,
    monkeypatch,
):
    repository = tmp_path / "demo_repo"
    repository.mkdir()

    source_file = repository / "config.py"
    source_file.write_text(
        'API_TOKEN = "super_secret_password_123"\n',
        encoding="utf-8",
    )

    def failing_scanner(
        self,
        repository_path,
        files,
    ):
        self.errors.append(
            {
                "rule_id": "SEC-001",
                "file": "config.py",
                "error": "Simulated scanner failure",
            }
        )
        return []

    monkeypatch.setattr(
        ScannerEngine,
        "scan_repository",
        failing_scanner,
    )

    analysis_id = create_analysis(
        str(repository)
    )

    run_analysis(
        analysis_id,
        str(repository),
        repository.name,
    )

    result = ANALYSES[analysis_id]

    assert result["status"] == "partial"
    assert result["progress"] == 100
    assert result["errors"]
    assert result["errors"][0]["rule_id"] == "SEC-001"
def test_analysis_becomes_partial_when_scanner_fails(
    tmp_path,
    monkeypatch,
):
    repository = tmp_path / "demo_repo"
    repository.mkdir()

    source_file = repository / "config.py"
    source_file.write_text(
        'API_TOKEN = "super_secret_password_123"\n',
        encoding="utf-8",
    )

    def failing_scanner(
        self,
        repository_path,
        files,
    ):
        self.errors.append(
            {
                "rule_id": "SEC-001",
                "file": "config.py",
                "error": "Simulated scanner failure",
            }
        )
        return []

    monkeypatch.setattr(
        ScannerEngine,
        "scan_repository",
        failing_scanner,
    )

    analysis_id = create_analysis(
        str(repository)
    )

    run_analysis(
        analysis_id,
        str(repository),
        repository.name,
    )

    result = ANALYSES[analysis_id]

    assert result["status"] == "partial"
    assert result["progress"] == 100
    assert result["errors"]
    assert result["errors"][0]["rule_id"] == "SEC-001"
def test_analyze_accepts_valid_zip_and_starts_analysis(
    tmp_path,
    monkeypatch,
):
    client = TestClient(app)

    zip_buffer = io.BytesIO()

    with ZipFile(zip_buffer, "w") as archive:
        archive.writestr(
            "demo_repo/config.py",
            'API_TOKEN = "super_secret_password_123"\n',
        )

    zip_buffer.seek(0)

    # Prevent the real background analysis from running during
    # this API-level test.
    def fake_run_analysis(
        analysis_id,
        repository_path,
        repository_name,
    ):
        return None

    from app.api import analyze

    monkeypatch.setattr(
        analyze,
        "run_analysis",
        fake_run_analysis,
    )

    response = client.post(
        "/api/analyze",
        files={
            "repository": (
                "demo_repo.zip",
                zip_buffer,
                "application/zip",
            )
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert "analysis_id" in body
    assert body["status"] == "queued"
    assert body["message"] == (
        "Repository analysis started."
    )
def test_full_upload_to_completed_analysis():
    client = TestClient(app)

    zip_buffer = io.BytesIO()

    with ZipFile(zip_buffer, "w") as archive:
        archive.writestr(
            "demo_repo/config.py",
            'API_TOKEN = "super_secret_password_123"\n',
        )

    zip_buffer.seek(0)

    response = client.post(
        "/api/analyze",
        files={
            "repository": (
                "demo_repo.zip",
                zip_buffer,
                "application/zip",
            )
        },
    )

    assert response.status_code == 200

    analysis_id = response.json()["analysis_id"]

    result = client.get(
        f"/api/analyze/{analysis_id}"
    )

    assert result.status_code == 200

    body = result.json()

    assert body["analysis_id"] == analysis_id
    assert body["status"] == "completed"
    assert body["progress"] == 100
    assert body["files_analyzed"] >= 1
    assert body["findings_count"] >= 1
    assert body["overall_score"] > 0
    assert len(body["findings"]) >= 1

from pathlib import Path

from app.scanner.secrets import (
    scan_high_entropy_strings,
)


def write_test_file(tmp_path: Path, content: str) -> str:
    file_path = tmp_path / "test.py"
    file_path.write_text(content, encoding="utf-8")
    return str(file_path)


def test_sec002_detects_real_looking_secret(tmp_path):
    content = '''
random_value = "aB7$xQ9!mK2@pL8#zR5"
'''

    file_path = write_test_file(tmp_path, content)

    findings = scan_high_entropy_strings(
        file_path,
        "test.py",
    )

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SEC-002"


def test_sec002_ignores_uuid(tmp_path):
    content = '''
request_id = "550e8400-e29b-41d4-a716-446655440000"
'''

    file_path = write_test_file(tmp_path, content)

    findings = scan_high_entropy_strings(
        file_path,
        "test.py",
    )

    assert findings == []


def test_sec002_ignores_hash(tmp_path):
    content = '''
checksum = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
'''

    file_path = write_test_file(tmp_path, content)

    findings = scan_high_entropy_strings(
        file_path,
        "test.py",
    )

    assert findings == []


def test_sec002_ignores_url(tmp_path):
    content = '''
api_url = "https://example.com/api/v1/users"
'''

    file_path = write_test_file(tmp_path, content)

    findings = scan_high_entropy_strings(
        file_path,
        "test.py",
    )

    assert findings == []


def test_sec002_ignores_version(tmp_path):
    content = '''
version = "v2.14.7-beta"
'''

    file_path = write_test_file(tmp_path, content)

    findings = scan_high_entropy_strings(
        file_path,
        "test.py",
    )

    assert findings == []


def test_sec002_ignores_normal_configuration(tmp_path):
    content = '''
environment_name = "production"
'''

    file_path = write_test_file(tmp_path, content)

    findings = scan_high_entropy_strings(
        file_path,
        "test.py",
    )

    assert findings == []


def test_sec002_does_not_duplicate_sec001(tmp_path):
    content = '''
API_KEY = "aB7$xQ9!mK2@pL8#zR5"
'''

    file_path = write_test_file(tmp_path, content)

    findings = scan_high_entropy_strings(
        file_path,
        "test.py",
    )

    # SEC-001 owns obvious credential variable names.
    assert findings == []

from app.scanner.config import scan_production_config


def write_config_file(tmp_path: Path, content: str, filename: str = "config.py") -> str:
    file_path = tmp_path / filename
    file_path.write_text(content, encoding="utf-8")
    return str(file_path)


def test_sec003_detects_production_sensitive_config(tmp_path):
    content = '''
ENVIRONMENT = "production"
DATABASE_URL = "postgres://app:password@db/prod"
'''

    file_path = write_config_file(tmp_path, content)

    findings = scan_production_config(
        file_path,
        "config.py",
    )

    assert len(findings) >= 1
    assert any(
        finding["rule_id"] == "SEC-003"
        for finding in findings
    )


def test_sec003_detects_production_config_file(tmp_path):
    content = '''
DATABASE_URL = "postgres://app:password@db/prod"
'''

    file_path = write_config_file(
        tmp_path,
        content,
        "production.py",
    )

    findings = scan_production_config(
        file_path,
        "production.py",
    )

    assert len(findings) >= 1
    assert findings[0]["rule_id"] == "SEC-003"


def test_sec003_ignores_development_config(tmp_path):
    content = '''
ENVIRONMENT = "development"
DATABASE_URL = "postgres://localhost/dev"
'''

    file_path = write_config_file(tmp_path, content)

    findings = scan_production_config(
        file_path,
        "config.py",
    )

    assert findings == []


def test_sec003_ignores_normal_production_value(tmp_path):
    content = '''
ENVIRONMENT = "production"
APP_NAME = "TraceLens"
'''

    file_path = write_config_file(tmp_path, content)

    findings = scan_production_config(
        file_path,
        "config.py",
    )

    assert findings == []


def test_sec003_detects_env_production_secret(tmp_path):
    content = '''
DATABASE_PASSWORD="super_secret_password"
'''

    file_path = write_config_file(
        tmp_path,
        content,
        ".env.production",
    )

    findings = scan_production_config(
        file_path,
        ".env.production",
    )

    assert len(findings) >= 1
    assert findings[0]["rule_id"] == "SEC-003"


def test_sec003_ignores_unrelated_file(tmp_path):
    content = '''
message = "production deployment is ready"
'''

    file_path = write_config_file(
        tmp_path,
        content,
        "README.txt",
    )

    findings = scan_production_config(
        file_path,
        "README.txt",
    )

    assert findings == []
from app.scanner.endpoints import scan_sensitive_endpoints


def write_endpoint_file(
    tmp_path: Path,
    content: str,
    filename: str = "api.py",
) -> str:
    file_path = tmp_path / filename
    file_path.write_text(content, encoding="utf-8")
    return str(file_path)


def test_sec006_detects_unprotected_admin_endpoint(tmp_path):
    content = '''
from fastapi import FastAPI

app = FastAPI()

@app.get("/admin/users")
def admin_users():
    return {"users": []}
'''

    file_path = write_endpoint_file(tmp_path, content)

    findings = scan_sensitive_endpoints(
        file_path,
        "api.py",
    )

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SEC-006"
    assert findings[0]["base_severity"] == "HIGH"


def test_sec006_ignores_login_required_endpoint(tmp_path):
    content = '''
from flask import Flask

app = Flask(__name__)

@app.get("/admin/users")
@login_required
def admin_users():
    return {"users": []}
'''

    file_path = write_endpoint_file(tmp_path, content)

    findings = scan_sensitive_endpoints(
        file_path,
        "api.py",
    )

    assert findings == []


def test_sec006_ignores_fastapi_dependency_auth(tmp_path):
    content = '''
from fastapi import FastAPI, Depends

app = FastAPI()

@app.get("/account")
def account(current_user = Depends(get_current_user)):
    return {"user": current_user}
'''

    file_path = write_endpoint_file(tmp_path, content)

    findings = scan_sensitive_endpoints(
        file_path,
        "api.py",
    )

    assert findings == []


def test_sec006_ignores_normal_public_endpoint(tmp_path):
    content = '''
from fastapi import FastAPI

app = FastAPI()

@app.get("/health")
def health():
    return {"status": "ok"}
'''

    file_path = write_endpoint_file(tmp_path, content)

    findings = scan_sensitive_endpoints(
        file_path,
        "api.py",
    )

    assert findings == []


def test_sec006_detects_async_sensitive_endpoint(tmp_path):
    content = '''
from fastapi import FastAPI

app = FastAPI()

@app.delete("/account")
async def delete_account():
    return {"deleted": True}
'''

    file_path = write_endpoint_file(tmp_path, content)

    findings = scan_sensitive_endpoints(
        file_path,
        "api.py",
    )

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SEC-006"


def test_sec006_ignores_non_python_file(tmp_path):
    content = '''
app.get("/admin/users", (req, res) => {
    res.json([]);
});
'''

    file_path = write_endpoint_file(
        tmp_path,
        content,
        "api.js",
    )

    findings = scan_sensitive_endpoints(
        file_path,
        "api.js",
    )

    assert findings == []


def test_sec006_finding_uses_cautious_language(tmp_path):
    content = '''
from fastapi import FastAPI

app = FastAPI()

@app.get("/payments")
def payments():
    return []
'''

    file_path = write_endpoint_file(tmp_path, content)

    findings = scan_sensitive_endpoints(
        file_path,
        "api.py",
    )

    assert len(findings) == 1

    title = findings[0]["title"].lower()
    evidence = findings[0]["evidence"].lower()

    assert "potentially" in title
    assert "no obvious" in evidence
from app.scanner.docker import scan_dockerfile


def write_dockerfile(
    tmp_path: Path,
    content: str,
    filename: str = "Dockerfile",
) -> str:
    file_path = tmp_path / filename
    file_path.write_text(content, encoding="utf-8")
    return str(file_path)


def test_sec007_detects_user_root(tmp_path):
    content = """
FROM python:3.12

USER root

COPY . /app
"""

    file_path = write_dockerfile(tmp_path, content)

    findings = scan_dockerfile(
        file_path,
        "Dockerfile",
    )

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SEC-007"
    assert findings[0]["base_severity"] == "MEDIUM"
    assert "root" in findings[0]["evidence"].lower()


def test_sec007_detects_missing_user_instruction(tmp_path):
    content = """
FROM python:3.12

COPY . /app
CMD ["python", "app.py"]
"""

    file_path = write_dockerfile(tmp_path, content)

    findings = scan_dockerfile(
        file_path,
        "Dockerfile",
    )

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SEC-007"
    assert "No USER instruction found" in findings[0]["evidence"]


def test_sec007_allows_non_root_user(tmp_path):
    content = """
FROM python:3.12

RUN useradd -m appuser
USER appuser

COPY . /app
CMD ["python", "app.py"]
"""

    file_path = write_dockerfile(tmp_path, content)

    findings = scan_dockerfile(
        file_path,
        "Dockerfile",
    )

    assert findings == []


def test_sec007_ignores_non_dockerfile(tmp_path):
    content = """
FROM python:3.12
USER root
"""

    file_path = write_dockerfile(
        tmp_path,
        content,
        "Dockerfile.txt",
    )

    findings = scan_dockerfile(
        file_path,
        "Dockerfile.txt",
    )

    assert findings == []


def test_sec007_detects_lowercase_user_root(tmp_path):
    content = """
FROM python:3.12

user root
"""

    file_path = write_dockerfile(tmp_path, content)

    findings = scan_dockerfile(
        file_path,
        "Dockerfile",
    )

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SEC-007"


def test_sec007_finding_is_about_configuration(tmp_path):
    content = """
FROM python:3.12

USER root
"""

    file_path = write_dockerfile(tmp_path, content)

    findings = scan_dockerfile(
        file_path,
        "Dockerfile",
    )

    assert len(findings) == 1

    assert findings[0]["category"] == "Container"
    assert findings[0]["title"] == (
        "Container runs with elevated privileges"
    )
from app.scanner.ci import scan_ci_workflow


def write_ci_file(
    tmp_path: Path,
    content: str,
    filename: str = "security.yml",
    directory: str = ".github/workflows",
) -> str:
    workflow_dir = tmp_path / directory
    workflow_dir.mkdir(parents=True, exist_ok=True)

    file_path = workflow_dir / filename
    file_path.write_text(content, encoding="utf-8")

    return str(file_path)


def test_sec008_detects_hardcoded_password(tmp_path):
    content = """
name: CI

jobs:
  test:
    runs-on: ubuntu-latest
    env:
      password: "SuperSecret123!"
"""

    file_path = write_ci_file(tmp_path, content)

    findings = scan_ci_workflow(
        file_path,
        ".github/workflows/security.yml",
    )

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SEC-008"
    assert findings[0]["base_severity"] == "HIGH"


def test_sec008_detects_hardcoded_api_key(tmp_path):
    content = """
name: CI

jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      api_key: "sk_test_12345678"
"""

    file_path = write_ci_file(tmp_path, content)

    findings = scan_ci_workflow(
        file_path,
        ".github/workflows/security.yml",
    )

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SEC-008"


def test_sec008_ignores_github_secret_reference(tmp_path):
    content = """
name: CI

jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      API_KEY: ${{ secrets.API_KEY }}
      PASSWORD: ${{ secrets.PASSWORD }}
"""

    file_path = write_ci_file(tmp_path, content)

    findings = scan_ci_workflow(
        file_path,
        ".github/workflows/security.yml",
    )

    assert findings == []


def test_sec008_ignores_non_ci_yaml(tmp_path):
    content = """
password: "SuperSecret123!"
"""

    file_path = write_ci_file(
        tmp_path,
        content,
        filename="config.yml",
        directory="config",
    )

    findings = scan_ci_workflow(
        file_path,
        "config/config.yml",
    )

    assert findings == []


def test_sec008_ignores_non_yaml_workflow(tmp_path):
    content = """
password: "SuperSecret123!"
"""

    file_path = write_ci_file(
        tmp_path,
        content,
        filename="security.json",
    )

    findings = scan_ci_workflow(
        file_path,
        ".github/workflows/security.json",
    )

    assert findings == []


def test_sec008_detects_token_in_workflow(tmp_path):
    content = """
name: CI

jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      deploy_token: "Abc12345Secret"
"""

    file_path = write_ci_file(tmp_path, content)

    findings = scan_ci_workflow(
        file_path,
        ".github/workflows/security.yml",
    )

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SEC-008"
    assert findings[0]["category"] == "CI/CD"

def test_github_parse_valid_url():
    owner, repo = parse_github_url(
        "https://github.com/example/demo"
    )

    assert owner == "example"
    assert repo == "demo"


def test_github_parse_git_url():
    owner, repo = parse_github_url(
        "https://github.com/example/demo.git"
    )

    assert owner == "example"
    assert repo == "demo"


def test_github_parse_rejects_invalid_url():
    invalid_urls = [
        "https://gitlab.com/example/demo",
        "https://github.com/",
        "https://github.com/example",
        "github.com/example/demo",
        "https://github.com/example/demo/issues",
    ]

    for url in invalid_urls:
        try:
            parse_github_url(url)
            assert False, f"Expected rejection for: {url}"
        except ValueError:
            pass


def test_github_default_branch(monkeypatch):
    class FakeResponse:
        def read(self):
            return b'{"default_branch": "main"}'

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            pass

    def fake_urlopen(request, timeout):
        assert "api.github.com/repos/example/demo" in request.full_url
        assert timeout == 20
        return FakeResponse()

    monkeypatch.setattr(
        "urllib.request.urlopen",
        fake_urlopen,
    )

    branch = get_default_branch(
        "example",
        "demo",
    )

    assert branch == "main"


def test_github_download_repository(monkeypatch, tmp_path):
    class FakeResponse:
        headers = {
            "Content-Length": "12"
        }

        def __init__(self):
            self.chunks = [
                b"hello ",
                b"world!",
            ]

        def read(self, size):
            if self.chunks:
                return self.chunks.pop(0)

            return b""

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            pass

    def fake_urlopen(request, timeout):
        return FakeResponse()

    monkeypatch.setattr(
        "urllib.request.urlopen",
        fake_urlopen,
    )

    destination = tmp_path / "repository.zip"

    with patch(
        "app.services.github_service.get_default_branch",
        return_value="main",
    ):

        result = download_github_repository(
            "https://github.com/example/demo",
            str(destination),
        )

    assert result == str(destination)
    assert destination.exists()
    assert destination.read_bytes() == b"hello world!"


def test_github_download_rejects_oversized_content_length(
    monkeypatch,
    tmp_path,
):
    class FakeResponse:
        headers = {
            "Content-Length": "60000000"
        }

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            pass

    def fake_urlopen(request, timeout):
        return FakeResponse()

    monkeypatch.setattr(
        "urllib.request.urlopen",
        fake_urlopen,
    )

    destination = tmp_path / "repository.zip"

    with patch(
        "app.services.github_service.get_default_branch",
        return_value="main",
    ):

        try:
            download_github_repository(
                "https://github.com/example/demo",
                str(destination),
            )
            assert False, "Expected oversized download to be rejected"
        except ValueError as error:
            assert "50 MB" in str(error)


def test_github_download_rejects_stream_over_limit(
    monkeypatch,
    tmp_path,
):
    class FakeResponse:
        headers = {}

        def __init__(self):
            self.remaining = 51 * 1024 * 1024

        def read(self, size):
            if self.remaining <= 0:
                return b""

            chunk_size = min(
                size,
                self.remaining,
            )

            self.remaining -= chunk_size

            return b"x" * chunk_size

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            pass

    def fake_urlopen(request, timeout):
        return FakeResponse()

    monkeypatch.setattr(
        "urllib.request.urlopen",
        fake_urlopen,
    )

    destination = tmp_path / "repository.zip"

    with patch(
        "app.services.github_service.get_default_branch",
        return_value="main",
    ):

        try:
            download_github_repository(
                "https://github.com/example/demo",
                str(destination),
            )
            assert False, "Expected stream limit to be enforced"
        except ValueError as error:
            assert "50 MB" in str(error)
def test_analyze_github_repository(
    tmp_path,
    monkeypatch,
):
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)

    repository_source = tmp_path / "github_repo"
    repository_source.mkdir()

    (repository_source / "app.py").write_text(
        '''
password = "SuperSecret123!"
''',
        encoding="utf-8",
    )

    fake_zip = tmp_path / "github_repo.zip"

    import zipfile

    with zipfile.ZipFile(
        fake_zip,
        "w",
        zipfile.ZIP_DEFLATED,
    ) as archive:
        archive.write(
            repository_source / "app.py",
            "demo-repo/app.py",
        )

    def fake_download(
        github_url,
        destination_zip,
    ):
        assert github_url == (
            "https://github.com/example/demo"
        )

        import shutil

        shutil.copyfile(
            fake_zip,
            destination_zip,
        )

        return destination_zip

    monkeypatch.setattr(
        "app.api.analyze.download_github_repository",
        fake_download,
    )

    response = client.post(
        "/api/analyze",
        data={
            "github_url": (
                "https://github.com/example/demo"
            )
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert "analysis_id" in data
    assert data["status"] == "queued"
def test_github_repository_analysis_completes(
    tmp_path,
    monkeypatch,
):
    import shutil
    import zipfile

    from fastapi.testclient import TestClient

    from app.main import app
    from app.services.analysis_service import ANALYSES

    client = TestClient(app)

    # -----------------------------------------------------
    # Create a fake repository
    # -----------------------------------------------------

    repository_source = tmp_path / "github_repo"
    repository_source.mkdir()

    (repository_source / "app.py").write_text(
        '''
password = "SuperSecret123!"

@app.get("/admin/users")
def admin_users():
    return {"users": []}
''',
        encoding="utf-8",
    )

    # -----------------------------------------------------
    # Create a ZIP that represents the GitHub download
    # -----------------------------------------------------

    fake_zip = tmp_path / "github_repo.zip"

    with zipfile.ZipFile(
        fake_zip,
        "w",
        zipfile.ZIP_DEFLATED,
    ) as archive:
        archive.write(
            repository_source / "app.py",
            "demo-repo/app.py",
        )

    # -----------------------------------------------------
    # Mock GitHub download
    # -----------------------------------------------------

    def fake_download(
        github_url,
        destination_zip,
    ):
        assert github_url == (
            "https://github.com/example/demo"
        )

        shutil.copyfile(
            fake_zip,
            destination_zip,
        )

        return destination_zip

    monkeypatch.setattr(
        "app.api.analyze.download_github_repository",
        fake_download,
    )

    # -----------------------------------------------------
    # Start analysis
    # -----------------------------------------------------

    response = client.post(
        "/api/analyze",
        data={
            "github_url": (
                "https://github.com/example/demo"
            )
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert "analysis_id" in data

    analysis_id = data["analysis_id"]

    # -----------------------------------------------------
    # BackgroundTasks are executed by TestClient.
    # Check the actual analysis result.
    # -----------------------------------------------------

    analysis = ANALYSES.get(analysis_id)

    assert analysis is not None

    assert analysis["status"] in {
        "completed",
        "partial",
    }

    assert analysis["files_analyzed"] >= 1
    assert analysis["findings_count"] >= 1

    # The hardcoded password should have been detected.
    finding_rule_ids = {
        finding["rule_id"]
        for finding in analysis["findings"]
    }

    assert "SEC-001" in finding_rule_ids
def test_scanner_deduplicates_identical_findings():
    from app.scanner.engine import ScannerEngine

    engine = ScannerEngine()

    duplicate_findings = [
        {
            "rule_id": "SEC-001",
            "title": "Potential hardcoded credential",
            "category": "Secrets",
            "file": "config.py",
            "line": 10,
            "evidence": 'password = "secret123"',
            "base_severity": "HIGH",
            "confidence": 0.90,
        },
        {
            "rule_id": "SEC-001",
            "title": "Potential hardcoded credential",
            "category": "Secrets",
            "file": "config.py",
            "line": 10,
            "evidence": 'password = "secret123"',
            "base_severity": "HIGH",
            "confidence": 0.90,
        },
    ]

    unique = engine._deduplicate_findings(
        duplicate_findings
    )

    assert len(unique) == 1
    assert unique[0]["rule_id"] == "SEC-001"
def test_context_risk_production_public_high():
    result = calculate_context_risk(
        base_severity="HIGH",
        exposure="PUBLIC",
        reachability="HIGH",
        environment="PRODUCTION",
        confidence=0.90,
    )

    # 75*0.40 + 100*0.25 + 100*0.20
    # + 100*0.10 + 90*0.05
    # = 89.5 -> 90
    assert result.score == 90
    assert result.level == "CRITICAL"


def test_context_risk_test_local_none():
    result = calculate_context_risk(
        base_severity="HIGH",
        exposure="LOCAL",
        reachability="NONE",
        environment="TEST",
        confidence=0.90,
    )

    # 75*0.40 + 30*0.25 + 10*0.20
    # + 20*0.10 + 90*0.05
    # = 46
    assert result.score == 46
    assert result.level == "LOW"


def test_context_risk_public_context_increases_risk():
    local_result = calculate_context_risk(
        base_severity="HIGH",
        exposure="LOCAL",
        reachability="NONE",
        environment="TEST",
        confidence=0.90,
    )

    public_result = calculate_context_risk(
        base_severity="HIGH",
        exposure="PUBLIC",
        reachability="HIGH",
        environment="PRODUCTION",
        confidence=0.90,
    )

    assert public_result.score > local_result.score
    assert (
        public_result.score - local_result.score
        == 44
    )


def test_context_risk_critical_severity_floor():
    result = calculate_context_risk(
        base_severity="CRITICAL",
        exposure="UNKNOWN",
        reachability="NONE",
        environment="UNKNOWN",
        confidence=0.50,
    )

    assert result.score >= 75


def test_context_risk_confidence_is_bounded():
    high_confidence = calculate_context_risk(
        base_severity="HIGH",
        exposure="PUBLIC",
        reachability="HIGH",
        environment="PRODUCTION",
        confidence=2.0,
    )

    low_confidence = calculate_context_risk(
        base_severity="HIGH",
        exposure="PUBLIC",
        reachability="HIGH",
        environment="PRODUCTION",
        confidence=-1.0,
    )

    # Confidence is clamped to 100 and 0.
    assert high_confidence.score == 90
    assert low_confidence.score == 85