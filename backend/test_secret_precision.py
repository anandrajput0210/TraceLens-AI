from app.scanner.secrets import (
    scan_hardcoded_credentials,
    scan_high_entropy_strings,
)


def _write(tmp_path, content: str):
    source = tmp_path / "sample.py"
    source.write_text(content, encoding="utf-8")
    return source


def test_ignores_github_actions_secret_reference(tmp_path):
    source = _write(
        tmp_path,
        'DEPLOY_TOKEN = "${{ secrets.DEPLOY_TOKEN }}"\n',
    )

    assert scan_hardcoded_credentials(str(source), "workflow.yml") == []


def test_ignores_shell_and_braced_environment_references(tmp_path):
    source = _write(
        tmp_path,
        'API_TOKEN = "$DEPLOY_TOKEN"\nPASSWORD = "${DATABASE_PASSWORD}"\n',
    )

    assert scan_hardcoded_credentials(str(source), "config.py") == []


def test_ignores_explicit_placeholder_values(tmp_path):
    source = _write(
        tmp_path,
        'api_key = "example-api-key-123456"\n'
        'password = "testPassword123"\n'
        'DEPLOY_TOKEN = "demoDeploymentToken12345"\n'
        'client_secret = "replace-me-before-deploy"\n',
    )

    assert scan_hardcoded_credentials(str(source), "fixtures.py") == []


def test_high_entropy_detector_ignores_marked_placeholder(tmp_path):
    source = _write(
        tmp_path,
        'build_value = "example-A9xQ7pLm2Nw4Rk8Z"\n',
    )

    assert scan_high_entropy_strings(str(source), "example.py") == []


def test_still_detects_non_placeholder_hardcoded_secret(tmp_path):
    source = _write(
        tmp_path,
        'API_TOKEN = "AbC123!defGhI456jkl"\n',
    )

    findings = scan_hardcoded_credentials(str(source), "app_config.py")
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SEC-001"
