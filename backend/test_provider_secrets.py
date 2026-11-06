from app.risk.scoring import calculate_context_risk
from app.scanner.secrets import (
    scan_hardcoded_credentials,
    scan_high_entropy_strings,
)
from app.services.repository_service import discover_files

AWS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"  # 20 chars, built so no real key is in the repo
GITHUB_TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"  # 40 chars


def _write(tmp_path, content: str, name: str = "settings.py"):
    source = tmp_path / name
    source.write_text(content, encoding="utf-8")
    return source


def test_aws_key_gets_specific_title_and_critical_severity(tmp_path):
    source = _write(tmp_path, f'AWS_ACCESS_KEY_ID = "{AWS_KEY}"\n')
    findings = scan_hardcoded_credentials(str(source), "settings.py")

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SEC-001"
    assert findings[0]["title"] == "Hardcoded AWS access key"
    assert findings[0]["base_severity"] == "CRITICAL"


def test_github_token_detected_whatever_the_variable_is_called(tmp_path):
    source = _write(tmp_path, f'build_value = "{GITHUB_TOKEN}"\n')

    findings = scan_hardcoded_credentials(str(source), "settings.py")
    assert [f["title"] for f in findings] == ["Hardcoded GitHub token"]
    # The generic entropy rule must not report the same value again.
    assert scan_high_entropy_strings(str(source), "settings.py") == []


def test_documentation_example_key_is_ignored(tmp_path):
    source = _write(tmp_path, 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n')
    assert scan_hardcoded_credentials(str(source), "settings.py") == []


def test_redaction_marker_is_not_a_finding(tmp_path):
    source = _write(
        tmp_path,
        'AWS_ACCESS_KEY_ID = "[REDACTED_BY_SENTINELZERO]"\napi_key = "***"\n',
    )
    assert scan_hardcoded_credentials(str(source), "settings.py") == []


def test_generic_password_stays_generic(tmp_path):
    source = _write(tmp_path, 'database_password = "Tr0ub4dor&3xyz"\n')
    findings = scan_hardcoded_credentials(str(source), "settings.py")

    assert len(findings) == 1
    assert findings[0]["title"] == "Potential hardcoded credential"
    assert findings[0]["base_severity"] == "HIGH"


def test_discovery_skips_backup_and_hidden_directories(tmp_path):
    (tmp_path / ".sentinelzero_backups").mkdir()
    (tmp_path / ".sentinelzero_backups" / "old_settings.py").write_text("x = 1\n")
    (tmp_path / "config_backup").mkdir()
    (tmp_path / "config_backup" / "settings.py").write_text("x = 1\n")
    (tmp_path / "app.py").write_text("x = 1\n")
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text("name: ci\n")

    paths = sorted(f["path"].replace("\\", "/") for f in discover_files(str(tmp_path)))
    assert paths == [".github/workflows/ci.yml", "app.py"]


def test_discovery_works_when_repo_sits_under_a_build_directory(tmp_path):
    repo = tmp_path / "build" / "dist" / "repo"
    repo.mkdir(parents=True)
    (repo / "app.py").write_text("x = 1\n")

    paths = [f["path"] for f in discover_files(str(repo))]
    assert paths == ["app.py"]


def test_critical_in_test_context_ranks_below_production():
    kwargs = dict(
        base_severity="CRITICAL",
        exposure="UNKNOWN",
        reachability="UNKNOWN",
        confidence=0.4,
    )
    production = calculate_context_risk(environment="PRODUCTION", **kwargs)
    test = calculate_context_risk(environment="TEST", **kwargs)

    assert production.level == "HIGH"
    assert production.score > test.score
