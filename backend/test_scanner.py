from pathlib import Path
from app.scanner.secrets import scan_high_entropy_strings
from app.scanner.engine import ScannerEngine
from app.services.repository_service import discover_files

DEMO_REPO_PATH = str(
    Path(__file__).resolve().parents[1] / "demo-repo"
)

EXPECTED_DEMO_RULES = {
    "SEC-001",
    "SEC-003",
    "SEC-004",
    "SEC-005",
    "SEC-006",
    "SEC-007",
    "SEC-008",
}

def test_scanner_finds_expected_rules():
    repository_path = DEMO_REPO_PATH

    files = discover_files(repository_path)

    engine = ScannerEngine()

    findings = engine.scan_repository(
        repository_path,
        files,
    )

    detected_rules = {
        finding.rule_id
        for finding in findings
    }

    missing_rules = EXPECTED_DEMO_RULES - detected_rules

    assert not missing_rules, (
        f"Expected security rules were not detected: {missing_rules}"
    )


def test_scanner_returns_findings():
    repository_path = DEMO_REPO_PATH

    files = discover_files(repository_path)

    engine = ScannerEngine()

    findings = engine.scan_repository(
        repository_path,
        files,
    )

    assert len(findings) > 0


def test_findings_have_valid_scores():
    repository_path = DEMO_REPO_PATH

    files = discover_files(repository_path)

    engine = ScannerEngine()

    findings = engine.scan_repository(
        repository_path,
        files,
    )

    for finding in findings:
        assert 0 <= finding.context_score <= 100
        assert 0 <= finding.confidence <= 1
        assert 0 <= finding.environment_confidence <= 1
        assert 0 <= finding.exposure_confidence <= 1


def test_production_credential_does_not_overclaim_public_reachability():
    repository_path = str(Path(__file__).resolve().parents[1] / "demo-repo")

    files = discover_files(repository_path)
    engine = ScannerEngine()
    findings = engine.scan_repository(repository_path, files)

    production_findings = [
        finding
        for finding in findings
        if finding.file.replace("\\", "/") == "config/production.py"
        and finding.rule_id == "SEC-001"
    ]

    assert production_findings

    finding = production_findings[0]
    assert finding.environment == "PRODUCTION"
    assert finding.exposure == "UNKNOWN"
    assert finding.reachability == "MEDIUM"
    assert finding.risk_path
    assert 0 <= finding.context_score <= 100

def test_high_entropy_secret_detection(tmp_path):
    test_file = tmp_path / "secret.py"

    test_file.write_text(
        'config_value = "aB7$xQ9!mK2@pL8#vN4&zR6"\n',
        encoding="utf-8",
    )

    findings = scan_high_entropy_strings(
        str(test_file),
        "secret.py",
    )

    assert findings

    assert any(
        finding["rule_id"] == "SEC-002"
        for finding in findings
    )