from app.models.finding import Finding
from app.risk.scoring import calculate_context_risk
from app.scanner import engine as scanner_engine_module
from app.scanner.engine import ScannerEngine
from app.services.repository_service import discover_files


def test_unknown_reachability_scores_more_conservatively_than_none():
    common = {
        "base_severity": "HIGH",
        "exposure": "UNKNOWN",
        "environment": "UNKNOWN",
        "confidence": 0.8,
    }
    unknown = calculate_context_risk(reachability="UNKNOWN", **common)
    explicit_none = calculate_context_risk(reachability="NONE", **common)

    # UNKNOWN receives a reachability score of 40; explicit NONE remains 10.
    # The 30-point signal difference weighted at 20% yields a +6 risk score.
    assert unknown.score - explicit_none.score == 6


def test_missing_static_path_is_reported_as_unknown(tmp_path, monkeypatch):
    source = tmp_path / "app.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")

    def synthetic_finding(_absolute_path, relative_path):
        return [{
            "rule_id": "SEC-001",
            "title": "Synthetic credential finding",
            "category": "Secrets",
            "file": relative_path,
            "line": 1,
            "evidence": 'PASSWORD = "synthetic-test-value"',
            "base_severity": "HIGH",
            "confidence": 0.9,
        }]

    monkeypatch.setattr(scanner_engine_module, "scan_hardcoded_credentials", synthetic_finding)
    monkeypatch.setattr(scanner_engine_module, "find_public_risk_path", lambda *_args, **_kwargs: [])

    files = discover_files(str(tmp_path))
    findings = ScannerEngine().scan_repository(str(tmp_path), files)

    assert findings
    assert findings[0].reachability == "UNKNOWN"


def test_finding_default_reachability_is_unknown():
    finding = Finding(
        id="F001", rule_id="SEC-001", title="Test", category="Secrets",
        file="app.py", line=1, evidence="redacted", base_severity="HIGH",
        confidence=0.8,
    )
    assert finding.reachability == "UNKNOWN"
