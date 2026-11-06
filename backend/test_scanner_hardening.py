"""Hardening tests: several secrets per line, .npmrc, evidence masking, scoring.

Credential-looking values are assembled at runtime so no real-looking secret
is stored in the repository. Every value below is synthetic.
"""

import json
import itertools

from app.risk.scoring import (
    ENVIRONMENT_SCORES,
    EXPOSURE_SCORES,
    REACHABILITY_SCORES,
    SEVERITY_SCORES,
    calculate_context_risk,
)
from app.scanner.engine import ScannerEngine
from app.scanner.secrets import scan_hardcoded_credentials
from app.services.analysis_service import serialize_finding
from app.services.repository_service import discover_files
from app.utils.redaction import redact_evidence

AWS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"
AWS_TEMP_KEY = "ASIA" + "ABCDEFGHIJKLMNOP"
GITHUB_TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
SLACK_TOKEN = "xoxb-" + "1234567890-abcdefghij"
STRIPE_KEY = "sk_live_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7"
GOOGLE_KEY = "AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"
NPM_TOKEN = "npm_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"

PROVIDER_TOKENS = {
    "aws": AWS_KEY,
    "aws_temp": AWS_TEMP_KEY,
    "github": GITHUB_TOKEN,
    "slack": SLACK_TOKEN,
    "stripe": STRIPE_KEY,
    "google": GOOGLE_KEY,
    "npm": NPM_TOKEN,
}


def _scan(root):
    files = discover_files(str(root))
    return ScannerEngine().scan_repository(str(root), files)


# ---------------------------------------------------------
# Several secrets on one line
# ---------------------------------------------------------

def test_minified_line_reports_every_secret(tmp_path):
    (tmp_path / "bundle.js").write_text(
        f'const c={{a:"{AWS_KEY}",t:"{GITHUB_TOKEN}"}};const password="Tr0ub4dor&3xyz";\n',
        encoding="utf-8",
    )
    findings = _scan(tmp_path)

    titles = sorted(f.title for f in findings)
    assert titles == [
        "Hardcoded AWS access key",
        "Hardcoded GitHub token",
        "Potential hardcoded credential",
    ]
    assert {f.line for f in findings} == {1}


def test_compact_json_reports_nested_and_top_level_secrets(tmp_path):
    (tmp_path / "config.json").write_text(
        '{"config": {"password": "Tr0ub4dor&3xyz"}, "apiKey": "Zx9Qw8Er7Ty6Ui5O"}\n',
        encoding="utf-8",
    )
    findings = _scan(tmp_path)
    assert len(findings) == 2


def test_two_tokens_of_the_same_type_on_one_line_are_both_reported(tmp_path):
    other = "ghp_" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2"
    (tmp_path / "a.js").write_text(
        f'x("{GITHUB_TOKEN}"); y("{other}");\n', encoding="utf-8"
    )
    assert len(_scan(tmp_path)) == 2


# ---------------------------------------------------------
# .npmrc
# ---------------------------------------------------------

def test_npmrc_is_discovered_and_scanned(tmp_path):
    (tmp_path / ".npmrc").write_text(
        "registry=https://registry.npmjs.org/\n"
        "//registry.npmjs.org/:_authToken=Zx9Qw8Er7Ty6Ui5OaB3cD4eF\n"
        "//npm.pkg.github.com/:_authToken=${NPM_TOKEN}\n",
        encoding="utf-8",
    )
    paths = [f["path"] for f in discover_files(str(tmp_path))]
    assert paths == [".npmrc"]

    findings = _scan(tmp_path)
    assert [(f.line, f.title) for f in findings] == [
        (2, "Potential hardcoded credential")
    ]


def test_npmrc_provider_token_is_recognised(tmp_path):
    (tmp_path / ".npmrc").write_text(
        f"//registry.npmjs.org/:_authToken={NPM_TOKEN}\n", encoding="utf-8"
    )
    findings = _scan(tmp_path)
    assert [f.title for f in findings] == ["Hardcoded npm access token"]


def test_ordinary_double_slash_comment_is_still_ignored(tmp_path):
    (tmp_path / "app.js").write_text(
        '// password = "Tr0ub4dor&3xyz"\n', encoding="utf-8"
    )
    assert _scan(tmp_path) == []


# ---------------------------------------------------------
# Evidence never carries the raw secret out through the API
# ---------------------------------------------------------

def test_serialized_evidence_never_contains_raw_provider_tokens(tmp_path):
    lines = []
    for index, token in enumerate(PROVIDER_TOKENS.values()):
        lines.append(f'const k{index} = "{token}";')       # innocuous name
        lines.append(f'const apiKey{index} = "{token}";')  # credential name
    (tmp_path / "app.js").write_text("\n".join(lines) + "\n", encoding="utf-8")

    findings = _scan(tmp_path)
    assert findings

    payload = json.dumps([serialize_finding(f) for f in findings])
    for name, token in PROVIDER_TOKENS.items():
        assert token not in payload, f"{name} token leaked into API output"


def test_serialized_evidence_hides_generic_and_json_secrets(tmp_path):
    (tmp_path / "config.json").write_text(
        '{\n  "password": "Tr0ub4dor&3xyz",\n  "apiKey": "Zx9Qw8Er7Ty6Ui5O"\n}\n',
        encoding="utf-8",
    )
    (tmp_path / ".env").write_text(
        "DATABASE_URL=postgres://user:Pa55w0rdReal@db:5432/app\n"
        "API_SECRET=s3cr3tValue!9xQ\n",
        encoding="utf-8",
    )
    payload = json.dumps([serialize_finding(f) for f in _scan(tmp_path)])

    for raw in ("Tr0ub4dor&3xyz", "Zx9Qw8Er7Ty6Ui5O", "Pa55w0rdReal", "s3cr3tValue!9xQ"):
        assert raw not in payload


def test_private_key_header_stays_visible_for_context():
    header = "-----BEGIN RSA PRIVATE KEY-----"
    assert redact_evidence(header) == header


# ---------------------------------------------------------
# Scoring: same finding, production always above test
# ---------------------------------------------------------

def test_production_always_scores_above_test_for_identical_findings():
    for severity, exposure, reachability, confidence in itertools.product(
        SEVERITY_SCORES, EXPOSURE_SCORES, REACHABILITY_SCORES, (0.0, 0.4, 0.9, 1.0)
    ):
        production = calculate_context_risk(
            severity, exposure, reachability, "PRODUCTION", confidence
        )
        test = calculate_context_risk(
            severity, exposure, reachability, "TEST", confidence
        )
        assert production.score > test.score, (
            severity, exposure, reachability, confidence
        )


def test_context_can_still_outrank_environment():
    """A test-file finding with strong exposure may outrank a production one
    with none. That is the point of context scoring, not a defect."""
    exposed_test = calculate_context_risk("HIGH", "PUBLIC", "HIGH", "TEST", 0.9)
    quiet_production = calculate_context_risk("LOW", "LOCAL", "NONE", "PRODUCTION", 0.9)
    assert exposed_test.score > quiet_production.score


# ---------------------------------------------------------
# Private keys: a header alone is only a marker
# ---------------------------------------------------------

PEM_HEADER = "-----BEGIN RSA PRIVATE KEY-----"
PEM_FOOTER = "-----END RSA PRIVATE KEY-----"
# Synthetic base64 body, 64 characters per line, assembled at runtime.
PEM_BODY_LINE = "QUJD" * 16


def test_header_string_alone_is_not_a_finding(tmp_path):
    (tmp_path / "check.py").write_text(
        f'if "{PEM_HEADER}" in text:\n    pass\n', encoding="utf-8"
    )
    (tmp_path / "docs.js").write_text(
        f'const marker = "{PEM_HEADER}";\n', encoding="utf-8"
    )
    assert _scan(tmp_path) == []


def test_header_followed_by_footer_only_is_not_a_finding(tmp_path):
    (tmp_path / "empty.txt.js").write_text(
        f"{PEM_HEADER}\n{PEM_FOOTER}\n", encoding="utf-8"
    )
    assert _scan(tmp_path) == []


def test_embedded_private_key_block_is_critical_on_the_header_line(tmp_path):
    (tmp_path / "key.js").write_text(
        "const pem = `\n"
        f"{PEM_HEADER}\n{PEM_BODY_LINE}\n{PEM_BODY_LINE}\n{PEM_FOOTER}\n`;\n",
        encoding="utf-8",
    )
    findings = _scan(tmp_path)

    assert [(f.title, f.base_severity, f.line) for f in findings] == [
        ("Hardcoded private key", "CRITICAL", 2)
    ]


def test_service_account_json_key_is_one_finding_and_is_masked(tmp_path):
    body = (PEM_BODY_LINE + "\\n") * 2
    (tmp_path / "service.json").write_text(
        '{"type": "service_account", "private_key": '
        f'"{PEM_HEADER}\\n{body}{PEM_FOOTER}\\n", "client_email": "x@y.z"}}\n',
        encoding="utf-8",
    )
    findings = _scan(tmp_path)

    assert [f.title for f in findings] == ["Hardcoded private key"]
    payload = json.dumps([serialize_finding(f) for f in findings])
    assert PEM_BODY_LINE not in payload


def test_placeholder_key_body_is_ignored(tmp_path):
    (tmp_path / "key.js").write_text(
        f"{PEM_HEADER}\n{'x' * 64}\n{PEM_FOOTER}\n", encoding="utf-8"
    )
    assert _scan(tmp_path) == []


# ---------------------------------------------------------
# Several findings on one line have distinct columns
# ---------------------------------------------------------

def test_findings_on_one_line_have_distinct_columns(tmp_path):
    source = tmp_path / "bundle.js"
    source.write_text(
        f'const c={{a:"{AWS_KEY}",t:"{GITHUB_TOKEN}"}};const password="Tr0ub4dor&3xyz";\n',
        encoding="utf-8",
    )
    findings = scan_hardcoded_credentials(str(source), "bundle.js")

    columns = [f["column"] for f in findings]
    assert len(columns) == 3
    assert len(set(columns)) == 3

    line = source.read_text(encoding="utf-8").splitlines()[0]
    assert line[columns[0]:].startswith(AWS_KEY)
    assert any(line[column:].startswith(GITHUB_TOKEN) for column in columns)
