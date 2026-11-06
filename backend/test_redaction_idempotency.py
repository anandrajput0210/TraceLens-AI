from app.utils.redaction import redact_evidence


def test_github_token_redaction_does_not_duplicate_bracket():
    token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
    result = redact_evidence(f"GITHUB_TOKEN={token}")

    assert result == "GITHUB_TOKEN=[REDACTED]"
    assert token not in result


def test_redaction_is_idempotent():
    token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

    first = redact_evidence(f"GITHUB_TOKEN={token}")
    second = redact_evidence(first)

    assert first == second
