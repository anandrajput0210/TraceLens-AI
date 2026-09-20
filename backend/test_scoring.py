from app.risk.scoring import calculate_context_risk


def test_production_public_reachable_risk():
    result = calculate_context_risk(
        base_severity="CRITICAL",
        exposure="PUBLIC",
        reachability="HIGH",
        environment="PRODUCTION",
        confidence=0.90,
    )

    assert 0 <= result.score <= 100
    assert result.score >= 90
    assert result.level == "CRITICAL"


def test_test_isolated_risk():
    result = calculate_context_risk(
        base_severity="HIGH",
        exposure="LOCAL",
        reachability="NONE",
        environment="TEST",
        confidence=0.90,
    )

    assert 0 <= result.score <= 100
    assert result.score < 75


def test_development_risk():
    result = calculate_context_risk(
        base_severity="HIGH",
        exposure="LOCAL",
        reachability="LOW",
        environment="DEVELOPMENT",
        confidence=0.80,
    )

    assert 0 <= result.score <= 100


def test_production_risk_higher_than_test_risk():
    production = calculate_context_risk(
        base_severity="CRITICAL",
        exposure="PUBLIC",
        reachability="HIGH",
        environment="PRODUCTION",
        confidence=0.90,
    )

    test = calculate_context_risk(
        base_severity="HIGH",
        exposure="LOCAL",
        reachability="NONE",
        environment="TEST",
        confidence=0.90,
    )

    assert production.score > test.score