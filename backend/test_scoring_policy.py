from app.risk.scoring import (
    CRITICAL_SCORE_FLOOR,
    RISK_LEVEL_THRESHOLDS,
    calculate_context_risk,
    get_risk_level,
    scoring_policy,
)


def test_policy_levels_match_classification_at_every_boundary():
    policy = scoring_policy()

    for entry in policy["levels"]:
        assert get_risk_level(entry["min"]) == entry["level"]
        assert get_risk_level(entry["min"] - 1) != entry["level"]

    assert get_risk_level(0) == "INFO"
    assert get_risk_level(100) == "CRITICAL"


def test_policy_levels_are_listed_lowest_first():
    minimums = [entry["min"] for entry in scoring_policy()["levels"]]
    assert minimums == sorted(minimums)
    assert len(minimums) == len(RISK_LEVEL_THRESHOLDS)


def test_policy_reports_the_floor_the_scorer_applies():
    policy = scoring_policy()
    assert policy["critical_floor"] == CRITICAL_SCORE_FLOOR

    production = calculate_context_risk("CRITICAL", "LOW", "NONE", "PRODUCTION", 0.1)
    test = calculate_context_risk("CRITICAL", "LOW", "NONE", "TEST", 0.1)
    assert production.score >= policy["critical_floor"]["default"]
    assert test.score >= policy["critical_floor"]["test"]
