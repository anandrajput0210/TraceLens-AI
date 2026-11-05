from dataclasses import dataclass


SEVERITY_SCORES = {
    "CRITICAL": 100,
    "HIGH": 75,
    "MEDIUM": 50,
    "LOW": 25,
    "INFO": 10,
}

EXPOSURE_SCORES = {
    "PUBLIC": 100,
    "INTERNAL": 60,
    "LOCAL": 30,
    "UNKNOWN": 40,
}

# A missing static path is uncertainty, not proof of no reachability.
REACHABILITY_SCORES = {
    "HIGH": 100,
    "MEDIUM": 70,
    "LOW": 40,
    # NONE is retained for callers that explicitly use that state.
    "NONE": 10,
    "UNKNOWN": 40,
}

ENVIRONMENT_SCORES = {
    "PRODUCTION": 100,
    "DEVELOPMENT": 50,
    "TEST": 20,
    "UNKNOWN": 40,
}


@dataclass
class RiskResult:
    score: int
    level: str


def calculate_context_risk(
    base_severity: str,
    exposure: str,
    reachability: str,
    environment: str,
    confidence: float,
) -> RiskResult:

    severity_score = SEVERITY_SCORES.get(
        base_severity.upper(),
        10,
    )

    exposure_score = EXPOSURE_SCORES.get(
        exposure.upper(),
        40,
    )

    reachability_score = REACHABILITY_SCORES.get(
        reachability.upper(),
        40,
    )

    environment_score = ENVIRONMENT_SCORES.get(
        environment.upper(),
        40,
    )

    confidence_score = max(
        0,
        min(100, confidence * 100),
    )

    # ---------------------------------------------------------
    # TraceLens Context Risk formula
    #
    # Severity      40%
    # Exposure      25%
    # Reachability  20%
    # Environment   10%
    # Confidence     5%
    # ---------------------------------------------------------

    score = (
        severity_score * 0.40
        + exposure_score * 0.25
        + reachability_score * 0.20
        + environment_score * 0.10
        + confidence_score * 0.05
    )

    score = round(score)

    # ---------------------------------------------------------
    # Severity floor
    #
    # A CRITICAL finding should never become LOW merely
    # because context information is incomplete.
    # ---------------------------------------------------------

    if base_severity.upper() == "CRITICAL":
        score = max(score, 75)

    level = get_risk_level(score)

    return RiskResult(
        score=score,
        level=level,
    )


def get_risk_level(score: int) -> str:

    if score >= 90:
        return "CRITICAL"

    if score >= 75:
        return "HIGH"

    if score >= 50:
        return "MEDIUM"

    if score >= 25:
        return "LOW"

    return "INFO"