from dataclasses import dataclass, field


@dataclass
class Finding:
    id: str
    rule_id: str
    title: str
    category: str
    file: str
    line: int
    evidence: str
    base_severity: str
    confidence: float

    environment: str = "UNKNOWN"
    environment_confidence: float = 0.0

    exposure: str = "UNKNOWN"
    exposure_confidence: float = 0.0

    reachability: str = "NONE"

    context_score: float = 0.0
    risk_level: str = "INFO"

    risk_path: list[str] = field(default_factory=list)

    explanation: str | None = None
    impact: str | None = None
    remediation: str | None = None