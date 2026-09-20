from pathlib import Path
import re


PUBLIC_SIGNALS = [
    "0.0.0.0",
    "allow_origins=['*']",
    'allow_origins=["*"]',
    'origin: "*"',
    'origin:"*"',
    "public=true",
    "public: true",
]


ROUTE_PATTERNS = [
    r"@app\.(get|post|put|delete|patch)\(",
    r"@router\.(get|post|put|delete|patch)\(",
    r"app\.(get|post|put|delete|patch)\(",
    r"router\.(get|post|put|delete|patch)\(",
]


def detect_exposure(file_path: str) -> tuple[str, float]:
    """
    Estimate whether a file contains evidence of public exposure.

    This is contextual evidence, not proof of exploitability.
    """

    path = Path(file_path)

    try:
        content = path.read_text(
            encoding="utf-8",
            errors="ignore",
        )
    except OSError:
        return "UNKNOWN", 0.40

    content_lower = content.lower()

    # --------------------------------------------------
    # Explicit public bind / public configuration
    # --------------------------------------------------

    for signal in PUBLIC_SIGNALS:
        if signal.lower() in content_lower:
            return "PUBLIC", 0.90

    # --------------------------------------------------
    # Application routes
    # --------------------------------------------------

    for pattern in ROUTE_PATTERNS:
        if re.search(pattern, content):
            return "PUBLIC", 0.75

    # --------------------------------------------------
    # Docker port exposure
    # --------------------------------------------------

    if re.search(
        r"^\s*EXPOSE\s+\d+",
        content,
        re.IGNORECASE | re.MULTILINE,
    ):
        return "PUBLIC", 0.70

    # --------------------------------------------------
    # No direct exposure evidence
    # --------------------------------------------------

    return "LOCAL", 0.50