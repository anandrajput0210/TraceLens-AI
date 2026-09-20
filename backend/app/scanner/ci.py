import re
from pathlib import Path


CI_SECRET_PATTERN = re.compile(
    r"(?i)"
    r"(password|token|api[_-]?key|access[_-]?key|secret)"
    r"\s*[:=]\s*"
    r"[\"'][^\"']{8,}[\"']"
)


def scan_ci_workflow(
    file_path: str,
    relative_path: str,
) -> list[dict]:

    path = Path(file_path)

    normalized = relative_path.replace("\\", "/")

    if (
        ".github/workflows/" not in normalized
        or path.suffix.lower() not in {".yml", ".yaml"}
    ):
        return []

    try:
        lines = path.read_text(
            encoding="utf-8",
            errors="ignore",
        ).splitlines()
    except OSError:
        return []

    findings = []

    for line_number, line in enumerate(
        lines,
        start=1,
    ):

        if CI_SECRET_PATTERN.search(line):

            findings.append(
                {
                    "rule_id": "SEC-008",
                    "title": "Credential exposed in CI/CD workflow",
                    "category": "CI/CD",
                    "file": relative_path,
                    "line": line_number,
                    "evidence": line.strip(),
                    "base_severity": "HIGH",
                    "confidence": 0.90,
                }
            )

    return findings