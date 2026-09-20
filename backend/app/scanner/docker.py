from pathlib import Path


def scan_dockerfile(
    file_path: str,
    relative_path: str,
) -> list[dict]:

    path = Path(file_path)

    if path.name.lower() != "dockerfile":
        return []

    try:
        lines = path.read_text(
            encoding="utf-8",
            errors="ignore",
        ).splitlines()
    except OSError:
        return []

    findings = []

    has_user = False

    for line_number, line in enumerate(
        lines,
        start=1,
    ):

        stripped = line.strip()

        if not stripped:
            continue

        if stripped.upper().startswith("USER "):

            has_user = True

            if stripped.upper() == "USER ROOT":

                findings.append(
                    {
                        "rule_id": "SEC-007",
                        "title": "Container runs with elevated privileges",
                        "category": "Container",
                        "file": relative_path,
                        "line": line_number,
                        "evidence": stripped,
                        "base_severity": "MEDIUM",
                        "confidence": 0.95,
                    }
                )

    # No USER instruction means the image may run
    # as the base image's default user.
    if not has_user:

        findings.append(
            {
                "rule_id": "SEC-007",
                "title": "Container user is not explicitly restricted",
                "category": "Container",
                "file": relative_path,
                "line": 1,
                "evidence": "No USER instruction found",
                "base_severity": "MEDIUM",
                "confidence": 0.75,
            }
        )

    return findings