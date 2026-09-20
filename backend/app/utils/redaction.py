import re


MASK = "••••••••"


def redact_evidence(evidence: str) -> str:

    # ---------------------------------------------------------
    # Password / secret / token / API key assignments
    # ---------------------------------------------------------

    evidence = re.sub(
        r'(?i)((?:password|passwd|secret|token|api[_-]?key)'
        r'\s*[:=]\s*)(["\']).*?\2',
        lambda match: (
            match.group(1)
            + match.group(2)
            + MASK
            + match.group(2)
        ),
        evidence,
    )

    # ---------------------------------------------------------
    # PostgreSQL connection strings
    #
    # postgres://username:PASSWORD@host
    # ---------------------------------------------------------

    evidence = re.sub(
        r'(?i)(postgres(?:ql)?://[^/:]+:)([^@]+)(@)',
        lambda match: (
            match.group(1)
            + MASK
            + match.group(3)
        ),
        evidence,
    )

    return evidence