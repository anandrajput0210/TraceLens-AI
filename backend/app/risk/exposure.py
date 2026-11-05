from pathlib import Path
import re


# These signals are deliberately narrow. A generic route declaration, a Docker
# EXPOSE instruction, wildcard CORS, or a 0.0.0.0 bind does not prove that an
# application is reachable from the public internet.
PUBLIC_PATTERNS = (
    re.compile(
        r"\b(?:publicly[_-]?accessible|public[_-]?access|internet[_-]?facing)"
        r"\b\s*[:=]\s*(?:true|yes|1)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:acl|accesscontrol)\b\s*[:=]\s*['\"]public-read(?:-write)?['\"]",
        re.IGNORECASE,
    ),
)

ALL_INTERFACE_BIND_PATTERNS = (
    # Bind evidence is scoped to recognizable application-server invocations,
    # common server-host environment variables, or an explicit --host option.
    # A generic host field may describe a database client, not the web server.
    re.compile(
        r"\b(?:app|application|server|uvicorn|web)\.(?:run|listen|serve)\s*\([^)]*\bhost\s*[:=]\s*['\"]?0\.0\.0\.0\b",
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(r"--host(?:\s+|=)['\"]?0\.0\.0\.0\b", re.IGNORECASE),
    re.compile(
        r"^\s*(?:HOST|BIND_HOST|SERVER_HOST|LISTEN_HOST)\s*=\s*['\"]?0\.0\.0\.0\b",
        re.IGNORECASE | re.MULTILINE,
    ),
)

LOOPBACK_BIND_PATTERNS = (
    re.compile(
        r"\b(?:app|application|server|uvicorn|web)\.(?:run|listen|serve)\s*\([^)]*\bhost\s*[:=]\s*['\"]?(?:localhost|127\.0\.0\.1|::1)\b",
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(
        r"--host(?:\s+|=)['\"]?(?:localhost|127\.0\.0\.1|::1)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"^\s*(?:HOST|BIND_HOST|SERVER_HOST|LISTEN_HOST)\s*=\s*['\"]?(?:localhost|127\.0\.0\.1|::1)\b",
        re.IGNORECASE | re.MULTILINE,
    ),
)


def detect_exposure(file_path: str) -> tuple[str, float]:
    """Return an evidence-based exposure estimate, not an internet-reachability verdict.

    PUBLIC is reserved for explicit public-access configuration signals.
    A 0.0.0.0 bind indicates listening on all interfaces, but routing/firewall
    controls are outside this file-level analysis, so the result is UNKNOWN.
    Route declarations and Docker EXPOSE metadata also do not prove public access.
    """
    path = Path(file_path)

    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return "UNKNOWN", 0.40

    for pattern in PUBLIC_PATTERNS:
        if pattern.search(content):
            return "PUBLIC", 0.85

    if any(pattern.search(content) for pattern in ALL_INTERFACE_BIND_PATTERNS):
        return "UNKNOWN", 0.65

    if any(pattern.search(content) for pattern in LOOPBACK_BIND_PATTERNS):
        return "LOCAL", 0.70

    # A route or Docker EXPOSE entry is not enough to infer internet exposure.
    return "UNKNOWN", 0.40
