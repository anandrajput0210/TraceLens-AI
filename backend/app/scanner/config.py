from pathlib import Path
import re

def is_production_config(relative_path: str) -> bool:
    """
    Determine whether a file appears to be a production
    configuration file based on its repository path/name.
    """

    normalized_path = relative_path.replace("\\", "/").lower()

    production_names = {
        "production.py",
        "production.json",
        "production.yml",
        "production.yaml",
        "production.js",
        "production.ts",
        "prod.py",
        "prod.json",
        "prod.yml",
        "prod.yaml",
        "prod.js",
        "prod.ts",
    }

    file_name = Path(normalized_path).name

    if file_name in production_names:
        return True

    # Common production configuration directories.
    production_directories = {
        "/production/",
        "/prod/",
        "/config/production/",
        "/config/prod/",
    }

    return any(
        directory in f"/{normalized_path}"
        for directory in production_directories
    )
def scan_config_security(
    file_path: str,
    relative_path: str,
) -> list[dict]:

    path = Path(file_path)

    try:
        content = path.read_text(
            encoding="utf-8",
            errors="ignore",
        )
    except OSError:
        return []

    findings = []
    # =====================================================
    # SEC-003 — PRODUCTION CONFIGURATION EXPOSURE
    # =====================================================

    if is_production_config(relative_path):

        findings.append(
            {
                "rule_id": "SEC-003",
                "title": "Production configuration exposed",
                "category": "Configuration",
                "file": relative_path,
                "line": 1,
                "evidence": (
                    "Production configuration file detected"
                ),
                "base_severity": "MEDIUM",
                "confidence": 0.90,
            }
        )
    for line_number, line in enumerate(
        content.splitlines(),
        start=1,
    ):

        stripped = line.strip()

        # =====================================================
        # SEC-004 — DEBUG MODE
        # =====================================================

        debug_patterns = [
            r"\bDEBUG\s*=\s*True\b",
            r"\bdebug\s*=\s*True\b",
            r"\.run\s*\([^)]*debug\s*=\s*True",
            r'["\']DEBUG["\']\s*\]\s*=\s*True',
        ]

        if any(
            re.search(
                pattern,
                line,
                re.IGNORECASE,
            )
            for pattern in debug_patterns
        ):

            findings.append(
                {
                    "rule_id": "SEC-004",
                    "title": "Debug mode enabled",
                    "category": "Configuration",
                    "file": relative_path,
                    "line": line_number,
                    "evidence": stripped,
                    "base_severity": "MEDIUM",
                    "confidence": 0.90,
                }
            )

        # =====================================================
        # SEC-005 — PERMISSIVE CORS
        # =====================================================

        cors_patterns = [
            r"allow_origins\s*=\s*\[\s*[\"']\*[\"']",
            r"origins\s*=\s*[\"']\*[\"']",
            r"origin\s*[:=]\s*[\"']\*[\"']",
            r"CORS\s*\([^)]*origins\s*=\s*[\"']\*[\"']",
        ]

        if any(
            re.search(
                pattern,
                line,
                re.IGNORECASE,
            )
            for pattern in cors_patterns
        ):

            findings.append(
                {
                    "rule_id": "SEC-005",
                    "title": "Potentially unsafe CORS configuration",
                    "category": "Configuration",
                    "file": relative_path,
                    "line": line_number,
                    "evidence": stripped,
                    "base_severity": "MEDIUM",
                    "confidence": 0.85,
                }
            )

    return findings
# =========================================================
# SEC-003 DEDICATED SCANNER
# PRODUCTION CONFIGURATION EXPOSURE
# =========================================================

PRODUCTION_VALUES = {
    "production",
    "prod",
    "live",
}


SENSITIVE_CONFIG_KEYWORDS = [
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "token",
    "auth_token",
    "private_key",
    "database_url",
    "database_uri",
    "connection_string",
    "credentials",
]


PRODUCTION_FILE_PATTERNS = {
    ".env.production",
    ".env.prod",
    "production.py",
    "prod.py",
    "production.json",
    "prod.json",
    "production.yaml",
    "production.yml",
    "prod.yaml",
    "prod.yml",
}


def is_production_filename(relative_path: str) -> bool:
    """
    Determine whether the file path strongly indicates
    production configuration.
    """

    path = Path(relative_path)

    filename = path.name.lower()

    if filename in PRODUCTION_FILE_PATTERNS:
        return True

    parts = {
        part.lower()
        for part in path.parts
    }

    if "production" in parts:
        return True

    if "prod" in parts:
        return True

    return False


def contains_production_environment(content: str) -> bool:
    """
    Determine whether the file explicitly declares
    a production environment.
    """

    pattern = re.compile(
        r"""
        (?:
            environment
            |
            env
            |
            node_env
            |
            app_env
            |
            deployment_environment
        )
        \s*(?:=|:)
        \s*
        ["']?
        (production|prod|live)
        ["']?
        """,
        re.IGNORECASE | re.VERBOSE,
    )

    return bool(pattern.search(content))


def is_production_context(
    relative_path: str,
    content: str,
) -> bool:
    """
    Determine whether the file appears to belong to
    a production environment.
    """

    if is_production_filename(relative_path):
        return True

    return contains_production_environment(content)


def find_sensitive_configuration(line: str) -> str | None:
    """
    Find a security-sensitive configuration variable
    in a line.
    """

    match = re.search(
        r"""
        (?P<name>
            [A-Za-z_][A-Za-z0-9_]*
        )
        \s*(?:=|:)
        """,
        line,
        re.VERBOSE,
    )

    if not match:
        return None

    variable_name = match.group("name")
    variable_name_lower = variable_name.lower()

    for keyword in SENSITIVE_CONFIG_KEYWORDS:
        if keyword in variable_name_lower:
            return variable_name

    return None


def scan_production_config(
    file_path: str,
    relative_path: str | None = None,
) -> list[dict]:
    """
    SEC-003:

    Detect security-sensitive configuration that appears
    to belong to a production environment.

    Requires:

        1. Production context
        2. Security-sensitive configuration

    The word "production" alone is not enough.
    """

    path = Path(file_path)

    try:
        content = path.read_text(
            encoding="utf-8",
            errors="ignore",
        )
    except OSError:
        return []

    display_path = relative_path or path.name

    # -----------------------------------------------------
    # Establish production context.
    # -----------------------------------------------------

    if not is_production_context(
        display_path,
        content,
    ):
        return []

    findings = []

    # -----------------------------------------------------
    # Examine configuration lines.
    # -----------------------------------------------------

    for line_number, line in enumerate(
        content.splitlines(),
        start=1,
    ):
        stripped = line.strip()

        if not stripped:
            continue

        if (
            stripped.startswith("#")
            or stripped.startswith("//")
        ):
            continue

        variable_name = find_sensitive_configuration(
            line
        )

        if variable_name is None:
            continue

        findings.append(
            {
                "rule_id": "SEC-003",
                "title": "Sensitive production configuration",
                "category": "Configuration",
                "file": display_path.replace("\\", "/"),
                "line": line_number,
                "evidence": stripped,
                "base_severity": "HIGH",
                "confidence": 0.85,
            }
        )

    return findings