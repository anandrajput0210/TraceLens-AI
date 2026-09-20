import math
import re
from pathlib import Path


# =========================================================
# SECRET KEYWORDS
# =========================================================

SECRET_KEYWORDS = [
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "access_key",
    "token",
    "auth_token",
    "private_key",
    "database_url",
    "connection_string",
]


# =========================================================
# SAFE VALUE PATTERNS
# =========================================================

SAFE_VALUE_PATTERNS = [
    "os.getenv(",
    "os.environ.get(",
    "process.env.",
    "getenv(",
]


# =========================================================
# COMMON NON-SECRET PATTERNS
# =========================================================

UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-"
    r"[0-9a-f]{4}-"
    r"[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-"
    r"[0-9a-f]{12}$",
    re.IGNORECASE,
)


HEX_HASH_PATTERN = re.compile(
    r"^[0-9a-f]{32,}$",
    re.IGNORECASE,
)


SHA_HASH_PATTERN = re.compile(
    r"^(?:sha1|sha224|sha256|sha384|sha512)[_-]?[0-9a-f]{32,}$",
    re.IGNORECASE,
)


SEMVER_PATTERN = re.compile(
    r"^v?\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?$"
)


HEX_COLOR_PATTERN = re.compile(
    r"^#[0-9a-f]{3,8}$",
    re.IGNORECASE,
)


IP_ADDRESS_PATTERN = re.compile(
    r"^\d{1,3}(?:\.\d{1,3}){3}$"
)


# =========================================================
# BASIC SECRET VALUE CHECK
# =========================================================

def looks_like_secret_value(value: str) -> bool:
    """
    Decide whether an assigned value looks like a real credential.

    This is used by SEC-001.
    """

    value = value.strip().strip("\"'")

    if not value:
        return False

    # -----------------------------------------------------
    # Obvious non-secret values
    # -----------------------------------------------------

    safe_values = {
        "none",
        "null",
        "false",
        "true",
        "password",
        "secret",
        "changeme",
        "your_password",
        "your_secret",
        "example",
        "test",
    }

    if value.lower() in safe_values:
        return False

    # -----------------------------------------------------
    # Environment-variable references are safe
    # -----------------------------------------------------

    for pattern in SAFE_VALUE_PATTERNS:
        if pattern.lower() in value.lower():
            return False

    # -----------------------------------------------------
    # Very short values are unlikely to be real credentials
    # -----------------------------------------------------

    if len(value) < 8:
        return False

    return True


# =========================================================
# SHANNON ENTROPY
# =========================================================

def calculate_entropy(value: str) -> float:
    """
    Calculate Shannon entropy for a string.

    Higher entropy means the characters are distributed
    more randomly.
    """

    if not value:
        return 0.0

    frequencies = {}

    for character in value:
        frequencies[character] = (
            frequencies.get(character, 0) + 1
        )

    entropy = 0.0
    length = len(value)

    for count in frequencies.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


# =========================================================
# NON-SECRET VALUE DETECTION
# =========================================================

def looks_like_obvious_non_secret(value: str) -> bool:
    """
    Detect common structured strings that may have high
    entropy but are not necessarily credentials.

    Examples:
    - UUIDs
    - hashes
    - semantic versions
    - IP addresses
    - hex colors
    """

    value = value.strip().strip("\"'")

    if not value:
        return True

    lower_value = value.lower()

    # -----------------------------------------------------
    # Placeholder values
    # -----------------------------------------------------

    safe_values = {
        "none",
        "null",
        "false",
        "true",
        "password",
        "secret",
        "changeme",
        "your_password",
        "your_secret",
        "example",
        "test",
        "development",
        "production",
        "localhost",
        "default",
    }

    if lower_value in safe_values:
        return True

    # -----------------------------------------------------
    # Environment-variable references
    # -----------------------------------------------------

    for pattern in SAFE_VALUE_PATTERNS:
        if pattern.lower() in lower_value:
            return True

    # -----------------------------------------------------
    # URLs
    # -----------------------------------------------------

    if value.startswith(
        (
            "http://",
            "https://",
            "ftp://",
            "ws://",
            "wss://",
        )
    ):
        return True

    # -----------------------------------------------------
    # File / path-like values
    # -----------------------------------------------------

    if value.startswith(
        (
            "/",
            "./",
            "../",
            ".\\",
            "..\\",
        )
    ):
        return True

    # Windows drive path
    if re.match(r"^[A-Za-z]:[\\/]", value):
        return True

    # -----------------------------------------------------
    # UUID
    # -----------------------------------------------------

    if UUID_PATTERN.fullmatch(value):
        return True

    # -----------------------------------------------------
    # Hash-like values
    # -----------------------------------------------------

    if HEX_HASH_PATTERN.fullmatch(value):
        return True

    if SHA_HASH_PATTERN.fullmatch(value):
        return True

    # -----------------------------------------------------
    # Semantic version
    # -----------------------------------------------------

    if SEMVER_PATTERN.fullmatch(value):
        return True

    # -----------------------------------------------------
    # IPv4 address
    # -----------------------------------------------------

    if IP_ADDRESS_PATTERN.fullmatch(value):
        return True

    # -----------------------------------------------------
    # Hex colour
    # -----------------------------------------------------

    if HEX_COLOR_PATTERN.fullmatch(value):
        return True

    return False


# =========================================================
# HIGH-ENTROPY SECRET DETECTION
# =========================================================

def looks_like_high_entropy_secret(value: str) -> bool:
    """
    Determine whether a string looks like a randomly
    generated hardcoded secret.

    This detector is intentionally conservative.

    SEC-002 should detect suspicious unknown secrets,
    not every random-looking identifier.
    """

    value = value.strip().strip("\"'")

    if not value:
        return False

    # -----------------------------------------------------
    # Minimum length
    # -----------------------------------------------------

    if len(value) < 16:
        return False

    # -----------------------------------------------------
    # Ignore obvious structured/non-secret values
    # -----------------------------------------------------

    if looks_like_obvious_non_secret(value):
        return False

    # -----------------------------------------------------
    # Normal sentences are not secrets
    # -----------------------------------------------------

    if any(character.isspace() for character in value):
        return False

    # -----------------------------------------------------
    # Calculate entropy
    # -----------------------------------------------------

    entropy = calculate_entropy(value)

    # Conservative entropy threshold.
    if entropy < 3.8:
        return False

    # -----------------------------------------------------
    # Character classes
    # -----------------------------------------------------

    has_lower = bool(
        re.search(r"[a-z]", value)
    )

    has_upper = bool(
        re.search(r"[A-Z]", value)
    )

    has_digit = bool(
        re.search(r"\d", value)
    )

    has_special = bool(
        re.search(r"[^A-Za-z0-9]", value)
    )

    character_classes = sum(
        [
            has_lower,
            has_upper,
            has_digit,
            has_special,
        ]
    )

    # -----------------------------------------------------
    # Require multiple character classes.
    #
    # This prevents ordinary identifiers such as:
    # abcdefghijklmnop
    #
    # from becoming findings.
    # -----------------------------------------------------

    if character_classes < 3:
        return False

    return True


# =========================================================
# SEC-002
# HIGH-ENTROPY HARDCODED STRINGS
# =========================================================

def scan_high_entropy_strings(
    file_path: str,
    relative_path: str | None = None,
) -> list[dict]:
    """
    SEC-002:

    Detect suspicious high-entropy hardcoded strings.

    This complements SEC-001 by detecting random-looking
    secrets even when the variable name is not obvious.
    """

    path = Path(file_path)

    try:
        content = path.read_text(
            encoding="utf-8",
            errors="ignore",
        )
    except OSError:
        return []

    findings = []

    for line_number, line in enumerate(
        content.splitlines(),
        start=1,
    ):
        stripped = line.strip()

        # -------------------------------------------------
        # Ignore comments.
        # -------------------------------------------------

        if (
            stripped.startswith("#")
            or stripped.startswith("//")
        ):
            continue

        # -------------------------------------------------
        # Find quoted strings assigned to variables or
        # object/configuration properties.
        #
        # Examples:
        #
        # token = "..."
        # key: "..."
        # secretValue = "..."
        # -------------------------------------------------

        matches = re.finditer(
            r"""
            (?P<name>[A-Za-z_][A-Za-z0-9_]*)
            \s*(?:=|:)
            \s*
            (?P<quote>["'])
            (?P<value>[^"']+)
            (?P=quote)
            """,
            line,
            re.VERBOSE,
        )

        for match in matches:

            # -------------------------------------------------
            # Use the regex capture directly instead of trying
            # to reconstruct the variable name from match.group(0).
            # -------------------------------------------------

            variable_name = match.group("name")
            variable_name_lower = variable_name.lower()

            value = match.group("value")

            # -------------------------------------------------
            # If the variable name clearly indicates a
            # credential, SEC-001 is responsible.
            #
            # This prevents duplicate SEC-001 + SEC-002
            # findings for the same assignment.
            # -------------------------------------------------

            if any(
                keyword in variable_name_lower
                for keyword in SECRET_KEYWORDS
            ):
                continue

            # -------------------------------------------------
            # Apply conservative high-entropy detection.
            # -------------------------------------------------

            if not looks_like_high_entropy_secret(value):
                continue

            entropy = calculate_entropy(value)

            findings.append(
                {
                    "rule_id": "SEC-002",
                    "title": "High-entropy hardcoded string",
                    "category": "Secrets",
                    "file": relative_path or path.name,
                    "line": line_number,
                    "evidence": stripped,
                    "base_severity": "MEDIUM",
                    "confidence": 0.80,
                    "entropy": round(entropy, 2),
                }
            )

    return findings


# =========================================================
# SEC-001
# HARDCODED CREDENTIALS
# =========================================================

def scan_hardcoded_credentials(
    file_path: str,
    relative_path: str | None = None,
) -> list[dict]:
    """
    SEC-001:

    Scan a source file for likely hardcoded credentials.

    This detector does NOT execute the target source code.
    """

    path = Path(file_path)

    try:
        content = path.read_text(
            encoding="utf-8",
            errors="ignore",
        )
    except OSError:
        return []

    findings = []

    for line_number, line in enumerate(
        content.splitlines(),
        start=1,
    ):
        stripped = line.strip()

        # -------------------------------------------------
        # Ignore comments.
        # -------------------------------------------------

        if (
            stripped.startswith("#")
            or stripped.startswith("//")
        ):
            continue

        # -------------------------------------------------
        # Find simple variable assignments.
        #
        # Examples:
        #
        # password = "supersecret"
        # API_TOKEN = "abc..."
        # database_url = "postgres://..."
        # -------------------------------------------------

        match = re.search(
            r"""
            (?P<name>[A-Za-z_][A-Za-z0-9_]*)
            \s*(?:=|:)
            \s*
            (?P<value>
                ["'][^"']+["']
                |
                [^,\s]+
            )
            """,
            line,
            re.VERBOSE,
        )

        if not match:
            continue

        # -------------------------------------------------
        # Extract the variable name directly.
        # -------------------------------------------------

        variable_name = match.group("name")
        variable_name_lower = variable_name.lower()

        value = match.group("value")

        # -------------------------------------------------
        # Check whether the variable name indicates a
        # credential.
        # -------------------------------------------------

        is_credential_name = any(
            keyword in variable_name_lower
            for keyword in SECRET_KEYWORDS
        )

        if not is_credential_name:
            continue

        # -------------------------------------------------
        # Check whether the assigned value looks like a
        # real hardcoded credential.
        # -------------------------------------------------

        if not looks_like_secret_value(value):
            continue

        findings.append(
            {
                "rule_id": "SEC-001",
                "title": "Potential hardcoded credential",
                "category": "Secrets",
                "file": relative_path or path.name,
                "line": line_number,
                "evidence": stripped,
                "base_severity": "HIGH",
                "confidence": 0.90,
            }
        )

    return findings