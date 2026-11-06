import math
import re
from pathlib import Path

from app.utils.provider_tokens import PRIVATE_KEY_HEADER, PROVIDER_TOKEN_RULES


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
    "os.environ[",
    "process.env.",
    "process.env[",
    "import.meta.env",
    "deno.env.get(",
    "getenv(",
]

# Explicit placeholder markers and references are not literal credentials.
# Keep these patterns narrow: arbitrary strings in test files are still scanned.
SAFE_REFERENCE_PATTERNS = (
    re.compile(r"^\$\{\{\s*(?:secrets|vars|env)\.[A-Za-z_][A-Za-z0-9_-]*\s*\}\}$", re.IGNORECASE),
    re.compile(r"^\$\{\s*[A-Za-z_][A-Za-z0-9_]*\s*\}$"),
    re.compile(r"^\$[A-Za-z_][A-Za-z0-9_]*$"),
)

PLACEHOLDER_TOKEN_PATTERN = re.compile(
    r"(?i)(?:^|[._:/\-\[\]<>{}*])(?:demo|dummy|example|sample|fake|placeholder|"
    r"changeme|replace[-_]?me|redacted)(?:$|[._:/\-\[\]<>{}*])"
)

# Redaction markers written by other tools, e.g. "[REDACTED_BY_TOOL]" or "***".
REDACTION_MARKER_PATTERN = re.compile(
    r"^(?:\[\s*redacted[^\]]*\]|<\s*redacted[^>]*>|\*{3,}|x{6,}|\.{3,})$",
    re.IGNORECASE,
)

CAMEL_PLACEHOLDER_PREFIX_PATTERN = re.compile(
    r"^(?i:demo|dummy|example|sample|fake|placeholder|redacted)[A-Z][A-Za-z0-9_-]*$"
)

TEST_PLACEHOLDER_PATTERN = re.compile(
    r"^(?:test|testing)(?:password|secret|token|key|credential|value|placeholder)[A-Za-z0-9_-]*$", re.IGNORECASE
)


# Sample credentials published in vendor documentation.
KNOWN_SAMPLE_VALUES = {
    "AKIAIOSFODNN7EXAMPLE",
    "AKIAI44QH8DHBEXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
}

# AWS documentation style access key ids: AKIA + letters/digits + EXAMPLE.
AWS_SAMPLE_KEY_PATTERN = re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{0,16}EXAMPLE[0-9A-Z]{0,4}")


# Template-style values such as "your-token-here" or "<your-stripe-key>".
# The marker words count only when the WHOLE value is a short phrase of plain
# words. A value with digits or long random chunks (abc_your_def_123456) is
# never treated as a placeholder just because it contains one of these words.
PLACEHOLDER_PHRASE_PATTERN = re.compile(
    r"<?[A-Za-z]{1,8}(?:[-_. ][A-Za-z]{1,8}){1,5}>?"
)
PLACEHOLDER_PHRASE_WORDS = {"your", "insert", "todo", "tbd", "here"}


def looks_like_placeholder_phrase(value: str) -> bool:
    if not PLACEHOLDER_PHRASE_PATTERN.fullmatch(value):
        return False

    words = re.split(r"[-_. <>]+", value.lower())
    return any(word in PLACEHOLDER_PHRASE_WORDS for word in words)


def is_placeholder_or_reference(value: str) -> bool:
    """Return True only for clearly labelled placeholders or variable references."""
    value = value.strip().strip("\"'")
    if not value:
        return False
    if any(pattern.fullmatch(value) for pattern in SAFE_REFERENCE_PATTERNS):
        return True
    if REDACTION_MARKER_PATTERN.fullmatch(value):
        return True
    # Documented sample credentials only (not any value ending in EXAMPLE).
    if value in KNOWN_SAMPLE_VALUES or AWS_SAMPLE_KEY_PATTERN.fullmatch(value):
        return True
    if PLACEHOLDER_TOKEN_PATTERN.search(value):
        return True
    if looks_like_placeholder_phrase(value):
        return True
    if CAMEL_PLACEHOLDER_PREFIX_PATTERN.fullmatch(value):
        return True
    if TEST_PLACEHOLDER_PATTERN.fullmatch(value):
        return True
    return False



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


# npm registry auth lines, e.g. //registry.npmjs.org/:_authToken=...
NPMRC_AUTH_LINE_PATTERN = re.compile(
    r"^//[^\s=]+:_(?:authToken|auth|password)\s*=", re.IGNORECASE
)


# =========================================================
# PROVIDER-SPECIFIC CREDENTIAL FORMATS
# =========================================================
#
# These tokens have a distinctive, documented format, so a match is far
# stronger evidence of a real credential than a variable called "password".
# They are reported under SEC-001 with a specific title and CRITICAL severity.

def find_provider_tokens(text: str) -> list[tuple[str, str, int]]:
    """Return every real-looking provider token as (label, token, start)."""
    hits: list[tuple[str, str, int]] = []
    taken: list[tuple[int, int]] = []

    for label, pattern, is_secret_value in PROVIDER_TOKEN_RULES:
        # Marker-only rules (such as a private key header) are not credentials.
        if not is_secret_value:
            continue

        for match in pattern.finditer(text):
            token = match.group(0)
            if is_placeholder_or_reference(token):
                continue
            span = match.span()
            if any(span[0] < end and start < span[1] for start, end in taken):
                continue
            taken.append(span)
            hits.append((label, token, span[0]))

    return sorted(hits, key=lambda hit: hit[2])


# Key material that follows a PEM header: a base64 body line, or the body
# inline after an escaped newline (as in service-account JSON files).
PEM_BODY_LINE_PATTERN = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
PEM_BODY_INLINE_PATTERN = re.compile(r"(?:\\[nr]|\s)*[A-Za-z0-9+/]{40,}={0,2}")


def find_private_key_block(
    lines: list[str],
    index: int,
) -> tuple[int, int] | None:
    """Detect an embedded PEM private key starting on lines[index].

    Returns (column, end_column) of the header and the rest of its quoted
    value, or None. A header with no key material after it, such as a code
    check for the header string, is not a finding.
    """
    line = lines[index]
    header = PRIVATE_KEY_HEADER.search(line)

    if not header:
        return None

    rest = line[header.end():]
    has_material = False

    inline = PEM_BODY_INLINE_PATTERN.match(rest)
    if inline:
        has_material = not is_placeholder_or_reference(
            inline.group(0).replace("\\n", "").replace("\\r", "").strip()
        )
    else:
        for following in lines[index + 1:index + 5]:
            text = following.strip()
            if not text or text.startswith(("Proc-Type:", "DEK-Info:")):
                continue
            if PEM_BODY_LINE_PATTERN.fullmatch(text):
                has_material = not is_placeholder_or_reference(text)
            break

    if not has_material:
        return None

    end = len(line)
    for quote in ('"', "'"):
        found = line.find(quote, header.end())
        if found != -1:
            end = min(end, found)

    return header.start(), end


def find_provider_token(text: str) -> tuple[str, str] | None:
    """Return (label, token) for the first provider token, if any."""
    hits = find_provider_tokens(text)
    return (hits[0][0], hits[0][1]) if hits else None


# =========================================================
# BASIC SECRET VALUE CHECK
# =========================================================

def looks_like_secret_value(value: str) -> bool:
    """
    Decide whether an assigned value looks like a real credential.

    This is used by SEC-001.
    """

    value = value.strip().strip("\"'")

    if is_placeholder_or_reference(value):
        return False

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

    if is_placeholder_or_reference(value):
        return True

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
            ["']?(?P<name>[A-Za-z_][A-Za-z0-9_]*)["']?
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

            if find_provider_token(value):
                continue

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
                    "column": match.start("value"),
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
    lines = content.splitlines()

    for line_number, line in enumerate(
        lines,
        start=1,
    ):
        stripped = line.strip()

        # -------------------------------------------------
        # Ignore comments, except npm auth lines such as
        # //registry.npmjs.org/:_authToken=..., which begin
        # with // but are real configuration.
        # -------------------------------------------------

        is_comment = stripped.startswith("#") or (
            stripped.startswith("//")
            and not NPMRC_AUTH_LINE_PATTERN.match(stripped)
        )

        if is_comment:
            continue

        def add_finding(title, severity, confidence, column):
            findings.append(
                {
                    "rule_id": "SEC-001",
                    "title": title,
                    "category": "Secrets",
                    "file": relative_path or path.name,
                    "line": line_number,
                    "evidence": stripped,
                    "base_severity": severity,
                    "confidence": confidence,
                    "column": column,
                }
            )

        # -------------------------------------------------
        # Provider-specific token formats win over the generic
        # variable-name heuristic, whatever the variable is called.
        # Every token on the line is reported.
        # -------------------------------------------------

        provider_hits = find_provider_tokens(line)
        provider_spans = []

        # A private key counts only when key material follows the header.
        private_key = find_private_key_block(lines, line_number - 1)

        if private_key:
            key_start, key_end = private_key
            provider_spans.append((key_start, key_end))
            add_finding("Hardcoded private key", "CRITICAL", 0.97, key_start)

        for label, token, start in provider_hits:
            provider_spans.append((start, start + len(token)))
            add_finding(f"Hardcoded {label}", "CRITICAL", 0.97, start)

        # -------------------------------------------------
        # Generic assignments: password = "...", {"apiKey": "..."}.
        # Every assignment on the line is checked.
        # -------------------------------------------------

        for match in re.finditer(
            r"""
            ["\']?(?P<name>[A-Za-z_][A-Za-z0-9_]*)["\']?
            \s*(?:=|:)
            \s*
            (?P<value>
                ["\'][^"\']+["\']
                |
                [^,\s"\'{\[][^,\s]*
            )
            """,
            line,
            re.VERBOSE,
        ):
            variable_name_lower = match.group("name").lower()
            value = match.group("value")
            value_start, value_end = match.span("value")

            # Already reported as a provider token.
            if any(
                value_start < end and start < value_end
                for start, end in provider_spans
            ):
                continue

            # The variable name must indicate a credential...
            if not any(
                keyword in variable_name_lower
                for keyword in SECRET_KEYWORDS
            ):
                continue

            # ...and the value must look like a real hardcoded one.
            if not looks_like_secret_value(value):
                continue

            add_finding(
                "Potential hardcoded credential",
                "HIGH",
                0.90,
                value_start,
            )

    return findings
