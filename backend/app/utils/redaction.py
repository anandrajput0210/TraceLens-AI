"""Best-effort redaction of likely credentials from scanner evidence."""

import math
import re
from collections import Counter


MASK = "[REDACTED]"

SAFE_VALUE_PATTERNS = (
    "os.getenv(",
    "os.environ.get(",
    "process.env.",
    "getenv(",
)

SECRET_MARKERS = (
    r"(?:password|passwd|passphrase|pwd|secret|token|api[_-]?key|"
    r"access[_-]?key|private[_-]?key|auth[_-]?(?:token|key)|"
    r"client[_-]?secret)"
)

# Matches exact and compound names, such as PASSWORD, API_TOKEN
# and DATABASE_PASSWORD. It intentionally excludes generic URL names.
SENSITIVE_NAME = (
    r"(?<![A-Za-z0-9_.-])[\"']?"
    r"(?:[A-Za-z_][A-Za-z0-9_.-]*?)?"
    + SECRET_MARKERS
    + r"[A-Za-z0-9_.-]*[\"']?"
)

QUOTE_PATTERN = "(?P<quote>'''|\"\"\"|'|\")"

# Quoted secret assignments, including JSON-style keys.
QUOTED_ASSIGNMENT_RE = re.compile(
    r"(?P<prefix>" + SENSITIVE_NAME + r"\s*[:=]\s*)"
    + QUOTE_PATTERN
    + r"(?P<value>(?:\\[^\r\n]|(?!(?P=quote))[^\r\n])*?)"
    + r"(?P=quote)",
    re.IGNORECASE,
)

# Unquoted assignments. Stop before delimiters and quote characters,
# so the surrounding source syntax is not accidentally consumed.
UNQUOTED_ASSIGNMENT_RE = re.compile(
    r"(?P<prefix>" + SENSITIVE_NAME + r"\s*[:=]\s*)(?![\"'])"
    r"(?P<value>[^\s,;#}\]\)\"']+)",
    re.IGNORECASE,
)

# Authorization headers. Preserve the authentication scheme while
# hiding the credential itself.
AUTH_HEADER_RE = re.compile(
    r"(?P<prefix>[\"']?(?:proxy-)?authorization[\"']?\s*[:=]\s*)"
    r"(?P<quote>[\"']?)"
    r"(?:(?P<scheme>Bearer|Basic|Token)\s+)?"
    r"(?P<token>[^\"'\s,;}\]]+)"
    r"(?P=quote)",
    re.IGNORECASE,
)

# Passwords in URL user-info sections, for example:
# postgres://user:password@host/db
# mongodb+srv://user:password@host/db
# redis://user:password@host/0
URL_CREDENTIALS_RE = re.compile(
    r"(?i)\b([a-z][a-z0-9+.-]*://[^:/@\s]+:)([^@/\s?#]+)(@)"
)

# Known provider token formats. This list is deliberately limited to
# recognizable formats; it is not an exhaustive list of all credentials.
KNOWN_TOKEN_RE = re.compile(
    r"\b(?:"
    r"gh[pousr]_[A-Za-z0-9]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|"
    r"sk-[A-Za-z0-9_-]{20,}|"
    r"AKIA[0-9A-Z]{16}"
    r")\b"
)

JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]{10,}"
    r"\.[A-Za-z0-9_-]{10,}"
    r"\.[A-Za-z0-9_-]{10,}\b"
)

# Detect likely secret literals even when the variable name is innocuous,
# such as random_value = "aB7$xQ9!mK2@pL8#zR5".
GENERIC_QUOTED_LITERAL_RE = re.compile(
    QUOTE_PATTERN
    + r"(?P<value>(?:\\[^\r\n]|(?!(?P=quote))[^\r\n])*?)"
    + r"(?P=quote)"
)

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

HEX_HASH_RE = re.compile(r"^[0-9a-f]{32,}$", re.IGNORECASE)

SHA_HASH_RE = re.compile(
    r"^(?:sha1|sha224|sha256|sha384|sha512)[_-]?[0-9a-f]{32,}$",
    re.IGNORECASE,
)

SEMVER_RE = re.compile(
    r"^v?\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?$"
)

IPV4_SHAPE_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

HEX_COLOR_RE = re.compile(r"^#[0-9a-f]{3,8}$", re.IGNORECASE)


def _is_safe_reference(value: str) -> bool:
    """Identify common references to externally configured values."""
    lowered = value.lower()

    return any(
        pattern in lowered
        for pattern in SAFE_VALUE_PATTERNS
    )


def _looks_like_high_entropy_secret(value: str) -> bool:
    """Use conservative heuristics to identify suspicious string literals."""
    value = value.strip().strip("\"'")

    if len(value) < 16:
        return False

    if any(character.isspace() for character in value):
        return False

    lower_value = value.lower()

    if lower_value in {
        "none",
        "null",
        "false",
        "true",
        "changeme",
        "example",
        "test",
        "development",
        "production",
        "localhost",
        "default",
    }:
        return False

    if _is_safe_reference(value):
        return False

    if value.startswith(
        ("http://", "https://", "ftp://", "ws://", "wss://")
    ):
        return False

    if value.startswith(("/", "./", "../", ".\\", "..\\")):
        return False

    if re.match(r"^[A-Za-z]:[\\/]", value):
        return False

    if UUID_RE.fullmatch(value) or HEX_HASH_RE.fullmatch(value):
        return False

    if SHA_HASH_RE.fullmatch(value) or SEMVER_RE.fullmatch(value):
        return False

    if IPV4_SHAPE_RE.fullmatch(value) or HEX_COLOR_RE.fullmatch(value):
        return False

    frequencies = Counter(value)
    length = len(value)

    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in frequencies.values()
    )

    if entropy < 3.8:
        return False

    has_lower = bool(re.search(r"[a-z]", value))
    has_upper = bool(re.search(r"[A-Z]", value))
    has_digit = bool(re.search(r"\d", value))
    has_special = bool(re.search(r"[^A-Za-z0-9]", value))

    character_classes = sum(
        (has_lower, has_upper, has_digit, has_special)
    )

    return character_classes >= 3


def redact_evidence(evidence: str) -> str:
    """Redact recognizable and likely credentials from scanner evidence.

    This is a defense-in-depth filter, not a guarantee that every secret
    format will be detected. It favors preventing credential disclosure
    over preserving every character of a suspicious value.
    """
    if not isinstance(evidence, str) or not evidence:
        return evidence

    # Recognizable tokens, including those assigned to innocuous variables.
    evidence = KNOWN_TOKEN_RE.sub(MASK, evidence)
    evidence = JWT_RE.sub(MASK, evidence)

    # Preserve useful URL context while hiding user-info passwords.
    evidence = URL_CREDENTIALS_RE.sub(
        lambda match: match.group(1) + MASK + match.group(3),
        evidence,
    )

    def redact_auth_header(match: re.Match[str]) -> str:
        scheme = match.group("scheme")
        scheme_text = f"{scheme} " if scheme else ""

        return (
            match.group("prefix")
            + match.group("quote")
            + scheme_text
            + MASK
            + match.group("quote")
        )

    evidence = AUTH_HEADER_RE.sub(
        redact_auth_header,
        evidence,
    )

    # Redact values assigned to sensitive variable or JSON key names.
    evidence = QUOTED_ASSIGNMENT_RE.sub(
        lambda match: (
            match.group("prefix")
            + match.group("quote")
            + MASK
            + match.group("quote")
        ),
        evidence,
    )

    def redact_unquoted_assignment(match: re.Match[str]) -> str:
        value = match.group("value")

        if _is_safe_reference(value):
            return match.group(0)

        return match.group("prefix") + MASK

    evidence = UNQUOTED_ASSIGNMENT_RE.sub(
        redact_unquoted_assignment,
        evidence,
    )

    # Last line of defense for suspicious string literals that have no
    # obvious credential-related name.
    def redact_high_entropy_literal(match: re.Match[str]) -> str:
        value = match.group("value")

        if not _looks_like_high_entropy_secret(value):
            return match.group(0)

        quote = match.group("quote")
        return quote + MASK + quote

    return GENERIC_QUOTED_LITERAL_RE.sub(
        redact_high_entropy_literal,
        evidence,
    )


def redact_data(value):
    """Recursively redact likely secrets from structured data."""

    sensitive_markers = (
        "password",
        "passwd",
        "passphrase",
        "pwd",
        "secret",
        "token",
        "apikey",
        "accesskey",
        "privatekey",
        "authorization",
        "credential",
        "databaseurl",
        "connectionstring",
    )

    if isinstance(value, dict):
        redacted = {}

        for key, item in value.items():
            normalized_key = re.sub(
                r"[^a-z0-9]",
                "",
                str(key).lower(),
            )

            is_sensitive = any(
                marker in normalized_key
                for marker in sensitive_markers
            )

            if is_sensitive and item is not None:
                if (
                    isinstance(item, str)
                    and _is_safe_reference(item)
                ):
                    redacted[key] = item
                else:
                    redacted[key] = MASK
            else:
                redacted[key] = redact_data(item)

        return redacted

    if isinstance(value, list):
        return [redact_data(item) for item in value]

    if isinstance(value, tuple):
        return tuple(redact_data(item) for item in value)

    if isinstance(value, str):
        return redact_evidence(value)

    return value
