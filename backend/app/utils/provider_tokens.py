"""Provider credential formats shared by the scanner and the redactor.

Keeping a single list means anything the scanner reports can also be masked
before it is shown, so detection and redaction cannot drift apart.
"""

import re

# PEM private key header. On its own it is only a marker: whether a key is
# actually embedded is decided by the scanner, which looks for key material.
PRIVATE_KEY_HEADER = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"
)

# (label, pattern, is_secret_value)
# is_secret_value is False when the match is only a marker (such as a private
# key header) and masking it would remove useful context.
PROVIDER_TOKEN_RULES = (
    (
        "AWS access key",
        re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])"),
        True,
    ),
    (
        "GitHub token",
        re.compile(
            r"(?<![A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9]{36,255}"
            r"|github_pat_[A-Za-z0-9_]{22,255})(?![A-Za-z0-9_])"
        ),
        True,
    ),
    (
        "Slack token",
        re.compile(r"(?<![A-Za-z0-9])xox[abprs]-[A-Za-z0-9-]{10,}"),
        True,
    ),
    (
        "Stripe live secret key",
        re.compile(r"(?<![A-Za-z0-9])sk_live_[0-9A-Za-z]{24,}"),
        True,
    ),
    (
        "Google API key",
        re.compile(r"(?<![A-Za-z0-9])AIza[0-9A-Za-z_\-]{35}(?![0-9A-Za-z_\-])"),
        True,
    ),
    (
        "npm access token",
        re.compile(r"(?<![A-Za-z0-9])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])"),
        True,
    ),
    (
        "Private key block",
        PRIVATE_KEY_HEADER,
        False,
    ),
)
