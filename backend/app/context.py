from pathlib import Path


PRODUCTION_SIGNALS = {
    "production",
    "prod",
    "release",
    "deploy",
    "deployment",
}

DEVELOPMENT_SIGNALS = {
    "development",
    "dev",
    "local",
}

TEST_SIGNALS = {
    "test",
    "tests",
    "testing",
    "mock",
    "mocks",
    "fixture",
    "fixtures",
}


def detect_environment(file_path: str) -> tuple[str, float]:
    """
    Estimate the environment associated with a file.

    Returns:
        (environment, confidence)
    """

    path = Path(file_path)

    parts = [
        part.lower()
        for part in path.parts
    ]

    filename = path.name.lower()

    # --------------------------------------------------
    # Production
    # --------------------------------------------------

    if any(
        signal in parts
        for signal in PRODUCTION_SIGNALS
    ):
        return "PRODUCTION", 0.94

    if any(
        signal in filename
        for signal in PRODUCTION_SIGNALS
    ):
        return "PRODUCTION", 0.90

    # --------------------------------------------------
    # Test
    # --------------------------------------------------

    if any(
        signal in parts
        for signal in TEST_SIGNALS
    ):
        return "TEST", 0.95

    if any(
        signal in filename
        for signal in TEST_SIGNALS
    ):
        return "TEST", 0.90

    # --------------------------------------------------
    # Development
    # --------------------------------------------------

    if any(
        signal in parts
        for signal in DEVELOPMENT_SIGNALS
    ):
        return "DEVELOPMENT", 0.85

    if any(
        signal in filename
        for signal in DEVELOPMENT_SIGNALS
    ):
        return "DEVELOPMENT", 0.80

    # --------------------------------------------------
    # Unknown
    # --------------------------------------------------

    return "UNKNOWN", 0.40