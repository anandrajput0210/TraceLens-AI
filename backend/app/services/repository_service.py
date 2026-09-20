from pathlib import Path


SUPPORTED_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".json",
    ".yml",
    ".yaml",
}

IGNORED_DIRECTORIES = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "dist",
    "build",
    "coverage",
    "__pycache__",
}


def is_supported_file(path: Path) -> bool:
    """
    Check whether a file is supported by TraceLens.
    """

    # Dockerfile has no extension
    if path.name.lower() == "dockerfile":
        return True

    # GitHub Actions workflow files
    if ".github" in path.parts and "workflows" in path.parts:
        return path.suffix.lower() in {".yml", ".yaml"}

    # Environment files
    if path.name.startswith(".env"):
        return True

    return path.suffix.lower() in SUPPORTED_EXTENSIONS


def discover_files(repository_path: str) -> list[dict]:
    """
    Safely discover analyzable files inside a repository.

    The repository is only read.
    No source code is executed.
    """

    root = Path(repository_path).resolve()

    if not root.exists():
        raise FileNotFoundError(
            f"Repository path does not exist: {root}"
        )

    if not root.is_dir():
        raise ValueError(
            f"Repository path is not a directory: {root}"
        )

    discovered = []

    for path in root.rglob("*"):

        # Ignore directories we don't want to inspect
        if path.is_dir():
            continue

        if any(
            ignored in path.parts
            for ignored in IGNORED_DIRECTORIES
        ):
            continue

        if not is_supported_file(path):
            continue

        try:
            relative_path = path.relative_to(root)

            discovered.append(
                {
                    "path": str(relative_path),
                    "absolute_path": str(path),
                    "extension": path.suffix.lower(),
                    "size": path.stat().st_size,
                }
            )

        except OSError:
            # Ignore files that cannot be accessed
            continue

    return discovered