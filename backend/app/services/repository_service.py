import re
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
    # Frontend sources that can embed credentials. CSS is deliberately not
    # included: stylesheets do not hold credentials.
    ".mjs",
    ".cjs",
    ".html",
    ".htm",
    ".vue",
    ".svelte",
}

# Generated lockfiles are full of integrity hashes and never hold secrets.
IGNORED_FILENAMES = {
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
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


# Hidden directories are skipped (tool caches, editor state, backup copies)
# except the ones that hold real configuration we scan.
ALLOWED_HIDDEN_DIRECTORIES = {".github"}

BACKUP_DIRECTORY_PATTERN = re.compile(
    r"(?i)(?:^|[._-])(?:backup|backups|bak)(?:$|[._-])"
)


def is_ignored_directory(name: str) -> bool:
    lowered = name.lower()
    if lowered in IGNORED_DIRECTORIES:
        return True
    if name.startswith(".") and lowered not in ALLOWED_HIDDEN_DIRECTORIES:
        return True
    return bool(BACKUP_DIRECTORY_PATTERN.search(name))


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

    # npm registry configuration can hold auth tokens
    if path.name.lower() == ".npmrc":
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

        # Judge only the path inside the repository. Checking the absolute
        # path would skip everything when the repo itself sits under a
        # directory such as "build" or "dist".
        try:
            relative_parts = path.relative_to(root).parts
        except ValueError:
            continue

        if any(
            is_ignored_directory(part)
            for part in relative_parts[:-1]
        ):
            continue

        if path.name.lower() in IGNORED_FILENAMES:
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