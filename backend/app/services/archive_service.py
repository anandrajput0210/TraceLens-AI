from pathlib import Path
from zipfile import ZipFile


MAX_FILES = 5000
MAX_FILE_SIZE = 1_000_000      # 1 MB
MAX_TOTAL_SIZE = 50_000_000    # 50 MB


def safe_extract_zip(
    zip_path: str,
    destination: str,
) -> str:
    """
    Safely extract a repository ZIP archive.

    Protections:
    - Maximum number of archive members
    - Maximum individual file size
    - Maximum total uncompressed size
    - Path traversal protection
    - Extraction-boundary validation

    The repository contents are never executed.
    """

    destination_path = Path(destination).resolve()

    # Ensure the extraction directory exists.
    destination_path.mkdir(
        parents=True,
        exist_ok=True,
    )

    total_size = 0

    with ZipFile(zip_path, "r") as archive:

        members = archive.infolist()

        # Maximum number of files/directories.
        if len(members) > MAX_FILES:
            raise ValueError(
                "Repository contains too many files."
            )

        # Validate every member BEFORE extraction.
        for member in members:

            member_path = Path(member.filename)

            # Block absolute paths.
            if member_path.is_absolute():
                raise ValueError(
                    "Unsafe ZIP path detected."
                )

            # Block ../ traversal.
            if ".." in member_path.parts:
                raise ValueError(
                    "Unsafe ZIP path detected."
                )

            # Defense-in-depth:
            # make sure the final resolved path remains
            # inside the extraction directory.
            target_path = (
                destination_path / member_path
            ).resolve()

            try:
                target_path.relative_to(
                    destination_path
                )
            except ValueError:
                raise ValueError(
                    "Unsafe ZIP path detected."
                )

            # Maximum individual file size.
            if member.file_size > MAX_FILE_SIZE:
                raise ValueError(
                    f"File too large: {member.filename}"
                )

            # Maximum total uncompressed size.
            total_size += member.file_size

            if total_size > MAX_TOTAL_SIZE:
                raise ValueError(
                    "Repository exceeds maximum extraction size."
                )

        # Only extract AFTER every member passes validation.
        archive.extractall(destination_path)

    # GitHub ZIPs commonly contain a single root folder.
    children = list(destination_path.iterdir())

    directories = [
        child
        for child in children
        if child.is_dir()
    ]

    if len(directories) == 1:
        return str(directories[0])

    return str(destination_path)