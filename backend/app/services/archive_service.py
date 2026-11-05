from __future__ import annotations

import re
import shutil
import stat
import tempfile
from pathlib import Path
from zipfile import ZipFile


MAX_FILES = 5000
MAX_FILE_SIZE = 1_000_000      # 1 MB
MAX_TOTAL_SIZE = 50_000_000    # 50 MB
_CHUNK_SIZE = 1024 * 1024
_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")


def _validated_member(member, destination_path: Path):
    """Return (relative_path, is_directory, canonical_key) or reject it."""
    original_name = member.filename
    if not original_name or "\x00" in original_name:
        raise ValueError("Unsafe ZIP path detected.")

    # ZIP names conventionally use '/', but archives created on Windows may
    # use '\\'. Normalize both before validating or writing any paths.
    normalized = original_name.replace("\\", "/")
    if normalized.startswith("/") or _DRIVE_PREFIX.match(normalized):
        raise ValueError("Unsafe ZIP path detected.")

    is_directory = member.is_dir() or normalized.endswith("/")
    normalized = normalized.rstrip("/")
    if not normalized:
        raise ValueError("Unsafe ZIP path detected.")

    parts = normalized.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("Unsafe ZIP path detected.")
    if any(_DRIVE_PREFIX.match(part) for part in parts):
        raise ValueError("Unsafe ZIP path detected.")

    # Reject symlinks and other special Unix file types. Repository archives
    # should contain ordinary files/directories only.
    unix_mode = (member.external_attr >> 16) & 0xFFFF
    file_type = stat.S_IFMT(unix_mode)
    if file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
        raise ValueError("Unsafe ZIP entry type detected.")
    if file_type == stat.S_IFDIR:
        is_directory = True

    relative_path = Path(*parts)
    resolved_target = (destination_path / relative_path).resolve()
    try:
        resolved_target.relative_to(destination_path)
    except ValueError as error:
        raise ValueError("Unsafe ZIP path detected.") from error

    # Windows filesystems are usually case-insensitive. Canonicalizing keys
    # this way also catches duplicate names that collide there.
    canonical_key = "/".join(part.casefold() for part in parts)
    return relative_path, is_directory, canonical_key


def safe_extract_zip(zip_path: str, destination: str) -> str:
    """Safely extract an untrusted repository ZIP without executing its code.

    Validation occurs before extraction. Files are written into a temporary
    staging directory and moved into an empty destination only after every
    entry has been extracted successfully.
    """
    destination_path = Path(destination).resolve()
    destination_path.mkdir(parents=True, exist_ok=True)
    if any(destination_path.iterdir()):
        raise ValueError("Extraction destination must be empty.")

    with ZipFile(zip_path, "r") as archive:
        members = archive.infolist()
        if len(members) > MAX_FILES:
            raise ValueError("Repository contains too many files.")

        total_size = 0
        validated_members = []
        entries: dict[str, bool] = {}

        # Validate the full archive before writing any member to disk.
        for member in members:
            if member.file_size < 0 or member.file_size > MAX_FILE_SIZE:
                raise ValueError("File too large.")
            total_size += member.file_size
            if total_size > MAX_TOTAL_SIZE:
                raise ValueError("Repository exceeds maximum extraction size.")

            relative_path, is_directory, key = _validated_member(
                member, destination_path
            )
            if key in entries:
                raise ValueError("Duplicate ZIP path detected.")
            entries[key] = is_directory
            validated_members.append((member, relative_path, is_directory, key))

        # A non-directory entry cannot also be an ancestor of another entry.
        for _member, _relative_path, _is_directory, key in validated_members:
            parts = key.split("/")
            for index in range(1, len(parts)):
                ancestor = "/".join(parts[:index])
                if ancestor in entries and not entries[ancestor]:
                    raise ValueError("Conflicting ZIP paths detected.")
            if not entries[key] and any(
                other.startswith(key + "/") for other in entries if other != key
            ):
                raise ValueError("Conflicting ZIP paths detected.")

        staging_path = Path(
            tempfile.mkdtemp(
                prefix=f".{destination_path.name}.extract-",
                dir=str(destination_path.parent),
            )
        )
        try:
            actual_total = 0
            for member, relative_path, is_directory, _key in validated_members:
                target_path = (staging_path / relative_path).resolve()
                try:
                    target_path.relative_to(staging_path)
                except ValueError as error:
                    raise ValueError("Unsafe ZIP path detected.") from error

                if is_directory:
                    target_path.mkdir(parents=True, exist_ok=True)
                    continue

                target_path.parent.mkdir(parents=True, exist_ok=True)
                extracted_size = 0
                with archive.open(member, "r") as source, target_path.open("xb") as output:
                    while True:
                        chunk = source.read(_CHUNK_SIZE)
                        if not chunk:
                            break
                        extracted_size += len(chunk)
                        actual_total += len(chunk)
                        if extracted_size > MAX_FILE_SIZE:
                            raise ValueError("File too large.")
                        if actual_total > MAX_TOTAL_SIZE:
                            raise ValueError("Repository exceeds maximum extraction size.")
                        output.write(chunk)

                if extracted_size != member.file_size:
                    raise ValueError("ZIP member size does not match its metadata.")

            # Destination is required to be empty. Same-filesystem moves avoid
            # reinterpreting archive paths at extraction time.
            for child in staging_path.iterdir():
                child.replace(destination_path / child.name)
        finally:
            shutil.rmtree(staging_path, ignore_errors=True)

    # GitHub archives usually have exactly one top-level folder. Only unwrap
    # it when it is the sole child so root-level files are never hidden.
    children = list(destination_path.iterdir())
    if len(children) == 1 and children[0].is_dir():
        return str(children[0])
    return str(destination_path)
