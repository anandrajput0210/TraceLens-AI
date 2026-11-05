import stat
from pathlib import Path
from zipfile import ZipFile, ZipInfo

import pytest

from app.services.archive_service import safe_extract_zip


def _make_zip(path: Path, entries: list[tuple[str, bytes | str]]) -> None:
    with ZipFile(path, "w") as archive:
        for name, content in entries:
            archive.writestr(name, content)


def test_normal_github_style_archive_extracts_to_project_root(tmp_path):
    zip_path = tmp_path / "repo.zip"
    _make_zip(zip_path, [("project/app.py", "print('ok')")])

    result = Path(safe_extract_zip(str(zip_path), str(tmp_path / "out")))
    assert result.name == "project"
    assert (result / "app.py").read_text(encoding="utf-8") == "print('ok')"


@pytest.mark.parametrize("member_name", [
    "../../outside.txt",
    r"..\..\outside.txt",
    r"C:\outside.txt",
    r"\\server\share\outside.txt",
])
def test_rejects_cross_platform_traversal_and_absolute_paths(tmp_path, member_name):
    zip_path = tmp_path / "unsafe.zip"
    _make_zip(zip_path, [(member_name, "bad")])

    with pytest.raises(ValueError, match="Unsafe ZIP path"):
        safe_extract_zip(str(zip_path), str(tmp_path / "out"))
    assert not (tmp_path / "outside.txt").exists()


def test_rejects_symlink_entries(tmp_path):
    zip_path = tmp_path / "symlink.zip"
    info = ZipInfo("project/link")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with ZipFile(zip_path, "w") as archive:
        archive.writestr(info, "../../outside.txt")

    with pytest.raises(ValueError, match="Unsafe ZIP entry type"):
        safe_extract_zip(str(zip_path), str(tmp_path / "out"))


def test_rejects_duplicate_paths_after_separator_normalization(tmp_path):
    zip_path = tmp_path / "duplicate.zip"
    _make_zip(zip_path, [
        ("project/config.py", "first"),
        (r"project\config.py", "second"),
    ])

    with pytest.raises(ValueError, match="Duplicate ZIP path"):
        safe_extract_zip(str(zip_path), str(tmp_path / "out"))


def test_rejects_file_directory_collisions(tmp_path):
    zip_path = tmp_path / "collision.zip"
    _make_zip(zip_path, [
        ("project/item", "file"),
        ("project/item/child.py", "child"),
    ])

    with pytest.raises(ValueError, match="Conflicting ZIP paths"):
        safe_extract_zip(str(zip_path), str(tmp_path / "out"))


def test_invalid_archive_leaves_destination_empty(tmp_path):
    zip_path = tmp_path / "invalid.zip"
    _make_zip(zip_path, [
        ("project/safe.py", "safe"),
        ("../escape.py", "unsafe"),
    ])
    output = tmp_path / "out"

    with pytest.raises(ValueError, match="Unsafe ZIP path"):
        safe_extract_zip(str(zip_path), str(output))
    assert list(output.iterdir()) == []


def test_root_level_files_are_not_hidden_by_single_directory(tmp_path):
    zip_path = tmp_path / "mixed.zip"
    _make_zip(zip_path, [
        ("project/app.py", "print('ok')"),
        ("README.md", "repo root"),
    ])

    result = Path(safe_extract_zip(str(zip_path), str(tmp_path / "out")))
    assert result.name == "out"
    assert (result / "README.md").exists()
    assert (result / "project" / "app.py").exists()


def test_destination_must_be_empty(tmp_path):
    zip_path = tmp_path / "repo.zip"
    _make_zip(zip_path, [("project/app.py", "print('ok')")])
    output = tmp_path / "out"
    output.mkdir()
    (output / "keep.txt").write_text("keep", encoding="utf-8")

    with pytest.raises(ValueError, match="destination must be empty"):
        safe_extract_zip(str(zip_path), str(output))
    assert (output / "keep.txt").read_text(encoding="utf-8") == "keep"
