from app.scanner.engine import ScannerEngine
from app.services.repository_service import discover_files


def _scan(root):
    return ScannerEngine().scan_repository(str(root), discover_files(str(root)))


def test_placeholders_and_references_are_not_reported(tmp_path):
    (tmp_path / ".env.example").write_text(
        "VITE_API_URL=http://localhost:8000\n"
        "API_KEY=\n"
        "SECRET_TOKEN=your-token-here\n"
        "API_SECRET=YOUR_API_SECRET\n"
        "DATABASE_URL=${DATABASE_URL}\n"
        "STRIPE_KEY=<your-stripe-key>\n"
        "ACCESS_TOKEN=changeme\n"
        "AUTH_TOKEN=insert-token-here\n",
        encoding="utf-8",
    )
    (tmp_path / ".npmrc").write_text(
        "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n", encoding="utf-8"
    )
    (tmp_path / "app.ts").write_text(
        "const apiKey = import.meta.env.VITE_API_KEY;\n"
        "const token = process.env.API_TOKEN;\n",
        encoding="utf-8",
    )
    assert _scan(tmp_path) == []


def test_real_looking_values_are_still_reported(tmp_path):
    (tmp_path / ".env").write_text(
        "SECRET_TOKEN=Zx9Qw8Er7Ty6Ui5OaB3c\n"
        "YOUR_PASSWORD=Tr0ub4dor&3xyz\n",
        encoding="utf-8",
    )
    assert [f.line for f in _scan(tmp_path)] == [1, 2]


def test_real_tokens_containing_marker_words_are_still_reported(tmp_path):
    (tmp_path / ".env").write_text(
        "API_TOKEN=abc_your_def_1234567890\n"
        "API_SECRET=Zx9_here_Qw8Er7Ty6Ui5\n"
        "AUTH_TOKEN=Tr0ub4dor-insert-9xQ\n"
        "ACCESS_TOKEN=abcdefghijklmn_your_opqrstuvwxyz\n",
        encoding="utf-8",
    )
    assert [f.line for f in _scan(tmp_path)] == [1, 2, 3, 4]
