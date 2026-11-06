"""Frontend repository scanning contract.

Builds a small React/Vite repository and checks which files are discovered
and which findings are produced. Credential-looking values are assembled at
runtime so no real-looking secret is stored in the repository.
"""

import json

from app.scanner.engine import ScannerEngine
from app.scanner.secrets import scan_hardcoded_credentials
from app.services.repository_service import discover_files

AWS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"
GITHUB_TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


def _build_react_repo(root):
    (root / "src").mkdir()
    (root / "public").mkdir()
    (root / "node_modules" / "left-pad").mkdir(parents=True)
    (root / ".next").mkdir()

    (root / "src" / "App.tsx").write_text(
        'const apiKey = import.meta.env.VITE_API_KEY;\n'
        'const publicKey = process.env.NEXT_PUBLIC_KEY;\n'
        'export default function App() { return <div />; }\n',
        encoding="utf-8",
    )
    (root / "src" / "api.js").write_text(
        'const API_SECRET = "s3cr3tValue!9xQ";\n'
        f'export const config = {{ accessToken: "{GITHUB_TOKEN}" }};\n',
        encoding="utf-8",
    )
    (root / "src" / "worker.mjs").write_text(
        'const secret_token = "Qw3rTy!uIoP9asDf";\n', encoding="utf-8"
    )
    (root / "src" / "style.css").write_text("body { color: red; }\n")
    (root / "index.html").write_text(
        f'<script>const key = "{AWS_KEY}";</script>\n', encoding="utf-8"
    )
    (root / "package.json").write_text(
        json.dumps({"name": "app", "config": {"password": "Tr0ub4dor&3xyz"}}, indent=2),
        encoding="utf-8",
    )
    (root / "package-lock.json").write_text(
        json.dumps(
            {"packages": {"node_modules/a": {"integrity": "sha512-" + "Qm9yZ2Vu" * 10}}},
            indent=2,
        ),
        encoding="utf-8",
    )
    (root / ".env.example").write_text(
        "VITE_API_URL=http://localhost:8000\n"
        "DATABASE_URL=postgres://user:Pa55w0rdReal@db.internal:5432/app\n"
        "ACCESS_TOKEN=Zx9Qw8Er7Ty6Ui5O\n",
        encoding="utf-8",
    )
    (root / "node_modules" / "left-pad" / "index.js").write_text(
        'const password = "Tr0ub4dor&3xyz";\n', encoding="utf-8"
    )
    (root / ".next" / "bundle.js").write_text(
        'const password = "Tr0ub4dor&3xyz";\n', encoding="utf-8"
    )


def test_frontend_file_discovery_policy(tmp_path):
    _build_react_repo(tmp_path)

    paths = sorted(f["path"].replace("\\", "/") for f in discover_files(str(tmp_path)))

    assert paths == [
        ".env.example",
        "index.html",
        "package.json",
        "src/App.tsx",
        "src/api.js",
        "src/worker.mjs",
    ]
    # CSS, lockfiles, node_modules and build output are intentionally skipped.


def test_frontend_repository_findings(tmp_path):
    _build_react_repo(tmp_path)

    files = discover_files(str(tmp_path))
    findings = ScannerEngine().scan_repository(str(tmp_path), files)

    found = {
        (f.file.replace("\\", "/"), f.line, f.title) for f in findings
    }

    assert ("index.html", 1, "Hardcoded AWS access key") in found
    assert ("src/api.js", 1, "Potential hardcoded credential") in found
    assert ("src/api.js", 2, "Hardcoded GitHub token") in found
    assert ("src/worker.mjs", 1, "Potential hardcoded credential") in found
    assert ("package.json", 4, "Potential hardcoded credential") in found
    assert (".env.example", 2, "Potential hardcoded credential") in found
    assert (".env.example", 3, "Potential hardcoded credential") in found

    # Environment-variable references are not hardcoded credentials.
    assert not [item for item in found if item[0] == "src/App.tsx"]
    # The URL-only variable and ignored directories produce nothing.
    assert not [item for item in found if item[1] == 1 and item[0] == ".env.example"]
    assert not [item for item in found if "node_modules" in item[0] or ".next" in item[0]]


def test_generic_credential_assignments(tmp_path):
    source = tmp_path / "config.js"
    source.write_text(
        'const API_SECRET = "s3cr3tValue!9xQ";\n'
        'const ACCESS_TOKEN = "Zx9Qw8Er7Ty6Ui5O";\n'
        'const DATABASE_URL = "postgres://user:Pa55w0rdReal@db:5432/app";\n'
        'const settings = { apiKey: "Zx9Qw8Er7Ty6Ui5O", region: "eu" };\n',
        encoding="utf-8",
    )

    findings = scan_hardcoded_credentials(str(source), "config.js")
    assert [f["line"] for f in findings] == [1, 2, 3, 4]


def test_env_reference_styles_are_not_credentials(tmp_path):
    source = tmp_path / "config.ts"
    source.write_text(
        "const apiKey = import.meta.env.VITE_API_KEY;\n"
        "const apiSecret = process.env.API_SECRET;\n"
        'const accessToken = process.env["ACCESS_TOKEN"];\n'
        'const authToken = Deno.env.get("AUTH_TOKEN");\n',
        encoding="utf-8",
    )
    assert scan_hardcoded_credentials(str(source), "config.ts") == []


def test_only_documented_aws_samples_are_suppressed(tmp_path):
    source = tmp_path / "settings.py"
    source.write_text(
        'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n'
        'password = "MyRealPasswordEXAMPLE"\n',
        encoding="utf-8",
    )
    findings = scan_hardcoded_credentials(str(source), "settings.py")
    assert [f["line"] for f in findings] == [2]
