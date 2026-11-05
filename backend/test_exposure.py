from pathlib import Path

from app.risk.exposure import detect_exposure


DEMO_REPO_PATH = Path(__file__).resolve().parents[1] / "demo-repo"


def test_all_interface_bind_does_not_prove_public_exposure():
    exposure, confidence = detect_exposure(str(DEMO_REPO_PATH / "public_app.py"))

    assert exposure == "UNKNOWN"
    assert 0 <= confidence <= 1


def test_database_loopback_endpoint_does_not_prove_app_exposure():
    exposure, confidence = detect_exposure(str(DEMO_REPO_PATH / "local_config.py"))

    assert exposure == "UNKNOWN"
    assert confidence == 0.40



def test_docker_expose_does_not_prove_public_exposure():
    exposure, confidence = detect_exposure(str(DEMO_REPO_PATH / "Dockerfile"))

    assert exposure == "UNKNOWN"
    assert 0 <= confidence <= 1


def test_route_declaration_alone_is_unknown(tmp_path):
    path = tmp_path / "route.py"
    path.write_text('@app.get("/health")\ndef health():\n    return {"ok": True}\n', encoding="utf-8")

    exposure, confidence = detect_exposure(str(path))

    assert exposure == "UNKNOWN"
    assert 0 <= confidence <= 1


def test_all_interface_bind_is_unknown_even_with_route(tmp_path):
    path = tmp_path / "app.py"
    path.write_text(
        '@app.get("/health")\ndef health():\n    return {"ok": True}\n'
        'app.run(host="0.0.0.0", port=5000)\n',
        encoding="utf-8",
    )

    exposure, confidence = detect_exposure(str(path))

    assert exposure == "UNKNOWN"
    assert confidence == 0.65


def test_explicit_public_access_configuration_is_public(tmp_path):
    path = tmp_path / "infra.tf"
    path.write_text('publicly_accessible = true\n', encoding="utf-8")

    exposure, confidence = detect_exposure(str(path))

    assert exposure == "PUBLIC"
    assert confidence == 0.85


def test_loopback_bind_is_local(tmp_path):
    path = tmp_path / "local.py"
    path.write_text('app.run(host="127.0.0.1", port=5000)\n', encoding="utf-8")

    exposure, confidence = detect_exposure(str(path))

    assert exposure == "LOCAL"
    assert 0 <= confidence <= 1


def test_missing_file_is_unknown(tmp_path):
    exposure, confidence = detect_exposure(str(tmp_path / "does-not-exist.py"))

    assert exposure == "UNKNOWN"
    assert confidence == 0.40

def test_database_host_field_does_not_prove_app_exposure(tmp_path):
    path = tmp_path / "database_config.py"
    path.write_text('database = {"host": "localhost"}\n', encoding="utf-8")

    exposure, confidence = detect_exposure(str(path))

    assert exposure == "UNKNOWN"
    assert confidence == 0.40
