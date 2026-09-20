from app.risk.exposure import detect_exposure


def test_public_exposure():
    exposure, confidence = detect_exposure("../demo-repo/public_app.py")

    assert exposure == "PUBLIC"
    assert 0 <= confidence <= 1


def test_local_exposure():
    exposure, confidence = detect_exposure("../demo-repo/local_config.py")

    assert exposure == "LOCAL"
    assert 0 <= confidence <= 1


def test_docker_exposure():
    exposure, confidence = detect_exposure("../demo-repo/Dockerfile")

    assert exposure in {"PUBLIC", "INTERNAL", "LOCAL", "UNKNOWN"}
    assert 0 <= confidence <= 1