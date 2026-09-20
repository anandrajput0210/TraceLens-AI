from app.risk.context import detect_environment


def test_production_environment():
    environment, confidence = detect_environment("config/production.py")

    assert environment == "PRODUCTION"
    assert confidence >=0.8


def test_prod_environment():
    environment, confidence = detect_environment("config/prod.py")

    assert environment == "PRODUCTION"
    assert confidence >=0.8


def test_test_environment():
    environment, confidence = detect_environment("tests/mock_config.py")

    assert environment == "TEST"
    assert confidence >=0.8


def test_development_environment():
    environment, confidence = detect_environment("config/development.py")

    assert environment == "DEVELOPMENT"
    assert confidence >=0.8


def test_unknown_environment():
    environment, confidence = detect_environment("app/main.py")

    assert environment == "UNKNOWN"
    assert 0 <= confidence <= 1