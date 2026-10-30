"""Configuration: safe defaults, loopback only, invalid values name the variable."""

import pytest

from config import ConfigError, Settings, load_settings


def test_defaults_are_safe():
    settings = load_settings({})
    assert settings == Settings()
    assert settings.host == "127.0.0.1"
    assert settings.port == 8501
    assert settings.max_request_bytes > settings.max_pdf_bytes + settings.max_p12_bytes


def test_env_overrides():
    settings = load_settings({
        "ESIGN_HOST": "localhost", "ESIGN_PORT": "9000", "ESIGN_MAX_PDF_MB": "5",
        "ESIGN_MAX_P12_KB": "64", "ESIGN_MAX_PLACEMENTS": "10", "ESIGN_MAX_IN_FLIGHT": "1",
    })
    assert (settings.host, settings.port) == ("localhost", 9000)
    assert settings.max_pdf_bytes == 5 * 1024 * 1024
    assert settings.max_p12_bytes == 64 * 1024
    assert (settings.max_placements, settings.max_in_flight) == (10, 1)
    assert settings.allowed_origins == {"http://localhost:9000", "http://127.0.0.1:9000"}


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.5", "example.com", "::"])
def test_non_loopback_host_is_rejected(host):
    with pytest.raises(ConfigError, match="ESIGN_HOST"):
        load_settings({"ESIGN_HOST": host})


@pytest.mark.parametrize("name, value", [
    ("ESIGN_PORT", "abc"), ("ESIGN_PORT", "0"), ("ESIGN_PORT", "70000"),
    ("ESIGN_MAX_PDF_MB", "-1"), ("ESIGN_MAX_P12_KB", "1.5"), ("ESIGN_MAX_PLACEMENTS", "0"),
    ("ESIGN_MAX_IN_FLIGHT", "100"), ("ESIGN_MAX_EXISTING_SIGNATURES", "0"),
    ("ESIGN_MAX_EXISTING_SIGNATURES", "many"), ("ESIGN_MAX_REVISIONS", "0"), ("ESIGN_MAX_REVISIONS", "x"),
])
def test_invalid_values_name_the_variable(name, value):
    with pytest.raises(ConfigError, match=name):
        load_settings({name: value})


def test_default_http_port_is_omitted_from_allowed_origins():
    # Browsers serialise http://127.0.0.1:80 as http://127.0.0.1.
    assert load_settings({"ESIGN_PORT": "80"}).allowed_origins == {"http://127.0.0.1", "http://localhost"}


def test_body_timeout_setting():
    assert load_settings({}).body_timeout_s == 30
    assert load_settings({"ESIGN_BODY_TIMEOUT_S": "5"}).body_timeout_s == 5
    with pytest.raises(ConfigError, match="ESIGN_BODY_TIMEOUT_S"):
        load_settings({"ESIGN_BODY_TIMEOUT_S": "0"})


def test_max_existing_signatures_setting():
    assert load_settings({}).max_existing_signatures == 20
    assert load_settings({"ESIGN_MAX_EXISTING_SIGNATURES": "3"}).max_existing_signatures == 3


def test_max_revisions_setting():
    assert load_settings({}).max_revisions == 100
    assert load_settings({"ESIGN_MAX_REVISIONS": "7"}).max_revisions == 7
