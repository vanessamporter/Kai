import os
import subprocess
import sys


def load_production_settings(**values):
    env = os.environ.copy()
    env.update(
        {
            "DJANGO_PRODUCTION": "1",
            "DJANGO_DEBUG": "0",
            "SECRET_KEY_BASE": "release-secret-0123456789abcdef0123456789abcdef",
            "DJANGO_ALLOWED_HOSTS": "kai.example.com",
            "SOURCE_CODE_URL": "https://example.com/kai",
            **values,
        }
    )
    return subprocess.run(
        [sys.executable, "-c", "import config.settings"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_production_settings_accept_safe_configuration():
    assert load_production_settings().returncode == 0


def test_production_settings_reject_default_secret():
    result = load_production_settings(
        SECRET_KEY_BASE="dev-only-secret-key-base-change-in-production"
    )
    assert result.returncode != 0
    assert "SECRET_KEY_BASE is required" in result.stderr


def test_production_settings_reject_wildcard_host():
    result = load_production_settings(DJANGO_ALLOWED_HOSTS="*")
    assert result.returncode != 0
    assert "explicit DJANGO_ALLOWED_HOSTS" in result.stderr
