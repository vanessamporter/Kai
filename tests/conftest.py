from datetime import timedelta

import pytest
from django.utils import timezone

from kai.models import User
from kai.security import token_digest


@pytest.fixture(autouse=True)
def media_root(settings, tmp_path):
    settings.MEDIA_ROOT = tmp_path / "storage"
    # Serve static files from finders so whitenoise doesn't warn about the
    # uncollected staticfiles/ directory.
    settings.WHITENOISE_AUTOREFRESH = True
    settings.ALLOW_PUBLIC_SIGNUP = True
    settings.SESSION_COOKIE_SECURE = False
    settings.CSRF_COOKIE_SECURE = False
    settings.EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"


@pytest.fixture(autouse=True)
def fast_password_hashing(settings):
    """Speed up tests with MD5 hashing, same trick as Rails' BCrypt::MIN_COST.

    Tests that specifically verify bcrypt behavior override this.
    """
    settings.PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]


@pytest.fixture
def make_user(db):
    def _make_user(email="test@example.com", password="password123", **fields):
        return User.objects.create_user(email=email, password=password, **fields)

    return _make_user


@pytest.fixture
def user(make_user):
    return make_user()


@pytest.fixture
def set_test_token():
    def _set(user, raw_token):
        user.api_token_digest = token_digest(raw_token)
        user.api_token_prefix = raw_token[:8]
        user.api_token_created_at = timezone.now()
        user.api_token_expires_at = timezone.now() + timedelta(days=1)
        user.save()
        return raw_token

    return _set
