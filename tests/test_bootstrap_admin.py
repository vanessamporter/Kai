import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from kai.models import User

pytestmark = pytest.mark.django_db


def test_bootstrap_admin_creates_active_staff_user(monkeypatch):
    monkeypatch.setenv("KAI_INITIAL_ADMIN_EMAIL", "first-admin@example.com")
    monkeypatch.setenv("KAI_INITIAL_ADMIN_PASSWORD", "Strong-bootstrap-passphrase-123!")

    call_command("bootstrap_admin")

    user = User.objects.get(email="first-admin@example.com")
    assert user.is_active
    assert user.is_staff
    assert user.check_password("Strong-bootstrap-passphrase-123!")


def test_bootstrap_admin_is_idempotent_and_does_not_reset_password(monkeypatch, make_user):
    user = make_user(email="existing@example.com", password="Original-password-123!")
    monkeypatch.setenv("KAI_INITIAL_ADMIN_EMAIL", user.email)
    monkeypatch.setenv("KAI_INITIAL_ADMIN_PASSWORD", "Different-password-123!")

    call_command("bootstrap_admin")

    user.refresh_from_db()
    assert user.is_active
    assert user.is_staff
    assert user.check_password("Original-password-123!")


def test_bootstrap_admin_requires_both_environment_values(monkeypatch):
    monkeypatch.setenv("KAI_INITIAL_ADMIN_EMAIL", "admin@example.com")
    monkeypatch.delenv("KAI_INITIAL_ADMIN_PASSWORD", raising=False)

    with pytest.raises(CommandError):
        call_command("bootstrap_admin")
