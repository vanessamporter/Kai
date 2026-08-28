import pytest
from django.core.exceptions import ValidationError

from kai.models import Pcap, User

pytestmark = pytest.mark.django_db


def test_valid_user():
    user = User(email="test@example.com")
    user.set_password("password123")
    user.full_clean()  # raises if invalid


def test_requires_email():
    user = User()
    user.set_password("password123")
    with pytest.raises(ValidationError) as excinfo:
        user.full_clean()
    assert "email" in excinfo.value.message_dict


def test_requires_unique_email(make_user):
    make_user(email="test@example.com")
    user = User(email="test@example.com")
    user.set_password("password123")
    with pytest.raises(ValidationError) as excinfo:
        user.full_clean()
    assert "email" in excinfo.value.message_dict


def test_normalizes_email_to_lowercase(make_user):
    user = make_user(email="TEST@Example.COM")
    assert user.email == "test@example.com"


def test_requires_valid_email_format():
    user = User(email="notanemail")
    user.set_password("password123")
    with pytest.raises(ValidationError) as excinfo:
        user.full_clean()
    assert "email" in excinfo.value.message_dict


def test_authenticates_with_correct_password(make_user):
    user = make_user()
    assert user.check_password("password123")
    assert not user.check_password("wrongpassword")


def test_password_digest_is_bcrypt(settings, db):
    settings.PASSWORD_HASHERS = ["django.contrib.auth.hashers.BCryptPasswordHasher"]
    user = User.objects.create_user(email="bcrypt@example.com", password="password123")
    # Raw bcrypt (no SHA-256 pre-hash) keeps digests compatible with Rails
    # has_secure_password data.
    assert user.password.startswith("bcrypt$$2")
    assert user.check_password("password123")


def test_authenticates_with_legacy_rails_bcrypt_digest(settings, db):
    settings.PASSWORD_HASHERS = ["django.contrib.auth.hashers.BCryptPasswordHasher"]
    user = User.objects.create_user(email="legacy@example.com", password="password123")
    user.password = user.password.removeprefix("bcrypt$")
    user.save(update_fields=["password"])

    assert user.check_password("password123")
    assert not user.check_password("wrongpassword")


def test_has_many_pcaps(user):
    pcap = user.pcaps.create(filename="test.pcap")
    assert pcap in user.pcaps.all()


def test_destroys_pcaps_when_destroyed(user):
    user.pcaps.create(filename="test.pcap")
    user.delete()
    assert Pcap.objects.count() == 0


def test_strips_whitespace_from_email(make_user):
    user = make_user(email="  spaces@example.com  ")
    assert user.email == "spaces@example.com"


def test_create_superuser_creates_active_staff_account():
    user = User.objects.create_superuser(email="admin@example.com", password="password123")

    assert user.is_active
    assert user.is_staff
