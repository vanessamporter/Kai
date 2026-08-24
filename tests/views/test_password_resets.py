from urllib.parse import urlparse

import pytest
from django.core import mail

pytestmark = pytest.mark.django_db

NEW_PASSWORD = "Strong-reset-passphrase-456!"


@pytest.fixture
def user(make_user):
    return make_user(email="reset@example.com", password="oldpass123")


def test_get_password_reset_renders_email_form(client, user):
    response = client.get("/password_reset")
    assert response.status_code == 200
    assert "Send reset link" in response.content.decode()


def test_password_reset_requires_emailed_expiring_token(client, user):
    response = client.post("/password_reset", {"email": "reset@example.com"})
    assert response.status_code == 302
    assert response.url == "/password_reset/done"
    assert len(mail.outbox) == 1

    reset_url = next(
        line for line in mail.outbox[0].body.splitlines() if "/password_reset/" in line
    )
    response = client.get(urlparse(reset_url).path)
    assert response.status_code == 302
    response = client.post(
        response.url,
        {"new_password1": NEW_PASSWORD, "new_password2": NEW_PASSWORD},
    )
    assert response.status_code == 302
    assert response.url == "/password_reset/complete"
    login = client.post("/login", {"email": "reset@example.com", "password": NEW_PASSWORD})
    assert login.status_code == 302


def test_unknown_email_has_same_response_and_sends_nothing(client, user):
    response = client.post("/password_reset", {"email": "unknown@example.com"})
    assert response.status_code == 302
    assert response.url == "/password_reset/done"
    assert mail.outbox == []


def test_invalid_reset_token_does_not_change_password(client, user):
    response = client.get("/password_reset/not-a-user/not-a-token")
    assert response.status_code == 200
    assert "invalid or has expired" in response.content.decode()
    assert user.check_password("oldpass123")
