import json
from datetime import timedelta

import pytest
from django.utils import timezone

from kai.security import token_digest

pytestmark = pytest.mark.django_db


@pytest.fixture
def user(make_user):
    return make_user(email="apiauth@example.com")


def request_token(client, email, password):
    response = client.post("/api/v1/auth/token", {"email": email, "password": password})
    return response, json.loads(response.content)


def test_token_returned_for_valid_credentials(client, user):
    response, data = request_token(client, "apiauth@example.com", "password123")
    assert response.status_code == 200
    assert data["data"]["api_token"]
    user.refresh_from_db()
    assert user.api_token_digest == token_digest(data["data"]["api_token"])
    assert data["data"]["api_token"] not in user.api_token_digest


def test_token_is_rotated_on_repeat_call(client, user):
    _response, first = request_token(client, "apiauth@example.com", "password123")
    _response, second = request_token(client, "apiauth@example.com", "password123")
    assert first["data"]["api_token"] != second["data"]["api_token"]
    assert second["data"]["expires_at"]


def test_401_for_invalid_password(client, user):
    response, data = request_token(client, "apiauth@example.com", "wrong")
    assert response.status_code == 401
    assert data["error"] == "Invalid email or password"


def test_401_for_unknown_email(client, user):
    response, _data = request_token(client, "nobody@example.com", "password123")
    assert response.status_code == 401


def test_expired_token_is_rejected(client, user):
    _response, data = request_token(client, user.email, "password123")
    user.refresh_from_db()
    user.api_token_expires_at = timezone.now() - timedelta(seconds=1)
    user.save(update_fields=["api_token_expires_at"])

    response = client.post(
        "/api/v1/pcaps",
        HTTP_AUTHORIZATION=f"Bearer {data['data']['api_token']}",
    )
    assert response.status_code == 401
