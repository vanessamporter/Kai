import pytest

from kai.security import token_digest

pytestmark = pytest.mark.django_db


@pytest.fixture
def user(make_user):
    return make_user(email="profile@example.com")


@pytest.fixture
def logged_in(client, user):
    client.post("/login", {"email": "profile@example.com", "password": "password123"})
    return user


def test_get_profile_requires_auth(client, logged_in):
    client.post("/logout")
    response = client.get("/profile")
    assert response.status_code == 302
    assert response.url == "/login"


def test_get_profile_shows_profile_page(client, logged_in):
    response = client.get("/profile")
    assert response.status_code == 200


def test_regenerate_token_generates_a_new_token(client, logged_in):
    assert logged_in.api_token_digest is None
    response = client.post("/profile/regenerate_token")
    logged_in.refresh_from_db()
    assert logged_in.api_token_digest
    assert response.status_code == 302
    assert response.url == "/profile"


def test_regenerate_token_replaces_existing_token(client, logged_in, set_test_token):
    set_test_token(logged_in, "old_token")
    old_digest = logged_in.api_token_digest
    client.post("/profile/regenerate_token")
    logged_in.refresh_from_db()
    assert logged_in.api_token_digest != old_digest


def test_regenerate_token_requires_auth(client, logged_in):
    client.post("/logout")
    response = client.post("/profile/regenerate_token")
    assert response.status_code == 302
    assert response.url == "/login"


def test_generated_token_is_shown_once_and_stored_as_hash(client, logged_in):
    response = client.post("/profile/regenerate_token", follow=True)
    logged_in.refresh_from_db()
    content = response.content.decode()
    token = content.split('class="kai-token mt-1">', 1)[1].split("</p>", 1)[0]
    assert logged_in.api_token_digest == token_digest(token)
    assert token not in client.get("/profile").content.decode()


def test_revoke_token(client, logged_in, set_test_token):
    set_test_token(logged_in, "revocable")
    response = client.post("/profile/revoke_token")
    logged_in.refresh_from_db()
    assert response.status_code == 302
    assert logged_in.api_token_digest is None
