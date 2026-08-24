import pytest

pytestmark = pytest.mark.django_db


@pytest.fixture
def user(make_user):
    return make_user(email="login@example.com")


def test_get_login_renders_login_form(client, user):
    response = client.get("/login")
    assert response.status_code == 200


def test_post_login_with_valid_credentials_logs_in(client, user):
    response = client.post("/login", {"email": "login@example.com", "password": "password123"})
    assert response.status_code == 302
    assert response.url == "/pcaps"


def test_post_login_with_invalid_credentials_shows_error(client, user):
    response = client.post("/login", {"email": "login@example.com", "password": "wrong"})
    assert response.status_code == 422


def test_logout_clears_session(client, user):
    client.post("/login", {"email": "login@example.com", "password": "password123"})
    response = client.post("/logout")
    assert response.status_code == 302
    assert response.url == "/login"

    response = client.get("/profile")
    assert response.status_code == 302
    assert response.url == "/login"


def test_post_login_with_nonexistent_email_shows_error(client, user):
    response = client.post("/login", {"email": "nobody@example.com", "password": "password123"})
    assert response.status_code == 422


def test_repeated_failed_logins_are_throttled(client, user, settings):
    settings.AUTH_RATE_LIMIT_ATTEMPTS = 2
    credentials = {"email": user.email, "password": "wrong"}

    assert client.post("/login", credentials).status_code == 422
    assert client.post("/login", credentials).status_code == 422
    assert client.post("/login", credentials).status_code == 429


def test_security_headers_include_nonce_based_csp(client):
    response = client.get("/login")

    assert response.status_code == 200
    assert "script-src 'self' 'nonce-" in response.headers["Content-Security-Policy"]
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Permissions-Policy"].startswith("camera=()")
