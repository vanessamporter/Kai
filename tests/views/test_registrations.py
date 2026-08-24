import pytest

from kai.models import User

pytestmark = pytest.mark.django_db


def signup_params(
    email,
    password="Strong-test-passphrase-123!",
    confirmation="Strong-test-passphrase-123!",
):
    return {
        "user[email]": email,
        "user[password]": password,
        "user[password_confirmation]": confirmation,
    }


def test_get_signup_renders_form(client):
    response = client.get("/signup")
    assert response.status_code == 200


def test_post_signup_creates_user_and_logs_in(client):
    response = client.post("/signup", signup_params("new@example.com"))
    assert User.objects.count() == 1
    assert response.status_code == 302
    assert response.url == "/pcaps"


def test_post_signup_with_mismatched_passwords_fails(client):
    response = client.post("/signup", signup_params("new@example.com", confirmation="different"))
    assert User.objects.count() == 0
    assert response.status_code == 422


def test_post_signup_with_duplicate_email_fails(client, make_user):
    make_user(email="taken@example.com")
    response = client.post("/signup", signup_params("taken@example.com"))
    assert User.objects.count() == 1
    assert response.status_code == 422


def test_post_signup_with_invalid_email_format_fails(client):
    response = client.post("/signup", signup_params("not-an-email"))
    assert User.objects.count() == 0
    assert response.status_code == 422


def test_post_signup_logs_in_the_new_user(client):
    response = client.post("/signup", signup_params("fresh@example.com"))
    assert response.status_code == 302
    # Verify we're logged in by accessing an auth-required page
    response = client.get("/profile")
    assert response.status_code == 200
