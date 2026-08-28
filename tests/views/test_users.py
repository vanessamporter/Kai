import pytest

from kai.models import User

pytestmark = pytest.mark.django_db


@pytest.fixture
def staff(client, make_user):
    user = make_user(email="admin@example.com", is_staff=True)
    client.post("/login", {"email": user.email, "password": "password123"})
    return user


def test_users_page_requires_staff(client, make_user):
    user = make_user(email="member@example.com")
    client.post("/login", {"email": user.email, "password": "password123"})

    assert client.get("/users").status_code == 403


def test_staff_can_approve_pending_user(client, staff, make_user):
    pending = make_user(email="pending@example.com", is_active=False)

    response = client.post(f"/users/{pending.id}/approve")

    assert response.status_code == 302
    pending.refresh_from_db()
    assert pending.is_active


def test_staff_can_create_active_member(client, staff):
    response = client.post(
        "/users",
        {
            "user[email]": "created@example.com",
            "user[password]": "Strong-test-passphrase-123!",
            "user[password_confirmation]": "Strong-test-passphrase-123!",
        },
    )

    assert response.status_code == 302
    user = User.objects.get(email="created@example.com")
    assert user.is_active
    assert not user.is_staff


def test_staff_can_create_another_administrator(client, staff):
    response = client.post(
        "/users",
        {
            "user[email]": "second-admin@example.com",
            "user[password]": "Strong-test-passphrase-123!",
            "user[password_confirmation]": "Strong-test-passphrase-123!",
            "user[is_staff]": "1",
        },
    )

    assert response.status_code == 302
    assert User.objects.get(email="second-admin@example.com").is_staff
