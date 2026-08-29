import pytest

from kai.models import SecurityEvent, User

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


def test_staff_can_view_download_activity(client, staff, make_user):
    member = make_user(email="downloader@example.com")
    SecurityEvent.objects.create(
        user=member,
        event="pcap_download",
        ip_address="192.0.2.10",
        details={
            "pcap_id": 42,
            "filename": "group-capture.pcap",
            "downloader_email": member.email,
            "source": "web",
        },
    )

    response = client.get("/users")
    content = response.content.decode()

    assert "downloader@example.com" in content
    assert "group-capture.pcap" in content
    assert "192.0.2.10" in content
    assert response.headers["Cache-Control"] == (
        "max-age=0, no-cache, no-store, must-revalidate, private"
    )
