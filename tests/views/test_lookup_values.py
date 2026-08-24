import json

import pytest

from kai.models import LookupValue

pytestmark = pytest.mark.django_db


@pytest.fixture
def user(make_user):
    return make_user(email="lvctrl@example.com", is_staff=True)


@pytest.fixture
def logged_in(client, user):
    client.post("/login", {"email": "lvctrl@example.com", "password": "password123"})
    LookupValue.objects.create(category="sector", value="Chemical", position=1)
    LookupValue.objects.create(category="sector", value="Water Treatment", position=2)
    LookupValue.objects.create(category="platform", value="Siemens S7", position=1)
    return user


def post_json(client, payload):
    return client.post("/lookup_values", json.dumps(payload), content_type="application/json")


def test_lookup_values_index_is_publicly_accessible(client, logged_in):
    client.post("/logout")
    assert client.get("/lookup_values").status_code == 200


def test_lookup_values_create_requires_auth(client, logged_in):
    client.post("/logout")
    response = post_json(client, {"category": "sector", "value": "Unauthorized"})
    assert LookupValue.objects.count() == 3
    assert response.status_code == 302
    assert response.url == "/login"


def test_lookup_values_index_returns_json_array(client, logged_in):
    response = client.get("/lookup_values")
    assert response.status_code == 200
    data = json.loads(response.content)
    assert isinstance(data, list)
    assert len(data) == 3


def test_lookup_values_index_filters_by_category(client, logged_in):
    response = client.get("/lookup_values", {"category": "sector"})
    data = json.loads(response.content)
    assert len(data) == 2


def test_lookup_values_index_filters_by_query(client, logged_in):
    response = client.get("/lookup_values", {"category": "sector", "q": "Chem"})
    data = json.loads(response.content)
    assert data == ["Chemical"]


def test_lookup_values_create(client, logged_in):
    response = post_json(client, {"category": "sector", "value": "Power Grid"})
    assert LookupValue.objects.count() == 4
    assert response.status_code == 201
    assert json.loads(response.content) == {"value": "Power Grid"}


def test_lookup_values_create_rejects_duplicate_in_same_category(client, logged_in):
    response = post_json(client, {"category": "sector", "value": "Chemical"})
    assert LookupValue.objects.count() == 3
    assert response.status_code == 422


def test_lookup_values_create_auto_increments_position(client, logged_in):
    response = post_json(client, {"category": "sector", "value": "Power Grid"})
    assert response.status_code == 201
    created = LookupValue.objects.get(category="sector", value="Power Grid")
    assert created.position == 3
