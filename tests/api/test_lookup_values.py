import json

import pytest

from kai.models import LookupValue

pytestmark = pytest.mark.django_db

AUTH = {"Authorization": "Bearer lv_token_123"}


@pytest.fixture
def lookup_values(make_user, set_test_token):
    user = make_user(email="apilv@example.com", is_staff=True)
    set_test_token(user, "lv_token_123")
    LookupValue.objects.create(category="sector", value="Chemical", position=1)
    LookupValue.objects.create(category="sector", value="Water Treatment", position=2)
    LookupValue.objects.create(category="platform", value="Siemens S7", position=1)
    return user


def test_index_is_publicly_accessible(client, lookup_values):
    response = client.get("/api/v1/lookup_values")
    assert response.status_code == 200
    assert len(json.loads(response.content)["data"]) == 3


def test_create_requires_auth(client, lookup_values):
    response = client.post("/api/v1/lookup_values", {"category": "sector", "value": "Unauthorized"})
    assert LookupValue.objects.count() == 3
    assert response.status_code == 401


def test_index_returns_all_values(client, lookup_values):
    response = client.get("/api/v1/lookup_values", headers=AUTH)
    assert response.status_code == 200
    assert len(json.loads(response.content)["data"]) == 3


def test_index_filters_by_category(client, lookup_values):
    response = client.get("/api/v1/lookup_values", {"category": "sector"}, headers=AUTH)
    assert len(json.loads(response.content)["data"]) == 2


def test_index_filters_by_query(client, lookup_values):
    response = client.get(
        "/api/v1/lookup_values", {"category": "sector", "q": "Chem"}, headers=AUTH
    )
    assert json.loads(response.content)["data"] == ["Chemical"]


def test_create_new_value(client, lookup_values):
    response = client.post(
        "/api/v1/lookup_values", {"category": "sector", "value": "Power Grid"}, headers=AUTH
    )
    assert LookupValue.objects.count() == 4
    assert response.status_code == 201
    assert json.loads(response.content)["data"]["value"] == "Power Grid"


def test_create_rejects_duplicate(client, lookup_values):
    response = client.post(
        "/api/v1/lookup_values", {"category": "sector", "value": "Chemical"}, headers=AUTH
    )
    assert LookupValue.objects.count() == 3
    assert response.status_code == 422


def test_create_auto_increments_position(client, lookup_values):
    response = client.post(
        "/api/v1/lookup_values", {"category": "sector", "value": "Power Grid"}, headers=AUTH
    )
    assert response.status_code == 201
    created = LookupValue.objects.get(category="sector", value="Power Grid")
    assert created.position == 3
