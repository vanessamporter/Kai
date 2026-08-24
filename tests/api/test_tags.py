import json

import pytest

from kai.models import Tag

pytestmark = pytest.mark.django_db

AUTH = {"Authorization": "Bearer tag_token_123"}


@pytest.fixture
def tags(make_user, set_test_token):
    user = make_user(email="apitag@example.com")
    set_test_token(user, "tag_token_123")
    for name in ("modbus", "dnp3", "http"):
        Tag.objects.create(name=name)
    return user


def test_index_is_publicly_accessible(client, tags):
    response = client.get("/api/v1/tags")
    assert response.status_code == 200
    assert len(json.loads(response.content)["data"]) == 3


def test_index_returns_all_tags(client, tags):
    response = client.get("/api/v1/tags", headers=AUTH)
    assert response.status_code == 200
    assert len(json.loads(response.content)["data"]) == 3


def test_index_filters_by_query(client, tags):
    response = client.get("/api/v1/tags", {"q": "mod"}, headers=AUTH)
    data = json.loads(response.content)
    assert data["data"] == ["modbus"]
