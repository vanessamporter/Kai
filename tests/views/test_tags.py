import json

import pytest

from kai.models import Pcap, Tag

pytestmark = pytest.mark.django_db


@pytest.fixture
def user(make_user):
    return make_user(email="tagctrl@example.com", is_staff=True)


@pytest.fixture
def logged_in(client, user):
    client.post("/login", {"email": "tagctrl@example.com", "password": "password123"})
    for name in ("modbus", "dnp3", "http"):
        Tag.objects.create(name=name)
    return user


def get_json(client, path, **params):
    response = client.get(path, params, HTTP_ACCEPT="application/json")
    return response, json.loads(response.content)


def test_tags_index_is_publicly_accessible(client, logged_in):
    client.post("/logout")
    assert client.get("/tags").status_code == 200


def test_tags_create_requires_auth(client, logged_in):
    client.post("/logout")
    response = client.post("/tags", {"tag[name]": "unauthorized"})
    assert Tag.objects.count() == 3
    assert response.status_code == 302
    assert response.url == "/login"


def test_tags_index_returns_json_with_tags_and_total(client, logged_in):
    response, data = get_json(client, "/tags")
    assert response.status_code == 200
    assert data["total"] == 3
    assert len(data["tags"]) == 3
    assert isinstance(data["tags"], list)


def test_tags_index_filters_by_query(client, logged_in):
    _response, data = get_json(client, "/tags", q="mod")
    assert data["total"] == 1
    assert data["tags"] == ["modbus"]


def test_tags_index_orders_by_usage_count(client, logged_in):
    pcap = Pcap.objects.create(filename="test.pcap", user=logged_in)
    pcap.tags.add(Tag.objects.get(name="modbus"))
    _response, data = get_json(client, "/tags")
    assert data["tags"][0] == "modbus"


def test_tags_json_extension_returns_autocomplete_suggestions(client, logged_in):
    response = client.get("/tags.json")
    assert response.status_code == 200
    data = json.loads(response.content)
    assert isinstance(data["tags"], list)
    assert data["total"] == 3
    assert len(data["tags"]) == 3


def test_tags_json_extension_filters_by_query_param(client, logged_in):
    response = client.get("/tags.json", {"q": "mod"})
    assert response.status_code == 200
    data = json.loads(response.content)
    assert data["total"] == 1
    assert data["tags"] == ["modbus"]


def test_tags_index_renders_html_management_page(client, logged_in):
    response = client.get("/tags")
    content = response.content.decode()
    assert response.status_code == 200
    assert "modbus" in content
    assert "dnp3" in content
    assert "http" in content


def test_tags_index_html_shows_pcap_counts(client, logged_in):
    pcap = Pcap.objects.create(filename="test.pcap", user=logged_in)
    pcap.tags.add(Tag.objects.get(name="modbus"))
    response = client.get("/tags")
    content = response.content.decode()
    assert response.status_code == 200
    assert 'href="/pcaps?tags=modbus"' in content
    assert 'data-action="tag-row#startEdit"' in content
    assert "molly-" not in content


def test_create_tag(client, logged_in):
    response = client.post("/tags", {"tag[name]": "new-protocol"})
    assert Tag.objects.count() == 4
    assert response.status_code == 302
    assert response.url == "/tags"
    followed = client.get(response.url)
    assert "new-protocol" in followed.content.decode()


def test_create_tag_normalizes_name(client, logged_in):
    response = client.post("/tags", {"tag[name]": "  UPPERCASE  "})
    assert response.status_code == 302
    assert Tag.objects.filter(name="uppercase").exists()


def test_create_tag_rejects_duplicate(client, logged_in):
    response = client.post("/tags", {"tag[name]": "modbus"})
    assert Tag.objects.count() == 3
    assert response.status_code == 302
    followed = client.get(response.url)
    assert "taken" in followed.content.decode()


def test_create_tag_rejects_blank_name(client, logged_in):
    response = client.post("/tags", {"tag[name]": ""})
    assert Tag.objects.count() == 3
    assert response.status_code == 302
    assert response.url == "/tags"


def test_rename_tag(client, logged_in):
    tag = Tag.objects.get(name="modbus")
    response = client.post(f"/tags/{tag.id}", {"tag[name]": "modbus-tcp"})
    assert response.status_code == 302
    assert response.url == "/tags"
    tag.refresh_from_db()
    assert tag.name == "modbus-tcp"


def test_rename_tag_rejects_duplicate_name(client, logged_in):
    tag = Tag.objects.get(name="modbus")
    response = client.post(f"/tags/{tag.id}", {"tag[name]": "dnp3"})
    assert response.status_code == 302
    followed = client.get(response.url)
    assert "taken" in followed.content.decode()
    tag.refresh_from_db()
    assert tag.name == "modbus"


def test_delete_tag(client, logged_in):
    tag = Tag.objects.get(name="http")
    response = client.post(f"/tags/{tag.id}", {"_method": "delete"})
    assert Tag.objects.count() == 2
    assert response.status_code == 302
    assert response.url == "/tags"


def test_delete_tag_removes_tag_from_pcaps(client, logged_in):
    pcap = Pcap.objects.create(filename="test.pcap", user=logged_in)
    modbus = Tag.objects.get(name="modbus")
    pcap.tags.add(modbus)
    assert pcap.tags.count() == 1

    response = client.post(f"/tags/{modbus.id}", {"_method": "delete"})
    assert response.status_code == 302
    pcap.refresh_from_db()
    assert pcap.tags.count() == 0


def test_rename_tag_requires_auth(client, logged_in):
    client.post("/logout")
    tag = Tag.objects.get(name="modbus")
    response = client.post(f"/tags/{tag.id}", {"tag[name]": "renamed"})
    assert response.status_code == 302
    assert response.url == "/login"
    tag.refresh_from_db()
    assert tag.name == "modbus"


def test_delete_tag_requires_auth(client, logged_in):
    client.post("/logout")
    tag = Tag.objects.get(name="modbus")
    response = client.post(f"/tags/{tag.id}", {"_method": "delete"})
    assert Tag.objects.count() == 3
    assert response.status_code == 302
    assert response.url == "/login"
