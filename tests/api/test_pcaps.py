import json
from pathlib import Path
from urllib.parse import urlencode

import pytest
from django.core.files.base import ContentFile
from django.core.files.uploadedfile import SimpleUploadedFile

from kai.models import Pcap, Tag

pytestmark = pytest.mark.django_db

FIXTURE_FILES = Path(__file__).resolve().parent.parent / "fixtures" / "files"
AUTH = {"Authorization": "Bearer test_token_abc123"}
VALID_PCAP = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 8 + b"\xff\xff\x00\x00\x01\x00\x00\x00"


@pytest.fixture
def user(make_user, set_test_token):
    user = make_user(email="apipcap@example.com")
    set_test_token(user, "test_token_abc123")
    return user


@pytest.fixture
def pcap(user):
    return user.pcaps.create(filename="test.pcap", event="Test Event", sector="Chemical")


def get_data(client, path, params=None, **kwargs):
    kwargs.setdefault("headers", AUTH)
    response = client.get(path, params or {}, **kwargs)
    return response, json.loads(response.content)


def test_index_requires_auth(client, pcap):
    response = client.get("/api/v1/pcaps")
    assert response.status_code == 401


def test_create_requires_auth(client, pcap):
    upload = SimpleUploadedFile("test.pcap", VALID_PCAP)
    response = client.post("/api/v1/pcaps", {"file": upload, "event": "No Auth"})
    assert Pcap.objects.count() == 1
    assert response.status_code == 401


def test_index_returns_paginated_results(client, pcap):
    response, data = get_data(client, "/api/v1/pcaps", headers=AUTH)
    assert response.status_code == 200
    assert isinstance(data["data"], list)
    assert data["meta"]["page"] == 1
    assert data["meta"]["total_count"] == 1
    assert data["meta"]["total_pages"] == 1


def test_index_filters_by_sector(client, user, pcap):
    user.pcaps.create(filename="water.pcap", sector="Water Treatment")
    _response, data = get_data(client, "/api/v1/pcaps", {"sector": "Chemical"}, headers=AUTH)
    assert len(data["data"]) == 1
    assert data["data"][0]["filename"] == "test.pcap"


def test_index_filters_by_event(client, pcap):
    _response, data = get_data(client, "/api/v1/pcaps", {"event": "Test"}, headers=AUTH)
    assert len(data["data"]) == 1


def test_index_filters_by_baseline(client, user, pcap):
    pcap.baseline = True
    pcap.save()
    user.pcaps.create(filename="other.pcap", baseline=False)
    _response, data = get_data(client, "/api/v1/pcaps", {"baseline": "true"}, headers=AUTH)
    assert len(data["data"]) == 1


def test_index_filters_by_tags(client, user, pcap):
    pcap.tags.add(Tag.objects.create(name="modbus"))
    user.pcaps.create(filename="untagged.pcap")

    _response, data = get_data(client, "/api/v1/pcaps", {"tag": "modbus"}, headers=AUTH)
    assert len(data["data"]) == 1
    assert data["data"][0]["filename"] == "test.pcap"


def test_show_returns_pcap(client, pcap):
    response, data = get_data(client, f"/api/v1/pcaps/{pcap.id}", headers=AUTH)
    assert response.status_code == 200
    assert data["data"]["filename"] == "test.pcap"
    assert data["data"]["uploader"] == "apipcap@example.com"


def test_show_returns_404_for_missing_pcap(client, user):
    response = client.get("/api/v1/pcaps/999999", headers=AUTH)
    assert response.status_code == 404


def test_create_pcap_with_file(client, user):
    upload = SimpleUploadedFile("test.pcap", VALID_PCAP)
    response = client.post(
        "/api/v1/pcaps",
        {"file": upload, "event": "API Upload", "tags": "api,test"},
        headers=AUTH,
    )
    assert Pcap.objects.count() == 1
    assert response.status_code == 201
    data = json.loads(response.content)
    assert data["data"]["filename"] == "test.pcap"
    assert "api" in data["data"]["tags"]


def test_create_rejects_non_pcap_file(client, user):
    with open(FIXTURE_FILES / "test.txt", "rb") as f:
        response = client.post("/api/v1/pcaps", {"file": f}, headers=AUTH)
    assert Pcap.objects.count() == 0
    assert response.status_code == 422


def test_create_rejects_spoofed_pcap_extension(client, user):
    upload = SimpleUploadedFile("spoofed.pcap", b"not a capture")
    response = client.post("/api/v1/pcaps", {"file": upload}, headers=AUTH)
    assert response.status_code == 422
    assert "File contents are not a valid" in json.loads(response.content)["error"]


def test_create_requires_file(client, user):
    response = client.post("/api/v1/pcaps", {"event": "No File"}, headers=AUTH)
    assert response.status_code == 422
    assert json.loads(response.content)["error"] == "File is required"


def test_update_metadata(client, pcap):
    response = client.patch(
        f"/api/v1/pcaps/{pcap.id}",
        urlencode({"event": "Updated Event", "tags": "new_tag"}),
        content_type="application/x-www-form-urlencoded",
        headers=AUTH,
    )
    assert response.status_code == 200
    data = json.loads(response.content)
    assert data["data"]["event"] == "Updated Event"
    assert "new_tag" in data["data"]["tags"]


def test_destroy_pcap(client, pcap):
    response = client.delete(f"/api/v1/pcaps/{pcap.id}", headers=AUTH)
    assert Pcap.objects.count() == 0
    assert response.status_code == 204


def test_download_streams_file(client, pcap):
    pcap.file.save("test.pcap", ContentFile(b"pcap data"))
    response = client.get(f"/api/v1/pcaps/{pcap.id}/download", headers=AUTH)
    assert response.status_code == 200
    assert b"".join(response.streaming_content) == b"pcap data"


def test_download_returns_404_without_file(client, pcap):
    response = client.get(f"/api/v1/pcaps/{pcap.id}/download", headers=AUTH)
    assert response.status_code == 404


def test_update_requires_auth(client, pcap):
    response = client.patch(
        f"/api/v1/pcaps/{pcap.id}",
        urlencode({"event": "Unauthorized"}),
        content_type="application/x-www-form-urlencoded",
    )
    assert response.status_code == 401


def test_destroy_requires_auth(client, pcap):
    response = client.delete(f"/api/v1/pcaps/{pcap.id}")
    assert Pcap.objects.count() == 1
    assert response.status_code == 401


def test_download_requires_auth(client, pcap):
    pcap.file.save("test.pcap", ContentFile(b"public data"))
    response = client.get(f"/api/v1/pcaps/{pcap.id}/download")
    assert response.status_code == 401


def test_fulltext_search_via_q_param(client, user, pcap):
    user.pcaps.create(filename="other.pcap", description="Unique industrial traffic capture")
    _response, data = get_data(client, "/api/v1/pcaps", {"q": "industrial"})
    assert len(data["data"]) == 1
    assert data["data"][0]["filename"] == "other.pcap"


def test_show_requires_auth(client, pcap):
    response = client.get(f"/api/v1/pcaps/{pcap.id}")
    assert response.status_code == 401


def test_show_includes_tshark_analysis(client, pcap):
    pcap.tshark_analysis = {"protocols": ["eth", "ip", "modbus"]}
    pcap.save()
    _response, data = get_data(client, f"/api/v1/pcaps/{pcap.id}")
    assert data["data"]["tshark_analysis"]["protocols"] == ["eth", "ip", "modbus"]


def test_update_replaces_existing_tags(client, pcap):
    pcap.tags.add(Tag.objects.create(name="old-api-tag"))
    response = client.patch(
        f"/api/v1/pcaps/{pcap.id}",
        urlencode({"tags": "new-api-tag"}),
        content_type="application/x-www-form-urlencoded",
        headers=AUTH,
    )
    assert response.status_code == 200
    data = json.loads(response.content)
    assert "new-api-tag" in data["data"]["tags"]
    assert "old-api-tag" not in data["data"]["tags"]
