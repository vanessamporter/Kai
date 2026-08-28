from pathlib import Path

import pytest
from django.core.files.base import ContentFile
from django.core.files.uploadedfile import SimpleUploadedFile

from kai.models import Pcap, Tag

pytestmark = pytest.mark.django_db

FIXTURE_FILES = Path(__file__).resolve().parent.parent / "fixtures" / "files"
VALID_PCAP = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 8 + b"\xff\xff\x00\x00\x01\x00\x00\x00"


@pytest.fixture
def user(make_user):
    return make_user(email="pcapctrl@example.com")


@pytest.fixture
def logged_in(client, user):
    client.post("/login", {"email": "pcapctrl@example.com", "password": "password123"})
    return user


def upload(client, filename, **extra_fields):
    if filename == "test.pcap":
        upload_file = SimpleUploadedFile(filename, VALID_PCAP)
        return client.post(
            "/pcaps", {"pcap[file]": upload_file, "pcap[tag_list]": "", **extra_fields}
        )
    with open(FIXTURE_FILES / filename, "rb") as f:
        data = {"pcap[file]": f, "pcap[tag_list]": "", **extra_fields}
        return client.post("/pcaps", data)


def test_pcaps_index_requires_auth(client, logged_in):
    client.post("/logout")
    response = client.get("/pcaps")
    assert response.status_code == 302
    assert response.url == "/login"


def test_pcaps_new_requires_auth(client, logged_in):
    client.post("/logout")
    response = client.get("/pcaps/new")
    assert response.status_code == 302
    assert response.url == "/login"


def test_pcaps_index_shows_browse_page(client, logged_in):
    response = client.get("/pcaps")
    content = response.content.decode()
    assert response.status_code == 200
    assert 'for="platform"' not in content
    assert 'for="sponsor"' not in content


def test_pcaps_new_shows_upload_form(client, logged_in):
    response = client.get("/pcaps/new")
    content = response.content.decode()
    assert response.status_code == 200
    assert 'for="pcap_platform"' not in content
    assert 'for="pcap_sponsor"' not in content


def test_upload_creates_pcap(client, logged_in):
    response = upload(
        client, "test.pcap", **{"pcap[event]": "Test Event", "pcap[tag_list]": "dns, test"}
    )
    assert Pcap.objects.count() == 1
    pcap = Pcap.objects.last()
    assert response.status_code == 302
    assert response.url == f"/pcaps/{pcap.id}"
    assert pcap.filename == "test.pcap"
    assert pcap.tags.count() == 2


def test_upload_rejects_non_pcap_files(client, logged_in):
    response = upload(client, "test.txt")
    assert Pcap.objects.count() == 0
    assert response.status_code == 422


def test_show_pcap(client, logged_in):
    pcap = logged_in.pcaps.create(filename="show.pcap", file_size=1024, sha256="abc123")
    assert client.get(f"/pcaps/{pcap.id}").status_code == 200


def test_show_pcap_tags_link_to_filtered_captures(client, logged_in):
    pcap = logged_in.pcaps.create(filename="tagged.pcap")
    pcap.tags.add(Tag.objects.create(name="modbus/tcp"))

    response = client.get(f"/pcaps/{pcap.id}")

    assert 'href="/pcaps?tags=modbus/tcp"' in response.content.decode()


def test_show_pcap_displays_tshark_analysis(client, logged_in):
    pcap = logged_in.pcaps.create(
        filename="analyzed.pcap",
        tshark_analysis={
            "analyzed_packets": 2,
            "protocols": ["eth", "ip", "modbus"],
            "endpoints": [{"address": "10.0.0.1", "packets": 2}],
        },
    )
    response = client.get(f"/pcaps/{pcap.id}")
    content = response.content.decode()
    assert "Automatic Tshark Analysis" in content
    assert "modbus" in content
    assert "10.0.0.1" in content


def test_edit_form(client, logged_in):
    pcap = logged_in.pcaps.create(filename="edit.pcap")
    assert client.get(f"/pcaps/{pcap.id}/edit").status_code == 200


def test_update_metadata(client, logged_in):
    pcap = logged_in.pcaps.create(filename="update.pcap", event="Old Event")
    response = client.post(
        f"/pcaps/{pcap.id}", {"pcap[event]": "New Event", "pcap[tag_list]": "updated"}
    )
    assert response.status_code == 302
    assert response.url == f"/pcaps/{pcap.id}"
    pcap.refresh_from_db()
    assert pcap.event == "New Event"
    assert list(pcap.tags.values_list("name", flat=True)) == ["updated"]


def test_destroy_pcap(client, logged_in):
    pcap = logged_in.pcaps.create(filename="delete.pcap")
    response = client.post(f"/pcaps/{pcap.id}", {"_method": "delete"})
    assert Pcap.objects.count() == 0
    assert response.status_code == 302
    assert response.url == "/pcaps"


def test_download_streams_file(client, logged_in):
    pcap = logged_in.pcaps.create(filename="download.pcap")
    pcap.file.save("download.pcap", ContentFile(b"fake pcap data"))
    response = client.get(f"/pcaps/{pcap.id}/download")
    assert response.status_code == 200
    assert b"".join(response.streaming_content) == b"fake pcap data"


def test_upload_shows_duplicate_sha256_warning(client, logged_in):
    upload(client, "test.pcap")
    response = upload(client, "test.pcap")
    pcap = Pcap.objects.latest("id")
    assert response.status_code == 302
    assert response.url == f"/pcaps/{pcap.id}"
    followed = client.get(response.url)
    assert "same SHA-256 hash" in followed.content.decode()


def test_upload_handles_tags_with_special_characters(client, logged_in):
    upload(client, "test.pcap", **{"pcap[tag_list]": "iec-61850, modbus/tcp"})
    pcap = Pcap.objects.last()
    tag_names = list(pcap.tags.values_list("name", flat=True))
    assert "iec-61850" in tag_names
    assert "modbus/tcp" in tag_names


def test_index_with_no_results_shows_empty_state(client, logged_in):
    response = client.get("/pcaps", {"sector": "Nonexistent"})
    assert response.status_code == 200
    assert "No pcaps match your filters" in response.content.decode()


def test_upload_without_file_shows_error(client, logged_in):
    response = client.post("/pcaps", {"pcap[event]": "No File", "pcap[tag_list]": ""})
    assert Pcap.objects.count() == 0
    assert response.status_code == 422


def test_download_without_file_redirects_with_alert(client, logged_in):
    pcap = logged_in.pcaps.create(filename="nofile.pcap")
    response = client.get(f"/pcaps/{pcap.id}/download")
    assert response.status_code == 302
    assert response.url == f"/pcaps/{pcap.id}"
    followed = client.get(response.url)
    assert "File not found" in followed.content.decode()


def test_show_requires_auth(client, logged_in):
    client.post("/logout")
    pcap = logged_in.pcaps.create(filename="public.pcap")
    response = client.get(f"/pcaps/{pcap.id}")
    assert response.status_code == 302
    assert response.url == "/login"


def test_download_requires_auth(client, logged_in):
    client.post("/logout")
    pcap = logged_in.pcaps.create(filename="public_dl.pcap")
    pcap.file.save("public_dl.pcap", ContentFile(b"data"))
    response = client.get(f"/pcaps/{pcap.id}/download")
    assert response.status_code == 302
    assert response.url == "/login"


def test_upload_rejects_spoofed_pcap_extension(client, logged_in):
    upload_file = SimpleUploadedFile("spoofed.pcap", b"not a capture")
    response = client.post("/pcaps", {"pcap[file]": upload_file, "pcap[tag_list]": ""})
    assert response.status_code == 422
    assert "File contents are not a valid" in response.content.decode()


def test_edit_requires_auth(client, logged_in):
    client.post("/logout")
    pcap = logged_in.pcaps.create(filename="noedit.pcap")
    response = client.get(f"/pcaps/{pcap.id}/edit")
    assert response.status_code == 302
    assert response.url == "/login"


def test_update_requires_auth(client, logged_in):
    client.post("/logout")
    pcap = logged_in.pcaps.create(filename="noupdate.pcap")
    response = client.post(f"/pcaps/{pcap.id}", {"pcap[event]": "Hacked", "pcap[tag_list]": ""})
    assert response.status_code == 302
    assert response.url == "/login"
    pcap.refresh_from_db()
    assert pcap.event != "Hacked"


def test_destroy_requires_auth(client, logged_in):
    client.post("/logout")
    pcap = logged_in.pcaps.create(filename="nodelete.pcap")
    response = client.post(f"/pcaps/{pcap.id}", {"_method": "delete"})
    assert Pcap.objects.count() == 1
    assert response.status_code == 302
    assert response.url == "/login"


def test_update_replaces_existing_tags(client, logged_in):
    pcap = logged_in.pcaps.create(filename="retag.pcap")
    pcap.tags.add(Tag.objects.create(name="old-tag"))

    response = client.post(f"/pcaps/{pcap.id}", {"pcap[tag_list]": "new-tag1, new-tag2"})
    assert response.status_code == 302
    pcap.refresh_from_db()
    names = sorted(pcap.tags.values_list("name", flat=True))
    assert names == ["new-tag1", "new-tag2"]
