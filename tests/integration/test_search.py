from datetime import timedelta

import pytest
from django.utils import timezone

from kai.models import Tag

pytestmark = pytest.mark.django_db


@pytest.fixture
def search_data(make_user):
    user = make_user(email="search@example.com")
    pcap1 = user.pcaps.create(
        filename="modbus_baseline.pcap",
        event="BaselineChemLSU",
        sector="Chemical",
        platform="Siemens S7",
        baseline=True,
        description="Industrial control system baseline capture",
        ot_protocols=["Modbus", "DNP3"],
        source_host="192.168.1.10",
        packet_count=5000,
        capture_duration_seconds=300.0,
        capture_start_time=timezone.now() - timedelta(days=2),
    )
    pcap1.tags.add(Tag.objects.create(name="modbus"), Tag.objects.create(name="baseline"))

    pcap2 = user.pcaps.create(
        filename="http_traffic.pcap",
        event="DHS-Hunt",
        sector="Water Treatment",
        platform="Allen-Bradley",
        baseline=False,
        description="HTTP browsing session during hunt exercise",
        ot_protocols=["EtherNet/IP"],
        source_host="10.0.0.1",
        packet_count=150,
        capture_duration_seconds=30.0,
        capture_start_time=timezone.now() - timedelta(days=1),
    )
    pcap2.tags.add(Tag.objects.create(name="http"))
    return user


@pytest.fixture(autouse=True)
def authenticated_browser(client, search_data):
    client.force_login(search_data)


def body(response):
    return response.content.decode()


def test_browse_page_shows_all_pcaps(client, search_data):
    response = client.get("/pcaps")
    assert response.status_code == 200
    assert "modbus_baseline.pcap" in body(response)
    assert "http_traffic.pcap" in body(response)


def test_fulltext_search_finds_matching_pcaps(client, search_data):
    response = client.get("/pcaps", {"q": "industrial"})
    assert response.status_code == 200
    assert "modbus_baseline.pcap" in body(response)
    assert "http_traffic.pcap" not in body(response)


def test_sector_filter_narrows_results(client, search_data):
    response = client.get("/pcaps", {"sector": "Chemical"})
    assert response.status_code == 200
    assert "modbus_baseline.pcap" in body(response)
    assert "http_traffic.pcap" not in body(response)


def test_tag_filter_narrows_results(client, search_data):
    response = client.get("/pcaps", {"tags": "modbus"})
    assert response.status_code == 200
    assert "modbus_baseline.pcap" in body(response)
    assert "http_traffic.pcap" not in body(response)


def test_combined_filters_use_and_semantics(client, search_data):
    response = client.get("/pcaps", {"sector": "Chemical", "baseline": "yes"})
    assert response.status_code == 200
    assert "modbus_baseline.pcap" in body(response)
    assert "http_traffic.pcap" not in body(response)


def test_combined_filters_that_match_nothing_return_empty(client, search_data):
    response = client.get("/pcaps", {"sector": "Chemical", "baseline": "no"})
    assert response.status_code == 200
    assert "modbus_baseline.pcap" not in body(response)
    assert "http_traffic.pcap" not in body(response)


def test_event_substring_filter_works(client, search_data):
    response = client.get("/pcaps", {"event": "Hunt"})
    assert response.status_code == 200
    assert "modbus_baseline.pcap" not in body(response)
    assert "http_traffic.pcap" in body(response)


def test_api_multi_filter_search_matches_web_results(client, search_data, set_test_token):
    import json

    set_test_token(search_data, "search_token")

    response = client.get(
        "/api/v1/pcaps",
        {"sector": "Chemical", "tag": "modbus"},
        headers={"Authorization": "Bearer search_token"},
    )
    data = json.loads(response.content)
    assert len(data["data"]) == 1
    assert data["data"][0]["filename"] == "modbus_baseline.pcap"
