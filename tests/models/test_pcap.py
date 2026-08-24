from datetime import timedelta

import pytest
from django.core.exceptions import ValidationError
from django.utils import timezone

from kai.models import Pcap, Tag

pytestmark = pytest.mark.django_db


@pytest.fixture
def user(make_user):
    return make_user(email="pcaptest@example.com")


def days_ago(days):
    return timezone.now() - timedelta(days=days)


def test_requires_filename(user):
    pcap = Pcap(user=user)
    with pytest.raises(ValidationError) as excinfo:
        pcap.full_clean()
    assert "filename" in excinfo.value.message_dict


def test_requires_user():
    pcap = Pcap(filename="test.pcap")
    with pytest.raises(ValidationError) as excinfo:
        pcap.full_clean()
    assert "user" in excinfo.value.message_dict


def test_has_many_tags_through_pcap_tags(user):
    pcap = user.pcaps.create(filename="test.pcap")
    tag = Tag.objects.create(name="dns")
    pcap.tags.add(tag)
    assert tag in pcap.tags.all()


def test_search_fulltext_finds_matching_records(user):
    user.pcaps.create(filename="modbus_traffic.pcap", description="Industrial control traffic")
    user.pcaps.create(filename="web_traffic.pcap", description="HTTP browsing session")

    results = Pcap.objects.search_fulltext("industrial")
    assert results.count() == 1
    assert results.first().filename == "modbus_traffic.pcap"


def test_with_tags_filters_by_tag_with_and_semantics(user):
    pcap1 = user.pcaps.create(filename="both.pcap")
    pcap2 = user.pcaps.create(filename="one.pcap")
    tag1 = Tag.objects.create(name="dns")
    tag2 = Tag.objects.create(name="http")
    pcap1.tags.add(tag1, tag2)
    pcap2.tags.add(tag1)

    results = list(Pcap.objects.with_tags(["dns", "http"]))
    assert len(results) == 1
    assert results[0].filename == "both.pcap"


def test_with_sector_filters_by_exact_match(user):
    user.pcaps.create(filename="chem.pcap", sector="Chemical")
    user.pcaps.create(filename="water.pcap", sector="Water Treatment")

    assert Pcap.objects.filter(sector="Chemical").count() == 1


def test_by_event_filters_by_substring(user):
    user.pcaps.create(filename="test.pcap", event="BaselineChemLSU")
    user.pcaps.create(filename="test2.pcap", event="DHS-Hunt")

    assert Pcap.objects.by_event("Chem").count() == 1


def test_with_ot_protocols_filters_by_array_containment(user):
    user.pcaps.create(filename="modbus.pcap", ot_protocols=["Modbus", "DNP3"])
    user.pcaps.create(filename="profinet.pcap", ot_protocols=["Profinet"])

    results = Pcap.objects.with_ot_protocols(["Modbus"])
    assert results.count() == 1
    assert results.first().filename == "modbus.pcap"


def test_with_baseline_filters_boolean(user):
    user.pcaps.create(filename="base.pcap", baseline=True)
    user.pcaps.create(filename="anomaly.pcap", baseline=False)

    assert Pcap.objects.filter(baseline=True).count() == 1
    assert Pcap.objects.filter(baseline=False).count() == 1


def test_with_date_range_filters_by_capture_start_time(user):
    user.pcaps.create(filename="old.pcap", capture_start_time=days_ago(365))
    user.pcaps.create(filename="recent.pcap", capture_start_time=days_ago(1))

    results = Pcap.objects.with_date_range(days_ago(7), timezone.now())
    assert results.count() == 1
    assert results.first().filename == "recent.pcap"


def test_with_platform_filters_by_exact_match(user):
    user.pcaps.create(filename="a.pcap", platform="Siemens S7")
    user.pcaps.create(filename="b.pcap", platform="Allen-Bradley")

    assert Pcap.objects.filter(platform="Siemens S7").count() == 1


def test_with_location_filters_by_exact_match(user):
    user.pcaps.create(filename="a.pcap", location="Lab A")
    user.pcaps.create(filename="b.pcap", location="Lab B")

    assert Pcap.objects.filter(location="Lab A").count() == 1


def test_with_sponsor_filters_by_exact_match(user):
    user.pcaps.create(filename="a.pcap", sponsor="DHS")
    user.pcaps.create(filename="b.pcap", sponsor="NSF")

    assert Pcap.objects.filter(sponsor="DHS").count() == 1


def test_with_hmi_filters_by_exact_match(user):
    user.pcaps.create(filename="a.pcap", hmi="FactoryTalk")
    user.pcaps.create(filename="b.pcap", hmi="WinCC")

    assert Pcap.objects.filter(hmi="FactoryTalk").count() == 1


def test_with_plc_filters_by_exact_match(user):
    user.pcaps.create(filename="a.pcap", plc="CompactLogix")
    user.pcaps.create(filename="b.pcap", plc="S7-1200")

    assert Pcap.objects.filter(plc="CompactLogix").count() == 1


def test_by_uploader_filters_by_user_email_substring(user, make_user):
    other = make_user(email="other@lab.org")
    user.pcaps.create(filename="a.pcap")
    other.pcaps.create(filename="b.pcap")

    results = Pcap.objects.by_uploader("other@lab")
    assert results.count() == 1
    assert results.first().filename == "b.pcap"


def test_by_source_host_filters_by_substring(user):
    user.pcaps.create(filename="a.pcap", source_host="192.168.1.10")
    user.pcaps.create(filename="b.pcap", source_host="10.0.0.1")

    assert Pcap.objects.by_source_host("192.168").count() == 1


def test_with_packet_count_range_filters_by_range(user):
    user.pcaps.create(filename="small.pcap", packet_count=100)
    user.pcaps.create(filename="large.pcap", packet_count=10000)

    results = Pcap.objects.with_packet_count_range(500, 20000)
    assert results.count() == 1
    assert results.first().filename == "large.pcap"


def test_with_duration_range_filters_by_range(user):
    user.pcaps.create(filename="short.pcap", capture_duration_seconds=5.0)
    user.pcaps.create(filename="long.pcap", capture_duration_seconds=3600.0)

    results = Pcap.objects.with_duration_range(60, 7200)
    assert results.count() == 1
    assert results.first().filename == "long.pcap"


def test_with_date_range_with_only_from_bound(user):
    user.pcaps.create(filename="old.pcap", capture_start_time=days_ago(365))
    user.pcaps.create(filename="recent.pcap", capture_start_time=days_ago(1))

    results = Pcap.objects.with_date_range(days_ago(7), None)
    assert results.count() == 1
    assert results.first().filename == "recent.pcap"


def test_with_date_range_with_only_to_bound(user):
    user.pcaps.create(filename="old.pcap", capture_start_time=days_ago(365))
    user.pcaps.create(filename="recent.pcap", capture_start_time=days_ago(1))

    results = Pcap.objects.with_date_range(None, days_ago(30))
    assert results.count() == 1
    assert results.first().filename == "old.pcap"


def test_with_packet_count_range_with_only_min_bound(user):
    user.pcaps.create(filename="small.pcap", packet_count=100)
    user.pcaps.create(filename="large.pcap", packet_count=10000)

    results = Pcap.objects.with_packet_count_range(500, None)
    assert results.count() == 1
    assert results.first().filename == "large.pcap"


def test_with_duration_range_with_only_max_bound(user):
    user.pcaps.create(filename="short.pcap", capture_duration_seconds=5.0)
    user.pcaps.create(filename="long.pcap", capture_duration_seconds=3600.0)

    results = Pcap.objects.with_duration_range(None, 60)
    assert results.count() == 1
    assert results.first().filename == "short.pcap"


def test_by_event_is_case_insensitive(user):
    user.pcaps.create(filename="test.pcap", event="BaselineChemLSU")

    assert Pcap.objects.by_event("baselinechem").count() == 1
    assert Pcap.objects.by_event("BASELINECHEM").count() == 1


def test_with_tags_accepts_a_single_string(user):
    pcap = user.pcaps.create(filename="tagged.pcap")
    tag = Tag.objects.create(name="single")
    pcap.tags.add(tag)

    assert len(Pcap.objects.with_tags("single")) == 1


def test_scopes_chain_with_and_semantics(user):
    user.pcaps.create(filename="match.pcap", sector="Chemical", baseline=True)
    user.pcaps.create(filename="sector_only.pcap", sector="Chemical", baseline=False)
    user.pcaps.create(filename="baseline_only.pcap", sector="Water Treatment", baseline=True)

    results = Pcap.objects.filter(sector="Chemical", baseline=True)
    assert results.count() == 1
    assert results.first().filename == "match.pcap"
