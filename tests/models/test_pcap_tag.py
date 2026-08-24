import pytest
from django.core.exceptions import ValidationError

from kai.models import PcapTag, Tag

pytestmark = pytest.mark.django_db


@pytest.fixture
def pcap(make_user):
    user = make_user(email="pcaptag@example.com")
    return user.pcaps.create(filename="test.pcap")


@pytest.fixture
def tag(db):
    return Tag.objects.create(name="modbus")


def test_requires_pcap(tag):
    pcap_tag = PcapTag(tag=tag)
    with pytest.raises(ValidationError) as excinfo:
        pcap_tag.full_clean()
    assert "pcap" in excinfo.value.message_dict


def test_requires_tag(pcap):
    pcap_tag = PcapTag(pcap=pcap)
    with pytest.raises(ValidationError) as excinfo:
        pcap_tag.full_clean()
    assert "tag" in excinfo.value.message_dict


def test_prevents_duplicate_tag_on_same_pcap(pcap, tag):
    PcapTag.objects.create(pcap=pcap, tag=tag)
    duplicate = PcapTag(pcap=pcap, tag=tag)
    with pytest.raises(ValidationError):
        duplicate.full_clean()


def test_allows_same_tag_on_different_pcaps(pcap, tag):
    other_pcap = pcap.user.pcaps.create(filename="other.pcap")
    PcapTag.objects.create(pcap=pcap, tag=tag)
    PcapTag(pcap=other_pcap, tag=tag).full_clean()  # raises if invalid


def test_destroyed_when_pcap_is_destroyed(pcap, tag):
    pcap.tags.add(tag)
    pcap.delete()
    assert PcapTag.objects.count() == 0


def test_destroyed_when_tag_is_destroyed(pcap, tag):
    pcap.tags.add(tag)
    tag.delete()
    assert PcapTag.objects.count() == 0
