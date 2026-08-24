import pytest
from django.core.exceptions import ValidationError

from kai.models import Tag

pytestmark = pytest.mark.django_db


def test_requires_name():
    tag = Tag()
    with pytest.raises(ValidationError) as excinfo:
        tag.full_clean()
    assert "name" in excinfo.value.message_dict


def test_normalizes_name_to_lowercase():
    tag = Tag.objects.create(name="DNS Traffic")
    assert tag.name == "dns traffic"


def test_requires_unique_name():
    Tag.objects.create(name="dns")
    tag = Tag(name="dns")
    with pytest.raises(ValidationError) as excinfo:
        tag.full_clean()
    assert "name" in excinfo.value.message_dict


def test_uniqueness_is_case_insensitive_via_normalization():
    Tag.objects.create(name="DNS")
    tag = Tag(name="dns")
    with pytest.raises(ValidationError):
        tag.full_clean()


def test_handles_special_characters_in_name():
    tag = Tag.objects.create(name="iec-61850/goose")
    assert tag.name == "iec-61850/goose"


def test_strips_whitespace_from_name():
    tag = Tag.objects.create(name="  modbus  ")
    assert tag.name == "modbus"


def test_concurrent_creation_with_same_name_is_handled_gracefully():
    Tag.objects.create(name="duplicate")
    tag = Tag(name="duplicate")
    with pytest.raises(ValidationError) as excinfo:
        tag.full_clean()
    assert "name" in excinfo.value.message_dict
