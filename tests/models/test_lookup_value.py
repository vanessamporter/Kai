import pytest
from django.core.exceptions import ValidationError

from kai.models import LookupValue

pytestmark = pytest.mark.django_db


def test_requires_category():
    lookup_value = LookupValue(value="Test")
    with pytest.raises(ValidationError) as excinfo:
        lookup_value.full_clean()
    assert "category" in excinfo.value.message_dict


def test_requires_value():
    lookup_value = LookupValue(category="sector")
    with pytest.raises(ValidationError) as excinfo:
        lookup_value.full_clean()
    assert "value" in excinfo.value.message_dict


def test_requires_unique_value_within_category():
    LookupValue.objects.create(category="sector", value="Chemical")
    lookup_value = LookupValue(category="sector", value="Chemical")
    with pytest.raises(ValidationError):
        lookup_value.full_clean()


def test_allows_same_value_in_different_categories():
    LookupValue.objects.create(category="sector", value="Test")
    LookupValue(category="platform", value="Test").full_clean()  # raises if invalid


def test_for_category_scope_filters_and_orders():
    LookupValue.objects.create(category="sector", value="B", position=2)
    LookupValue.objects.create(category="sector", value="A", position=1)
    LookupValue.objects.create(category="platform", value="C", position=1)

    results = LookupValue.objects.for_category("sector")
    assert results.count() == 2
    assert results.first().value == "A"
