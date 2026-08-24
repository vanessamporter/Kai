from kai.templatetags.kai_helpers import GAP, human_size, pagy_series


def test_pagy_series_fits_in_slots():
    assert pagy_series(1, 5) == ["1", 2, 3, 4, 5]
    assert pagy_series(3, 5) == [1, 2, "3", 4, 5]


def test_pagy_series_first_half():
    assert pagy_series(1, 20) == ["1", 2, 3, 4, 5, GAP, 20]


def test_pagy_series_middle_has_gaps_on_both_sides():
    # Gaps replace edge slots; the series always holds exactly `slots` items
    assert pagy_series(10, 20) == [1, GAP, 9, "10", 11, GAP, 20]


def test_pagy_series_last_half():
    assert pagy_series(20, 20) == [1, GAP, 16, 17, 18, 19, "20"]


def test_pagy_series_no_gap_when_adjacent():
    # series[1] stays 2 when contiguous with the first page; the right side gaps
    assert pagy_series(4, 8) == [1, 2, 3, "4", 5, GAP, 8]
    assert pagy_series(4, 7) == [1, 2, 3, "4", 5, 6, 7]


def test_human_size_matches_rails_number_to_human_size():
    assert human_size(None) == ""
    assert human_size(123) == "123 Bytes"
    assert human_size(1) == "1 Byte"
    assert human_size(5000) == "4.88 KB"
    assert human_size(1048576) == "1 MB"
    assert human_size(1234567) == "1.18 MB"
    assert human_size(483989) == "473 KB"
    assert human_size(3145728) == "3 MB"
