"""Template helpers ported from Rails: pagy's series_nav and number_to_human_size."""

import math

from django import template
from django.utils.html import format_html, format_html_join

register = template.Library()

GAP = None
SERIES_SLOTS = 7


def pagy_series(page, last, slots=SERIES_SLOTS):
    """Pagy's series algorithm: page numbers with gaps, current page as a string."""
    if slots >= last:
        series = list(range(1, last + 1))
    else:
        half = (slots - 1) // 2
        if page <= half:
            start = 1
        elif page > last - slots + half:
            start = last - slots + 1
        else:
            start = page - half
        series = list(range(start, start + slots))
        series[0] = 1
        if series[1] != 2:
            series[1] = GAP
        if series[-2] != last - 1:
            series[-2] = GAP
        series[-1] = last
    return [str(item) if item == page else item for item in series]


@register.simple_tag(takes_context=True)
def pagy_series_nav(context, page_obj):
    """Render pagination with the same markup as pagy 43's series_nav helper."""
    request = context["request"]
    page = page_obj.number
    last = page_obj.paginator.num_pages

    def page_url(number):
        params = request.GET.copy()
        params["page"] = number
        return f"{request.path}?{params.urlencode()}"

    previous_page = page - 1 if page > 1 else None
    next_page = page + 1 if page < last else None

    parts = []
    if previous_page:
        parts.append(
            format_html(
                '<a href="{}" rel="prev" aria-label="Previous">&lt;</a>',
                page_url(previous_page),
            )
        )
    else:
        parts.append(
            format_html('<a role="link" aria-disabled="true" aria-label="Previous">{}</a>', "<")
        )
    for item in pagy_series(page, last):
        if item is GAP:
            parts.append(format_html('<a role="separator" aria-disabled="true">{}</a>', "…"))
        elif isinstance(item, str):
            parts.append(
                format_html('<a role="link" aria-disabled="true" aria-current="page">{}</a>', item)
            )
        else:
            if item == previous_page:
                parts.append(format_html('<a href="{}" rel="prev">{}</a>', page_url(item), item))
            elif item == next_page:
                parts.append(format_html('<a href="{}" rel="next">{}</a>', page_url(item), item))
            else:
                parts.append(format_html('<a href="{}">{}</a>', page_url(item), item))
    if next_page:
        parts.append(
            format_html('<a href="{}" rel="next" aria-label="Next">&gt;</a>', page_url(next_page))
        )
    else:
        parts.append(
            format_html('<a role="link" aria-disabled="true" aria-label="Next">{}</a>', ">")
        )

    aria_label = "Page" if last == 1 else "Pages"
    links = format_html_join("", "{}", ((part,) for part in parts))
    return format_html('<nav class="pagy series-nav" aria-label="{}">{}</nav>', aria_label, links)


@register.filter
def get_param(querydict, key):
    """Dynamic-key lookup for request.GET in templates."""
    return querydict.get(key, "")


@register.filter
def human_size(value):
    """Rails number_to_human_size: binary units, 3 significant digits."""
    if value is None or value == "":
        return ""
    size = float(value)
    units = ["Bytes", "KB", "MB", "GB", "TB", "PB", "EB"]
    exponent = 0
    while size >= 1024 and exponent < len(units) - 1:
        size /= 1024.0
        exponent += 1
    if exponent == 0:
        count = int(size)
        unit = "Byte" if count == 1 else "Bytes"
        return f"{count} {unit}"
    digits = max(0, 2 - math.floor(math.log10(size))) if size > 0 else 0
    rounded = round(size, digits)
    text = f"{rounded:.{digits}f}".rstrip("0").rstrip(".") if digits else f"{rounded:.0f}"
    return f"{text} {units[exponent]}"
