import hashlib
import os
from datetime import datetime, time

from django.conf import settings
from django.contrib import messages
from django.core.paginator import Paginator
from django.http import FileResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.dateparse import parse_date, parse_datetime

from kai import pcap_metadata
from kai.analysis import enqueue
from kai.models import LookupValue, Pcap, Tag
from kai.templatetags.kai_helpers import human_size
from kai.views.helpers import login_required, require_owner_or_staff

PER_PAGE = 25

LOOKUP_CATEGORIES = {
    "sectors": "sector",
    "platforms": "platform",
    "locations": "location",
    "sponsors": "sponsor",
    "hmis": "hmi",
    "plcs": "plc",
    "ot_protocols": "ot_protocol",
}

PCAP_FIELDS = (
    "description",
    "notes",
    "event",
    "sector",
    "platform",
    "location",
    "sponsor",
    "hmi",
    "plc",
    "source_host",
    "network_interface",
)

ALLOWED_EXTENSIONS = (".pcap", ".pcapng")


def present(value):
    return bool(value and str(value).strip())


def lookup_context():
    return {
        key: list(LookupValue.objects.for_category(category).values_list("value", flat=True))
        for key, category in LOOKUP_CATEGORIES.items()
    }


def parse_time_param(value):
    """Accept date or datetime strings; treat naive values as UTC like Rails."""
    if not present(value):
        return None
    parsed = parse_datetime(value)
    if parsed is None:
        date = parse_date(value)
        if date is None:
            return None
        parsed = datetime.combine(date, time.min)
    if timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed, timezone.utc)
    return parsed


def tag_names_param(params, key="tags"):
    """Rails accepts a comma-separated string or an array parameter."""
    values = params.getlist(key)
    if len(values) == 1:
        values = values[0].split(",")
    return [value.strip() for value in values if value.strip()]


def filtered_pcaps(params):
    """Compose search filters with AND semantics, mirroring PcapsController#index."""
    pcaps = Pcap.objects.all()

    if present(params.get("q")):
        pcaps = pcaps.search_fulltext(params["q"])

    if present(params.get("tags")):
        tag_names = tag_names_param(params)
        if tag_names:
            pcaps = pcaps.with_tags(tag_names)

    for field in ("sector", "platform", "location", "sponsor", "hmi", "plc"):
        if present(params.get(field)):
            pcaps = pcaps.filter(**{field: params[field]})

    if present(params.get("ot_protocols")):
        pcaps = pcaps.with_ot_protocols(params.getlist("ot_protocols"))

    if present(params.get("baseline")) and params["baseline"] != "either":
        pcaps = pcaps.filter(baseline=params["baseline"] == "yes")

    if present(params.get("event")):
        pcaps = pcaps.by_event(params["event"])
    if present(params.get("uploader")):
        pcaps = pcaps.by_uploader(params["uploader"])
    if present(params.get("source_host")):
        pcaps = pcaps.by_source_host(params["source_host"])
    if present(params.get("date_from")) or present(params.get("date_to")):
        pcaps = pcaps.with_date_range(
            parse_time_param(params.get("date_from")), parse_time_param(params.get("date_to"))
        )
    if present(params.get("packets_min")) or present(params.get("packets_max")):
        pcaps = pcaps.with_packet_count_range(params.get("packets_min"), params.get("packets_max"))
    if present(params.get("duration_min")) or present(params.get("duration_max")):
        pcaps = pcaps.with_duration_range(params.get("duration_min"), params.get("duration_max"))

    # Newest first unless full-text search provides ranking
    if not present(params.get("q")):
        pcaps = pcaps.order_by("-created_at")

    return pcaps


def collection(request):
    if request.method == "POST":
        return create(request)
    return index(request)


def member(request, pk):
    if request.method == "POST":
        if request.POST.get("_method") == "delete":
            return destroy(request, pk)
        return update(request, pk)
    return show(request, pk)


@login_required
def index(request):
    params = request.GET
    pcaps = filtered_pcaps(params).select_related("user", "analysis_job").prefetch_related("tags")

    paginator = Paginator(pcaps, PER_PAGE)
    page_obj = paginator.get_page(params.get("page"))

    has_filters = any(
        present(params.get(key)) for key in ("q", "sector", "platform", "tags", "event")
    ) or (present(params.get("baseline")) and params["baseline"] != "either")

    context = {
        "pcaps": page_obj.object_list,
        "page_obj": page_obj,
        "total_count": paginator.count,
        "has_filters": has_filters,
        "params": params,
        **lookup_context(),
    }
    return render(request, "pcaps/index.html", context)


@login_required
def show(request, pk):
    pcap = get_object_or_404(Pcap, pk=pk)

    metadata_pairs = _present_pairs(
        [
            ("Event", pcap.event),
            ("Description", pcap.description),
            ("Sector", pcap.sector),
            ("Location", pcap.location),
            ("HMI", pcap.hmi),
            ("PLC", pcap.plc),
            ("Baseline", "Yes" if pcap.baseline else "No"),
            ("Source Host", pcap.source_host),
            ("Network Iface", pcap.network_interface),
            ("Uploaded by", pcap.user.email),
        ]
    )
    capture_pairs = _present_pairs(
        [
            ("Packets", _maybe_str(pcap.packet_count)),
            ("Start Time", _format_time(pcap.capture_start_time)),
            ("End Time", _format_time(pcap.capture_end_time)),
            (
                "Duration",
                f"{round(pcap.capture_duration_seconds, 2)}s"
                if pcap.capture_duration_seconds is not None
                else None,
            ),
            ("Snap Length", _maybe_str(pcap.snaplen)),
            ("Link Layer", pcap.link_layer_type),
            (
                "Avg Pkt Size",
                f"{round(pcap.average_packet_size, 1)} bytes"
                if pcap.average_packet_size is not None
                else None,
            ),
            (
                "Data Rate",
                f"{human_size(pcap.data_rate_bytes_per_sec)}/s"
                if pcap.data_rate_bytes_per_sec is not None
                else None,
            ),
        ]
    )

    context = {
        "pcap": pcap,
        "metadata_pairs": metadata_pairs,
        "capture_pairs": capture_pairs,
        "has_capture_details": pcap.packet_count is not None,
        "analysis": pcap.tshark_analysis or {},
        "analysis_status": pcap.analysis_status,
    }
    return render(request, "pcaps/show.html", context)


@login_required
def new(request):
    return _render_form(request, "pcaps/new.html", Pcap(), [])


@login_required
def create(request):
    pcap = Pcap(user=request.user)
    _apply_pcap_params(pcap, request.POST)

    upload = request.FILES.get("pcap[file]")
    if upload is None:
        return _render_form(request, "pcaps/new.html", pcap, ["File must be attached"], status=422)

    if upload.size > settings.MAX_PCAP_UPLOAD_BYTES:
        return _render_form(
            request, "pcaps/new.html", pcap, ["File exceeds the upload size limit"], status=413
        )

    extension = os.path.splitext(upload.name)[1].lower()
    if extension not in ALLOWED_EXTENSIONS:
        return _render_form(
            request, "pcaps/new.html", pcap, ["File must be a .pcap or .pcapng file"], status=422
        )

    if not pcap_metadata.valid_capture(upload):
        return _render_form(
            request,
            "pcaps/new.html",
            pcap,
            ["File contents are not a valid pcap or pcapng capture"],
            status=422,
        )

    pcap.filename = upload.name
    pcap.file_size = upload.size
    pcap.sha256 = _sha256_of(upload)

    if Pcap.objects.filter(sha256=pcap.sha256).exists():
        messages.error(request, "A file with the same SHA-256 hash already exists.")

    tags = _tag_objects(request.POST.get("pcap[tag_list]"))
    pcap.file = upload
    pcap.save()
    pcap.tags.set(tags)
    enqueue(pcap)

    messages.success(request, "Pcap uploaded successfully.")
    return redirect(f"/pcaps/{pcap.id}")


@login_required
def edit(request, pk):
    pcap = get_object_or_404(Pcap, pk=pk)
    require_owner_or_staff(request.user, pcap)
    tag_list = ",".join(pcap.tags.values_list("name", flat=True))
    return _render_form(request, "pcaps/edit.html", pcap, [], tag_list=tag_list)


@login_required
def update(request, pk):
    pcap = get_object_or_404(Pcap, pk=pk)
    require_owner_or_staff(request.user, pcap)
    _apply_pcap_params(pcap, request.POST)
    tags = _tag_objects(request.POST.get("pcap[tag_list]"))
    pcap.save()
    pcap.tags.set(tags)
    messages.success(request, "Pcap updated successfully.")
    return redirect(f"/pcaps/{pcap.id}")


@login_required
def destroy(request, pk):
    pcap = get_object_or_404(Pcap, pk=pk)
    require_owner_or_staff(request.user, pcap)
    pcap.delete()
    messages.success(request, "Pcap deleted.")
    return redirect("/pcaps")


@login_required
def download(request, pk):
    pcap = get_object_or_404(Pcap, pk=pk)
    if pcap.file:
        return FileResponse(
            pcap.file.open("rb"),
            as_attachment=True,
            filename=pcap.filename,
            content_type="application/vnd.tcpdump.pcap",
        )
    messages.error(request, "File not found.")
    return redirect(f"/pcaps/{pcap.id}")


def _render_form(request, template, pcap, errors, status=200, tag_list=""):
    context = {
        "pcap": pcap,
        "errors": errors,
        "tag_list": tag_list,
        **lookup_context(),
    }
    return render(request, template, context, status=status)


def _apply_pcap_params(pcap, post):
    for field in PCAP_FIELDS:
        key = f"pcap[{field}]"
        if key in post:
            setattr(pcap, field, post[key])
    if "pcap[baseline]" in post:
        pcap.baseline = post["pcap[baseline]"] == "1"
    if "pcap[ot_protocols][]" in post:
        pcap.ot_protocols = [v for v in post.getlist("pcap[ot_protocols][]") if v.strip()]


def _tag_objects(tag_list):
    names = [name.strip() for name in (tag_list or "").split(",") if name.strip()]
    tags = []
    for name in names:
        tag, _created = Tag.objects.get_or_create(name=name.lower())
        if tag not in tags:
            tags.append(tag)
    return tags


def _sha256_of(upload):
    digest = hashlib.sha256()
    for chunk in upload.chunks():
        digest.update(chunk)
    upload.seek(0)
    return digest.hexdigest()


def _present_pairs(pairs):
    return [(label, value) for label, value in pairs if value is not None and str(value).strip()]


def _maybe_str(value):
    return str(value) if value is not None else None


def _format_time(value):
    return value.strftime("%Y-%m-%d %H:%M:%S UTC") if value else None
