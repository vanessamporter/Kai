"""JSON API under /api/v1."""

import json
import os
from functools import wraps

from django.conf import settings
from django.contrib.auth import authenticate
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.db.models import Max
from django.http import FileResponse, HttpResponse, JsonResponse, QueryDict
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt

from kai import pcap_metadata
from kai.analysis import enqueue
from kai.models import LookupValue, Pcap, Tag, User
from kai.security import (
    audit,
    clear_failures,
    rate_limited,
    record_failure,
    rotate_api_token,
    token_digest,
)
from kai.views.pcaps import (
    ALLOWED_EXTENSIONS,
    PER_PAGE,
    _sha256_of,
    _tag_objects,
    parse_time_param,
    present,
)

TAG_LIMIT = 20


def token_required(view):
    @wraps(view)
    def wrapper(request, *args, **kwargs):
        header = request.headers.get("Authorization") or ""
        token = header.removeprefix("Bearer ").strip()
        user = (
            User.objects.filter(api_token_digest=token_digest(token), is_active=True).first()
            if token
            else None
        )
        if (
            user is None
            or not user.api_token_expires_at
            or user.api_token_expires_at <= timezone.now()
        ):
            return JsonResponse({"error": "Unauthorized", "status": 401}, status=401)
        request.api_user = user
        user.api_token_last_used_at = timezone.now()
        user.save(update_fields=["api_token_last_used_at"])
        return view(request, *args, **kwargs)

    return wrapper


@csrf_exempt
def auth_token(request):
    params = _body_params(request)
    email = (params.get("email") or "").strip().lower()
    password = params.get("password") or ""
    if rate_limited("api_login", request, email):
        return JsonResponse({"error": "Too many attempts", "status": 429}, status=429)
    user = authenticate(request, username=email, password=password)
    if user is not None and user.is_active:
        clear_failures("api_login", request, email)
        token = rotate_api_token(user)
        audit(request, "api_token_issued", user=user)
        return JsonResponse(
            {"data": {"api_token": token, "expires_at": _json_time(user.api_token_expires_at)}}
        )
    record_failure("api_login", request, email)
    audit(request, "api_login", success=False, details={"email": email})
    return JsonResponse({"error": "Invalid email or password", "status": 401}, status=401)


@csrf_exempt
def pcaps_collection(request):
    if request.method == "POST":
        return token_required(pcaps_create)(request)
    return token_required(pcaps_index)(request)


@csrf_exempt
def pcaps_member(request, pk):
    if request.method in ("PATCH", "PUT"):
        return token_required(pcaps_update)(request, pk)
    if request.method == "DELETE":
        return token_required(pcaps_destroy)(request, pk)
    return token_required(pcaps_show)(request, pk)


def pcaps_index(request):
    params = request.GET
    pcaps = Pcap.objects.all()

    if present(params.get("q")):
        pcaps = pcaps.search_fulltext(params["q"])
    tag_names = _array_param(params, "tag")
    if tag_names:
        pcaps = pcaps.with_tags(tag_names)
    for field in ("sector", "platform", "location", "sponsor", "hmi", "plc"):
        if present(params.get(field)):
            pcaps = pcaps.filter(**{field: params[field]})
    protocols = _array_param(params, "ot_protocol")
    if protocols:
        pcaps = pcaps.with_ot_protocols(protocols)
    if present(params.get("baseline")):
        pcaps = pcaps.filter(baseline=params["baseline"] == "true")
    if present(params.get("event")):
        pcaps = pcaps.by_event(params["event"])
    if present(params.get("from")) or present(params.get("to")):
        pcaps = pcaps.with_date_range(
            parse_time_param(params.get("from")), parse_time_param(params.get("to"))
        )

    if not present(params.get("q")):
        pcaps = pcaps.order_by("-created_at")

    paginator = Paginator(
        pcaps.select_related("user", "analysis_job").prefetch_related("tags"), PER_PAGE
    )
    page_obj = paginator.get_page(params.get("page"))

    return JsonResponse(
        {
            "data": [pcap_json(pcap) for pcap in page_obj.object_list],
            "meta": {
                "page": page_obj.number,
                "total_pages": paginator.num_pages,
                "total_count": paginator.count,
            },
        }
    )


def pcaps_show(request, pk):
    pcap = _find_pcap(pk)
    if pcap is None:
        return _not_found()
    return JsonResponse({"data": pcap_json(pcap)})


def pcaps_create(request):
    upload = request.FILES.get("file")
    if upload is None:
        return JsonResponse({"error": "File is required", "status": 422}, status=422)
    if upload.size > settings.MAX_PCAP_UPLOAD_BYTES:
        return JsonResponse(
            {"error": "File exceeds the upload size limit", "status": 413}, status=413
        )

    extension = os.path.splitext(upload.name)[1].lower()
    if extension not in ALLOWED_EXTENSIONS:
        return JsonResponse({"error": "File must be .pcap or .pcapng", "status": 422}, status=422)
    if not pcap_metadata.valid_capture(upload):
        return JsonResponse(
            {"error": "File contents are not a valid pcap or pcapng capture", "status": 422},
            status=422,
        )

    pcap = Pcap(user=request.api_user)
    _apply_api_params(pcap, request.POST)
    pcap.filename = upload.name
    pcap.file_size = upload.size
    pcap.sha256 = _sha256_of(upload)

    tags = _tag_objects(",".join(_array_param(request.POST, "tags")))
    pcap.file = upload
    pcap.save()
    pcap.tags.set(tags)
    enqueue(pcap)

    return JsonResponse({"data": pcap_json(pcap)}, status=201)


def pcaps_update(request, pk):
    pcap = _find_pcap(pk)
    if pcap is None:
        return _not_found()
    if not request.api_user.is_staff and pcap.user_id != request.api_user.id:
        raise PermissionDenied
    params = _write_params(request)
    _apply_api_params(pcap, params)
    tags = _tag_objects(",".join(_array_param(params, "tags")))
    pcap.save()
    pcap.tags.set(tags)
    return JsonResponse({"data": pcap_json(pcap)})


def pcaps_destroy(request, pk):
    pcap = _find_pcap(pk)
    if pcap is None:
        return _not_found()
    if not request.api_user.is_staff and pcap.user_id != request.api_user.id:
        raise PermissionDenied
    pcap.delete()
    return HttpResponse(status=204)


@token_required
def pcaps_download(request, pk):
    pcap = _find_pcap(pk)
    if pcap is None:
        return _not_found()
    if pcap.file:
        audit(
            request,
            "pcap_download",
            user=request.api_user,
            details={
                "pcap_id": pcap.id,
                "filename": pcap.filename,
                "downloader_email": request.api_user.email,
                "source": "api",
            },
        )
        return FileResponse(
            pcap.file.open("rb"),
            as_attachment=True,
            filename=pcap.filename,
            content_type="application/vnd.tcpdump.pcap",
        )
    return JsonResponse({"error": "File not found", "status": 404}, status=404)


def tags_index(request):
    tags = Tag.objects.all()
    if present(request.GET.get("q")):
        tags = tags.filter(name__icontains=request.GET["q"])
    names = list(tags.order_by("name").values_list("name", flat=True)[:TAG_LIMIT])
    return JsonResponse({"data": names})


@csrf_exempt
def lookup_values_collection(request):
    if request.method == "POST":
        return token_required(lookup_values_create)(request)
    return lookup_values_index(request)


def lookup_values_index(request):
    values = LookupValue.objects.all()
    if present(request.GET.get("category")):
        values = values.filter(category=request.GET["category"])
    if present(request.GET.get("q")):
        values = values.filter(value__icontains=request.GET["q"])
    names = list(values.order_by("position", "value").values_list("value", flat=True))
    return JsonResponse({"data": names})


def lookup_values_create(request):
    if not request.api_user.is_staff:
        raise PermissionDenied
    params = _body_params(request)
    category = params.get("category")
    value = params.get("value")

    errors = []
    if not present(category):
        errors.append("Category can't be blank")
    if not present(value):
        errors.append("Value can't be blank")
    elif present(category) and LookupValue.objects.filter(category=category, value=value).exists():
        errors.append("Value has already been taken")
    if errors:
        return JsonResponse({"error": ", ".join(errors), "status": 422}, status=422)

    max_position = (
        LookupValue.objects.filter(category=category).aggregate(Max("position"))["position__max"]
        or 0
    )
    lookup_value = LookupValue.objects.create(
        category=category, value=value, position=max_position + 1
    )
    return JsonResponse(
        {"data": {"category": lookup_value.category, "value": lookup_value.value}}, status=201
    )


def pcap_json(pcap):
    return {
        "id": pcap.id,
        "filename": pcap.filename,
        "description": pcap.description,
        "notes": pcap.notes,
        "event": pcap.event,
        "sector": pcap.sector,
        "platform": pcap.platform,
        "location": pcap.location,
        "sponsor": pcap.sponsor,
        "baseline": pcap.baseline,
        "hmi": pcap.hmi,
        "plc": pcap.plc,
        "ot_protocols": pcap.ot_protocols or [],
        "source_host": pcap.source_host,
        "network_interface": pcap.network_interface,
        "file_size": pcap.file_size,
        "sha256": pcap.sha256,
        "packet_count": pcap.packet_count,
        "capture_start_time": _json_time(pcap.capture_start_time),
        "capture_end_time": _json_time(pcap.capture_end_time),
        "capture_duration_seconds": pcap.capture_duration_seconds,
        "file_format": pcap.file_format,
        "snaplen": pcap.snaplen,
        "link_layer_type": pcap.link_layer_type,
        "average_packet_size": pcap.average_packet_size,
        "data_rate_bytes_per_sec": pcap.data_rate_bytes_per_sec,
        "tshark_analysis": pcap.tshark_analysis or {},
        "analysis_status": pcap.analysis_status,
        "tags": list(pcap.tags.values_list("name", flat=True)),
        "uploader": pcap.user.email,
        "created_at": _json_time(pcap.created_at),
        "updated_at": _json_time(pcap.updated_at),
    }


def _json_time(value):
    """Rails-style ISO8601 with millisecond precision, e.g. 2026-08-16T15:00:00.000Z."""
    if value is None:
        return None
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"


def _find_pcap(pk):
    return Pcap.objects.filter(pk=pk).first()


def _not_found():
    return JsonResponse({"error": "Not found", "status": 404}, status=404)


def _array_param(params, key):
    """Rails Array(params[:key]) over query/form data: key, key[], or comma-joined."""
    if hasattr(params, "getlist"):
        values = params.getlist(key) + params.getlist(f"{key}[]")
    else:
        raw = params.get(key)
        values = raw if isinstance(raw, list) else ([raw] if raw is not None else [])
    return [part.strip() for value in values for part in str(value).split(",") if part.strip()]


def _body_params(request):
    """Parse POST bodies: JSON or form-encoded."""
    if request.content_type == "application/json":
        try:
            return json.loads(request.body)
        except ValueError:
            return {}
    return request.POST


def _write_params(request):
    """Parse PATCH/PUT bodies: JSON or form-encoded."""
    if request.content_type == "application/json":
        try:
            return json.loads(request.body)
        except ValueError:
            return {}
    if request.method == "POST":
        return request.POST
    return QueryDict(request.body)


API_FIELDS = (
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


def _apply_api_params(pcap, params):
    for field in API_FIELDS:
        if field in params:
            setattr(pcap, field, params[field])
    if "baseline" in params:
        pcap.baseline = str(params["baseline"]).lower() in ("1", "true")
    protocols = _array_param(params, "ot_protocols")
    if protocols or "ot_protocols" in params or "ot_protocols[]" in params:
        pcap.ot_protocols = protocols
