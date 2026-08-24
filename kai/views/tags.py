from django.contrib import messages
from django.db.models import Count
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from kai.models import Tag
from kai.views.helpers import staff_required
from kai.views.pcaps import present

AUTOCOMPLETE_LIMIT = 20


def collection(request):
    if request.method == "POST":
        return create(request)
    if "application/json" in request.headers.get("Accept", ""):
        return index_json(request)
    return index_html(request)


def index_html(request):
    tags = Tag.objects.annotate(pcaps_count=Count("pcap_tags")).order_by("name")
    return render(request, "tags/index.html", {"tags": tags})


def index_json(request):
    base = Tag.objects.all()
    if present(request.GET.get("q")):
        base = base.filter(name__icontains=request.GET["q"])
    total = base.count()
    names = list(
        base.annotate(usage=Count("pcap_tags"))
        .order_by("-usage", "name")
        .values_list("name", flat=True)[:AUTOCOMPLETE_LIMIT]
    )
    return JsonResponse({"tags": names, "total": total})


@staff_required
def create(request):
    errors, normalized = _tag_errors(request.POST.get("tag[name]"))
    if errors:
        messages.error(request, ", ".join(errors))
    else:
        Tag.objects.create(name=normalized)
        messages.success(request, f"Tag '{normalized}' created.")
    return redirect("/tags")


@staff_required
@require_POST
def member(request, pk):
    tag = get_object_or_404(Tag, pk=pk)
    if request.POST.get("_method") == "delete":
        return _destroy(request, tag)
    return _update(request, tag)


def _update(request, tag):
    errors, normalized = _tag_errors(request.POST.get("tag[name]"), exclude_pk=tag.pk)
    if errors:
        messages.error(request, ", ".join(errors))
    else:
        tag.name = normalized
        tag.save()
        messages.success(request, f"Tag renamed to '{normalized}'.")
    return redirect("/tags")


def _destroy(request, tag):
    name = tag.name
    tag.delete()
    messages.success(request, f"Tag '{name}' deleted.")
    return redirect("/tags")


def _tag_errors(name, exclude_pk=None):
    """Tag validations with Rails-style messages; returns (errors, normalized name)."""
    normalized = (name or "").strip().lower()
    if not normalized:
        return ["Name can't be blank"], normalized
    existing = Tag.objects.filter(name=normalized)
    if exclude_pk is not None:
        existing = existing.exclude(pk=exclude_pk)
    if existing.exists():
        return ["Name has already been taken"], normalized
    return [], normalized
