import json

from django.db.models import Max
from django.http import JsonResponse

from kai.models import LookupValue
from kai.views.helpers import staff_required
from kai.views.pcaps import present


def collection(request):
    if request.method == "POST":
        return create(request)
    return index(request)


def index(request):
    values = LookupValue.objects.all()
    if present(request.GET.get("category")):
        values = values.filter(category=request.GET["category"])
    if present(request.GET.get("q")):
        values = values.filter(value__icontains=request.GET["q"])
    names = list(values.order_by("position", "value").values_list("value", flat=True))
    return JsonResponse(names, safe=False)


@staff_required
def create(request):
    params = _params(request)
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
        return JsonResponse({"error": ", ".join(errors)}, status=422)

    max_position = (
        LookupValue.objects.filter(category=category).aggregate(Max("position"))["position__max"]
        or 0
    )
    lookup_value = LookupValue.objects.create(
        category=category, value=value, position=max_position + 1
    )
    return JsonResponse({"value": lookup_value.value}, status=201)


def _params(request):
    if request.content_type == "application/json":
        try:
            return json.loads(request.body)
        except ValueError:
            return {}
    return request.POST
