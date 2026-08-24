from django.conf import settings
from django.http import HttpResponse
from django.shortcuts import render


def api_docs(request):
    return render(request, "api_docs/index.html")


def license_text(request):
    return HttpResponse(
        (settings.BASE_DIR / "LICENSE").read_text(), content_type="text/plain; charset=utf-8"
    )


def health(request):
    """Health check endpoint, same contract as the Rails /up route."""
    return HttpResponse('<!DOCTYPE html><html><body style="background-color: green"></body></html>')
