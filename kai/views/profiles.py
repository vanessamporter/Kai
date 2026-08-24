from django.contrib import messages
from django.shortcuts import redirect, render
from django.views.decorators.http import require_POST

from kai.security import audit, revoke_api_token, rotate_api_token
from kai.views.helpers import login_required


@login_required
def show(request):
    return render(
        request, "profiles/show.html", {"new_api_token": request.session.pop("new_api_token", None)}
    )


@login_required
@require_POST
def regenerate_token(request):
    request.session["new_api_token"] = rotate_api_token(request.user)
    audit(request, "api_token_rotated", user=request.user)
    messages.success(request, "API token generated. Copy it now; it will not be shown again.")
    return redirect("/profile")


@login_required
@require_POST
def revoke_token(request):
    revoke_api_token(request.user)
    audit(request, "api_token_revoked", user=request.user)
    messages.success(request, "API token revoked.")
    return redirect("/profile")
