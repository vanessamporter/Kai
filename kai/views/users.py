from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from kai.models import User
from kai.security import audit
from kai.views.helpers import staff_required, validate_new_user


@staff_required
def collection(request):
    if request.method == "POST":
        return create(request)
    users = User.objects.order_by("-created_at")
    return render(request, "users/index.html", {"users": users})


def create(request):
    email = request.POST.get("user[email]") or ""
    password = request.POST.get("user[password]") or ""
    confirmation = request.POST.get("user[password_confirmation]") or ""
    errors = validate_new_user(email, password, confirmation)
    if errors:
        for error in errors:
            messages.error(request, error)
        return redirect("/users")
    user = User.objects.create_user(
        email=email,
        password=password,
        is_active=True,
        is_staff=request.POST.get("user[is_staff]") == "1",
    )
    audit(request, "user_created_by_staff", user=user, details={"actor_id": request.user.id})
    messages.success(request, f"Account for {user.email} created.")
    return redirect("/users")


@staff_required
@require_POST
def approve(request, pk):
    user = get_object_or_404(User, pk=pk)
    if user.is_active:
        messages.success(request, f"{user.email} is already active.")
    else:
        user.is_active = True
        user.save(update_fields=["is_active", "updated_at"])
        audit(request, "user_approved", user=user, details={"actor_id": request.user.id})
        messages.success(request, f"{user.email} approved.")
    return redirect("/users")
