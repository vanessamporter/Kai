from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth import views as auth_views
from django.http import Http404, HttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.http import require_POST

from kai.models import User
from kai.security import audit, clear_failures, rate_limited, record_failure, revoke_api_token
from kai.views.helpers import validate_new_user


def login_view(request):
    if request.method == "POST":
        email = (request.POST.get("email") or "").strip().lower()
        if rate_limited("login", request, email):
            audit(request, "login_rate_limited", success=False, details={"email": email})
            return HttpResponse("Too many login attempts. Try again later.", status=429)
        password = request.POST.get("password") or ""
        user = authenticate(request, username=email, password=password)
        if user is not None and user.is_active:
            clear_failures("login", request, email)
            auth_login(request, user)
            audit(request, "login", user=user)
            messages.success(request, "Logged in successfully.")
            return redirect("/pcaps")
        record_failure("login", request, email)
        audit(request, "login", success=False, details={"email": email})
        messages.error(request, "Invalid email or password.")
        return render(request, "sessions/new.html", status=422)
    return render(request, "sessions/new.html")


@require_POST
def logout_view(request):
    user = request.user if request.user.is_authenticated else None
    audit(request, "logout", user=user)
    auth_logout(request)
    messages.success(request, "Logged out.")
    return redirect("/login")


def signup_view(request):
    if not settings.ALLOW_PUBLIC_SIGNUP:
        raise Http404
    if request.method == "POST":
        if rate_limited("signup", request):
            return HttpResponse("Too many signup attempts. Try again later.", status=429)
        email = request.POST.get("user[email]") or ""
        password = request.POST.get("user[password]") or ""
        confirmation = request.POST.get("user[password_confirmation]") or ""
        errors = validate_new_user(email, password, confirmation)
        if errors:
            record_failure("signup", request)
            audit(request, "signup", success=False, details={"email": email})
            return render(
                request, "registrations/new.html", {"errors": errors, "email": email}, status=422
            )
        user = User.objects.create_user(email=email, password=password)
        clear_failures("signup", request)
        auth_login(request, user)
        audit(request, "signup", user=user)
        messages.success(request, "Account created successfully.")
        return redirect("/pcaps")
    return render(request, "registrations/new.html")


class SecurePasswordResetView(auth_views.PasswordResetView):
    template_name = "password_resets/new.html"
    email_template_name = "password_resets/email.txt"
    subject_template_name = "password_resets/subject.txt"
    success_url = "/password_reset/done"

    def post(self, request, *args, **kwargs):
        email = (request.POST.get("email") or "").strip().lower()
        if rate_limited("password_reset", request, email):
            return HttpResponse("Too many reset requests. Try again later.", status=429)
        record_failure("password_reset", request, email)
        audit(request, "password_reset_requested", details={"email": email})
        return super().post(request, *args, **kwargs)


class SecurePasswordResetConfirmView(auth_views.PasswordResetConfirmView):
    template_name = "password_resets/confirm.html"
    success_url = "/password_reset/complete"

    def form_valid(self, form):
        user = form.user
        response = super().form_valid(form)
        revoke_api_token(user)
        audit(self.request, "password_reset_completed", user=user)
        return response
