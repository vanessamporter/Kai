from functools import wraps

from django.contrib import messages
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.validators import validate_email
from django.shortcuts import redirect

from kai.models import User


def login_required(view):
    """Port of the Rails require_login before_action."""

    @wraps(view)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            messages.error(request, "You must be logged in to access this page.")
            return redirect("/login")
        return view(request, *args, **kwargs)

    return wrapper


def staff_required(view):
    @wraps(view)
    @login_required
    def wrapper(request, *args, **kwargs):
        if not request.user.is_staff:
            raise PermissionDenied
        return view(request, *args, **kwargs)

    return wrapper


def require_owner_or_staff(user, pcap):
    if not user.is_staff and pcap.user_id != user.id:
        raise PermissionDenied


def validate_password_fields(password, password_confirmation):
    """Password rules from has_secure_password, with Rails-style messages."""
    errors = []
    if not password:
        errors.append("Password can't be blank")
    elif len(password.encode("utf-8")) > 72:
        errors.append("Password is too long (maximum is 72 characters)")
    if password != password_confirmation:
        errors.append("Password confirmation doesn't match Password")
    return errors


def validate_new_user(email, password, password_confirmation):
    """User model validations with Rails-style messages."""
    errors = []
    email = (email or "").strip().lower()
    if not email:
        errors.append("Email can't be blank")
    else:
        try:
            validate_email(email)
        except ValidationError:
            errors.append("Email is invalid")
        if User.objects.filter(email=email).exists():
            errors.append("Email has already been taken")
    errors.extend(validate_password_fields(password, password_confirmation))
    if password and password == password_confirmation:
        try:
            validate_password(password, User(email=email))
        except ValidationError as error:
            errors.extend(error.messages)
    return errors
