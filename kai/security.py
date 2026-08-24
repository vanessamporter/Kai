import hashlib
import logging
import secrets
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from kai.models import AuthFailure, SecurityEvent

logger = logging.getLogger(__name__)


def client_ip(request):
    # REMOTE_ADDR is supplied by the trusted application server. Do not trust
    # X-Forwarded-For directly; the reverse proxy must normalize REMOTE_ADDR.
    value = request.META.get("REMOTE_ADDR")
    return value if value and len(value) <= 45 else None


def _rate_key(scope, request, identifier=""):
    raw = f"{scope}|{client_ip(request) or 'unknown'}|{identifier.strip().lower()}"
    return hashlib.sha256(raw.encode()).hexdigest()


def rate_limited(scope, request, identifier=""):
    cutoff = timezone.now() - timedelta(seconds=settings.AUTH_RATE_LIMIT_WINDOW_SECONDS)
    return (
        AuthFailure.objects.filter(
            key=_rate_key(scope, request, identifier), created_at__gte=cutoff
        ).count()
        >= settings.AUTH_RATE_LIMIT_ATTEMPTS
    )


def record_failure(scope, request, identifier=""):
    cutoff = timezone.now() - timedelta(seconds=settings.AUTH_RATE_LIMIT_WINDOW_SECONDS)
    AuthFailure.objects.filter(created_at__lt=cutoff).delete()
    AuthFailure.objects.create(key=_rate_key(scope, request, identifier))


def clear_failures(scope, request, identifier=""):
    AuthFailure.objects.filter(key=_rate_key(scope, request, identifier)).delete()


def audit(request, event, *, user=None, success=True, details=None):
    try:
        SecurityEvent.objects.create(
            user=user,
            event=event,
            ip_address=client_ip(request),
            success=success,
            details=details or {},
        )
    except Exception:
        logger.exception("Unable to record security event %s", event)


def token_digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def rotate_api_token(user):
    token = secrets.token_urlsafe(32)
    now = timezone.now()
    user.api_token_digest = token_digest(token)
    user.api_token_prefix = token[:8]
    user.api_token_created_at = now
    user.api_token_expires_at = now + timedelta(days=settings.API_TOKEN_TTL_DAYS)
    user.api_token_last_used_at = None
    user.save(
        update_fields=[
            "api_token_digest",
            "api_token_prefix",
            "api_token_created_at",
            "api_token_expires_at",
            "api_token_last_used_at",
            "updated_at",
        ]
    )
    return token


def revoke_api_token(user):
    user.api_token_digest = None
    user.api_token_prefix = None
    user.api_token_created_at = None
    user.api_token_expires_at = None
    user.api_token_last_used_at = None
    user.save(
        update_fields=[
            "api_token_digest",
            "api_token_prefix",
            "api_token_created_at",
            "api_token_expires_at",
            "api_token_last_used_at",
            "updated_at",
        ]
    )
