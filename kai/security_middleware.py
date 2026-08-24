import secrets

from django.conf import settings


class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.csp_nonce = secrets.token_urlsafe(18)
        response = self.get_response(request)
        nonce = request.csp_nonce
        response.headers["Content-Security-Policy"] = "; ".join(
            (
                "default-src 'self'",
                f"script-src 'self' 'nonce-{nonce}'",
                "style-src 'self' 'unsafe-inline'",
                "img-src 'self' data:",
                "font-src 'self'",
                "connect-src 'self'",
                "object-src 'none'",
                "base-uri 'self'",
                "form-action 'self'",
                "frame-ancestors 'none'",
            )
        )
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        )
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        return response


def csp_nonce(request):
    return {
        "csp_nonce": getattr(request, "csp_nonce", ""),
        "allow_public_signup": settings.ALLOW_PUBLIC_SIGNUP,
        "source_code_url": settings.SOURCE_CODE_URL,
    }
