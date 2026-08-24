from django.urls import path
from django.views.generic import RedirectView

from kai.views import api, auth, lookup_values, misc, pcaps, profiles, tags

urlpatterns = [
    path("up", misc.health, name="health"),
    path("LICENSE", misc.license_text, name="license"),
    # Pcaps (web mutations POST to the resource URL with a _method field,
    # mirroring the Rails form markup; the JSON API keeps true HTTP verbs)
    path("pcaps", pcaps.collection, name="pcaps"),
    path("pcaps/new", pcaps.new, name="new_pcap"),
    path("pcaps/<int:pk>", pcaps.member, name="pcap"),
    path("pcaps/<int:pk>/edit", pcaps.edit, name="edit_pcap"),
    path("pcaps/<int:pk>/download", pcaps.download, name="download_pcap"),
    # Tags (HTML management + JSON autocomplete)
    path("tags", tags.collection, name="tags"),
    path("tags.json", tags.index_json),
    path("tags/<int:pk>", tags.member, name="tag"),
    path("lookup_values", lookup_values.collection, name="lookup_values"),
    # API documentation
    path("api/docs", misc.api_docs, name="api_docs"),
    # JSON API
    path("api/v1/auth/token", api.auth_token),
    path("api/v1/pcaps", api.pcaps_collection),
    path("api/v1/pcaps/<int:pk>", api.pcaps_member),
    path("api/v1/pcaps/<int:pk>/download", api.pcaps_download),
    path("api/v1/tags", api.tags_index),
    path("api/v1/lookup_values", api.lookup_values_collection),
    # Auth
    path("signup", auth.signup_view, name="signup"),
    path("login", auth.login_view, name="login"),
    path("logout", auth.logout_view, name="logout"),
    path("password_reset", auth.SecurePasswordResetView.as_view(), name="password_reset"),
    path(
        "password_reset/done",
        auth.auth_views.PasswordResetDoneView.as_view(template_name="password_resets/done.html"),
        name="password_reset_done",
    ),
    path(
        "password_reset/<uidb64>/<token>",
        auth.SecurePasswordResetConfirmView.as_view(),
        name="password_reset_confirm",
    ),
    path(
        "password_reset/complete",
        auth.auth_views.PasswordResetCompleteView.as_view(
            template_name="password_resets/complete.html"
        ),
        name="password_reset_complete",
    ),
    # User profile
    path("profile", profiles.show, name="profile"),
    path("profile/regenerate_token", profiles.regenerate_token, name="regenerate_token"),
    path("profile/revoke_token", profiles.revoke_token, name="revoke_token"),
    # Root
    path("", RedirectView.as_view(url="/pcaps"), name="root"),
]
