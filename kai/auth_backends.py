from django_auth_ldap.backend import LDAPBackend


class SecureLDAPBackend(LDAPBackend):
    """Mark provisioned LDAP users and prevent local password-reset fallback."""

    def authenticate(self, request, username=None, password=None, **kwargs):
        user = super().authenticate(request, username=username, password=password, **kwargs)
        if user and user.auth_source != "ldap":
            user.auth_source = "ldap"
            user.set_unusable_password()
            user.save(update_fields=["auth_source", "password", "updated_at"])
        return user
