import os

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.core.validators import validate_email
from django.db import transaction

from kai.models import User


class Command(BaseCommand):
    help = "Create or activate the administrator configured for initial deployment"

    @transaction.atomic
    def handle(self, *args, **options):
        email = os.environ.get("KAI_INITIAL_ADMIN_EMAIL", "").strip().lower()
        password = os.environ.get("KAI_INITIAL_ADMIN_PASSWORD", "")
        if not email and not password:
            return
        if not email or not password:
            raise CommandError(
                "KAI_INITIAL_ADMIN_EMAIL and KAI_INITIAL_ADMIN_PASSWORD must both be set"
            )
        try:
            validate_email(email)
        except ValidationError as error:
            raise CommandError("KAI_INITIAL_ADMIN_EMAIL is invalid") from error

        user = User.objects.filter(email=email).first()
        if user:
            changed = []
            if not user.is_active:
                user.is_active = True
                changed.append("is_active")
            if not user.is_staff:
                user.is_staff = True
                changed.append("is_staff")
            if changed:
                user.save(update_fields=[*changed, "updated_at"])
                self.stdout.write(self.style.SUCCESS(f"Activated administrator {email}"))
            return

        try:
            validate_password(password, User(email=email))
        except ValidationError as error:
            raise CommandError(
                "Initial administrator password: " + "; ".join(error.messages)
            ) from error
        User.objects.create_superuser(email=email, password=password)
        self.stdout.write(self.style.SUCCESS(f"Created administrator {email}"))
