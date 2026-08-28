from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.contrib.auth.hashers import check_password
from django.contrib.postgres.fields import ArrayField
from django.contrib.postgres.indexes import GinIndex, OpClass
from django.contrib.postgres.search import SearchQuery, SearchRank, SearchVector, SearchVectorField
from django.db import models
from django.db.models import Count, F
from django.db.models.signals import post_delete
from django.dispatch import receiver

# String columns use TextField to match the Rails schema, where `t.string` maps
# to unbounded varchar in PostgreSQL. Input length is controlled by the forms.


def _given(value):
    """Rails .present? semantics for filter bounds: 0 counts, blank strings don't."""
    return value is not None and str(value).strip() != ""


class UserManager(BaseUserManager):
    use_in_migrations = True

    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Email is required")
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_active", True)
        if not extra_fields["is_staff"]:
            raise ValueError("Administrator must have is_staff=True")
        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser):
    email = models.EmailField(unique=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    auth_source = models.CharField(max_length=20, default="local")
    api_token_digest = models.CharField(max_length=64, unique=True, null=True, blank=True)
    api_token_prefix = models.CharField(max_length=12, null=True, blank=True)
    api_token_created_at = models.DateTimeField(null=True, blank=True)
    api_token_expires_at = models.DateTimeField(null=True, blank=True)
    api_token_last_used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = UserManager()

    class Meta:
        db_table = "users"

    def _normalize(self):
        if self.email:
            self.email = self.email.strip().lower()

    def full_clean(self, *args, **kwargs):
        self._normalize()
        super().full_clean(*args, **kwargs)

    def save(self, *args, **kwargs):
        self._normalize()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.email

    def check_password(self, raw_password):
        encoded = self.password
        if encoded.startswith(("$2a$", "$2b$", "$2y$")):
            encoded = f"bcrypt${encoded}"

        def setter(password):
            self.set_password(password)
            self._password = None
            self.save(update_fields=["password", "updated_at"])

        return check_password(raw_password, encoded, setter)

    @property
    def has_api_token(self):
        return bool(self.api_token_digest)


class Tag(models.Model):
    name = models.TextField(unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "tags"
        indexes = [
            GinIndex(OpClass(F("name"), name="gin_trgm_ops"), name="index_tags_on_name_trgm"),
        ]

    def _normalize(self):
        if self.name:
            self.name = self.name.strip().lower()

    def full_clean(self, *args, **kwargs):
        self._normalize()
        super().full_clean(*args, **kwargs)

    def save(self, *args, **kwargs):
        self._normalize()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name


class PcapQuerySet(models.QuerySet):
    def search_fulltext(self, query):
        search = SearchQuery(query, config="english", search_type="plain")
        return (
            self.filter(search_vector=search)
            .annotate(rank=SearchRank(F("search_vector"), search))
            .order_by("-rank")
        )

    def with_tags(self, tag_names):
        if isinstance(tag_names, str):
            tag_names = [tag_names]
        names = [name.lower() for name in tag_names]
        return (
            self.filter(tags__name__in=names)
            .annotate(matching_tags=Count("tags", distinct=True))
            .filter(matching_tags=len(names))
        )

    def with_ot_protocols(self, protocols):
        return self.filter(ot_protocols__contains=list(protocols))

    def with_date_range(self, date_from, date_to):
        queryset = self
        if _given(date_from):
            queryset = queryset.filter(capture_start_time__gte=date_from)
        if _given(date_to):
            queryset = queryset.filter(capture_start_time__lte=date_to)
        return queryset

    def with_packet_count_range(self, minimum, maximum):
        queryset = self
        if _given(minimum):
            queryset = queryset.filter(packet_count__gte=minimum)
        if _given(maximum):
            queryset = queryset.filter(packet_count__lte=maximum)
        return queryset

    def with_duration_range(self, minimum, maximum):
        queryset = self
        if _given(minimum):
            queryset = queryset.filter(capture_duration_seconds__gte=minimum)
        if _given(maximum):
            queryset = queryset.filter(capture_duration_seconds__lte=maximum)
        return queryset

    def by_event(self, event):
        return self.filter(event__icontains=event)

    def by_uploader(self, email):
        return self.filter(user__email__icontains=email)

    def by_source_host(self, host):
        return self.filter(source_host__icontains=host)


SEARCH_VECTOR_FIELDS = (
    "filename",
    "description",
    "notes",
    "event",
    "source_host",
    "hmi",
    "plc",
    "sector",
)


class Pcap(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="pcaps")
    filename = models.TextField()
    file = models.FileField(upload_to="pcaps/%Y/%m/%d/", max_length=500, blank=True)

    # User-provided metadata
    description = models.TextField(null=True, blank=True)
    notes = models.TextField(null=True, blank=True)
    event = models.TextField(null=True, blank=True)
    sector = models.TextField(null=True, blank=True)
    platform = models.TextField(null=True, blank=True)
    location = models.TextField(null=True, blank=True)
    sponsor = models.TextField(null=True, blank=True)
    baseline = models.BooleanField(null=True, default=False)
    hmi = models.TextField(null=True, blank=True)
    plc = models.TextField(null=True, blank=True)
    ot_protocols = ArrayField(models.TextField(), null=True, blank=True, default=list)
    source_host = models.TextField(null=True, blank=True)
    network_interface = models.TextField(null=True, blank=True)

    # Auto-extracted metadata
    file_size = models.BigIntegerField(null=True, blank=True)
    sha256 = models.TextField(null=True, blank=True)
    packet_count = models.IntegerField(null=True, blank=True)
    capture_start_time = models.DateTimeField(null=True, blank=True)
    capture_end_time = models.DateTimeField(null=True, blank=True)
    capture_duration_seconds = models.FloatField(null=True, blank=True)
    file_format = models.TextField(null=True, blank=True)
    snaplen = models.IntegerField(null=True, blank=True)
    link_layer_type = models.TextField(null=True, blank=True)
    average_packet_size = models.FloatField(null=True, blank=True)
    data_rate_bytes_per_sec = models.FloatField(null=True, blank=True)
    tshark_analysis = models.JSONField(default=dict, blank=True)

    search_vector = models.GeneratedField(
        expression=SearchVector(*SEARCH_VECTOR_FIELDS, config="english"),
        output_field=SearchVectorField(),
        db_persist=True,
    )

    tags = models.ManyToManyField(Tag, through="PcapTag", related_name="pcaps", blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = PcapQuerySet.as_manager()

    class Meta:
        db_table = "pcaps"
        indexes = [
            GinIndex(fields=["search_vector"], name="index_pcaps_on_search_vector"),
            GinIndex(fields=["ot_protocols"], name="index_pcaps_on_ot_protocols"),
            GinIndex(OpClass(F("filename"), name="gin_trgm_ops"), name="index_pcaps_on_filename"),
            GinIndex(OpClass(F("event"), name="gin_trgm_ops"), name="index_pcaps_on_event"),
        ]

    def __str__(self):
        return self.filename

    @property
    def analysis_status(self):
        try:
            return self.analysis_job.status
        except AnalysisJob.DoesNotExist:
            return None


class PcapTag(models.Model):
    pcap = models.ForeignKey(Pcap, on_delete=models.CASCADE, related_name="pcap_tags")
    tag = models.ForeignKey(Tag, on_delete=models.CASCADE, related_name="pcap_tags")

    class Meta:
        db_table = "pcap_tags"
        constraints = [
            models.UniqueConstraint(fields=["pcap", "tag"], name="uniq_pcap_tags_pcap_tag"),
        ]


@receiver(post_delete, sender=Pcap)
def _delete_pcap_file(sender, instance, **kwargs):
    """Remove the stored file when a pcap is destroyed (ActiveStorage purge parity)."""
    if instance.file:
        instance.file.delete(save=False)


class LookupValueQuerySet(models.QuerySet):
    def for_category(self, category):
        return self.filter(category=category).order_by("position", "value")


class LookupValue(models.Model):
    category = models.TextField()
    value = models.TextField()
    position = models.IntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = LookupValueQuerySet.as_manager()

    class Meta:
        db_table = "lookup_values"
        constraints = [
            models.UniqueConstraint(
                fields=["category", "value"], name="uniq_lookup_category_value"
            ),
        ]
        indexes = [
            GinIndex(
                OpClass(F("value"), name="gin_trgm_ops"),
                name="idx_lookup_values_value_trgm",
            ),
        ]

    def __str__(self):
        return f"{self.category}: {self.value}"


class SecurityEvent(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    event = models.CharField(max_length=64)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    success = models.BooleanField(default=True)
    details = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "security_events"
        indexes = [models.Index(fields=["event", "created_at"], name="idx_security_event_time")]


class AuthFailure(models.Model):
    key = models.CharField(max_length=64, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        db_table = "auth_failures"


class AnalysisJob(models.Model):
    pcap = models.OneToOneField(Pcap, on_delete=models.CASCADE, related_name="analysis_job")
    status = models.CharField(max_length=16, default="pending", db_index=True)
    attempts = models.PositiveSmallIntegerField(default=0)
    error = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "analysis_jobs"
