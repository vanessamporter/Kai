from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from kai import pcap_metadata
from kai.models import AnalysisJob, Pcap

MAX_ATTEMPTS = 3
STALE_AFTER = timedelta(minutes=5)
METADATA_FIELDS = tuple(pcap_metadata.EMPTY_RESULT)


def enqueue(pcap):
    AnalysisJob.objects.update_or_create(
        pcap=pcap, defaults={"status": "pending", "attempts": 0, "error": ""}
    )


def run_one():
    with transaction.atomic():
        stale = timezone.now() - STALE_AFTER
        job = (
            AnalysisJob.objects.select_for_update(skip_locked=True)
            .filter(status="pending")
            .order_by("created_at")
            .first()
        )
        if job is None:
            job = (
                AnalysisJob.objects.select_for_update(skip_locked=True)
                .filter(status="running", updated_at__lt=stale)
                .order_by("updated_at")
                .first()
            )
        if job is None:
            return False
        job.status = "running"
        job.attempts += 1
        job.error = ""
        job.save(update_fields=["status", "attempts", "error", "updated_at"])

    try:
        pcap = Pcap.objects.get(pk=job.pcap_id)
        result = pcap_metadata.extract(pcap.file.path)
        for field in METADATA_FIELDS:
            setattr(pcap, field, result[field])
        pcap.save(update_fields=[*METADATA_FIELDS, "updated_at"])
        job.status = "complete"
    except Exception as error:  # noqa: BLE001 - worker records and retries failures
        job.status = "pending" if job.attempts < MAX_ATTEMPTS else "failed"
        job.error = str(error)[:1000]
    job.save(update_fields=["status", "error", "updated_at"])
    return True
