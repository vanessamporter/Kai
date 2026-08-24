from unittest.mock import patch

import pytest
from django.core.files.base import ContentFile

from kai.analysis import enqueue, run_one
from kai.models import AnalysisJob
from kai.pcap_metadata import EMPTY_RESULT

pytestmark = pytest.mark.django_db


@patch("kai.analysis.pcap_metadata.extract")
def test_worker_processes_queued_capture(extract, user):
    result = {**EMPTY_RESULT, "packet_count": 4, "file_format": "pcap"}
    extract.return_value = result
    pcap = user.pcaps.create(filename="queued.pcap")
    pcap.file.save("queued.pcap", ContentFile(b"capture"))

    enqueue(pcap)
    assert run_one() is True

    pcap.refresh_from_db()
    job = AnalysisJob.objects.get(pcap=pcap)
    assert job.status == "complete"
    assert pcap.packet_count == 4


def test_worker_returns_false_when_queue_is_empty():
    assert run_one() is False
