import time

from django.core.management.base import BaseCommand

from kai.analysis import run_one


class Command(BaseCommand):
    help = "Process queued pcap analysis jobs"

    def add_arguments(self, parser):
        parser.add_argument("--once", action="store_true")
        parser.add_argument("--poll", type=float, default=2)

    def handle(self, *args, **options):
        while True:
            worked = run_one()
            if options["once"]:
                return
            if not worked:
                time.sleep(options["poll"])
