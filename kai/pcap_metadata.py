"""Bounded pcap metadata and Tshark extraction."""

import logging
import os
import re
import resource
import shutil
import struct
import subprocess  # nosec B404
import tempfile
from collections import Counter
from datetime import UTC, datetime, timedelta

logger = logging.getLogger(__name__)

CAPINFOS_PATH = shutil.which("capinfos")
TSHARK_PATH = shutil.which("tshark")
CAPINFOS_AVAILABLE = CAPINFOS_PATH is not None
TSHARK_AVAILABLE = TSHARK_PATH is not None
TSHARK_PACKET_LIMIT = 100_000
TSHARK_TIMEOUT_SECONDS = 60
TSHARK_LIST_LIMIT = 100
ANALYSIS_MEMORY_LIMIT_BYTES = 1_073_741_824
ANALYSIS_FILE_DESCRIPTOR_LIMIT = 64

EMPTY_RESULT = {
    "packet_count": None,
    "capture_start_time": None,
    "capture_end_time": None,
    "capture_duration_seconds": None,
    "file_format": None,
    "snaplen": None,
    "link_layer_type": None,
    "average_packet_size": None,
    "data_rate_bytes_per_sec": None,
    "tshark_analysis": {},
}

LINK_LAYER_NAMES = {
    0: "NULL/Loopback",
    1: "Ethernet",
    6: "Token Ring",
    9: "PPP",
    105: "IEEE 802.11 (WiFi)",
    113: "Linux cooked capture",
    228: "Raw IPv4",
    229: "Raw IPv6",
}

PCAPNG_TSRESOL = 1_000_000  # default microseconds

PCAP_MAGIC = {
    b"\xa1\xb2\xc3\xd4",
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x4d\x3c\xb2\xa1",
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
PCAPNG_BYTE_ORDER_MAGIC = {b"\x1a\x2b\x3c\x4d", b"\x4d\x3c\x2b\x1a"}


def valid_capture(upload):
    position = upload.tell()
    try:
        upload.seek(0)
        header = upload.read(28)
        if len(header) >= 24 and header[:4] in PCAP_MAGIC:
            big_endian_magic = {b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"}
            endian = ">" if header[:4] in big_endian_magic else "<"
            major, minor = struct.unpack(f"{endian}HH", header[4:8])
            snaplen = struct.unpack(f"{endian}I", header[16:20])[0]
            return major == 2 and minor <= 4 and snaplen > 0

        if len(header) < 28 or header[:4] != PCAPNG_MAGIC:
            return False
        byte_order = header[8:12]
        if byte_order not in PCAPNG_BYTE_ORDER_MAGIC:
            return False
        endian = "<" if byte_order == b"\x4d\x3c\x2b\x1a" else ">"
        block_length = struct.unpack(f"{endian}I", header[4:8])[0]
        major, minor = struct.unpack(f"{endian}HH", header[12:16])
        if block_length < 28 or block_length > 1_048_576 or block_length % 4:
            return False
        upload.seek(0)
        block = upload.read(block_length)
        closing_length = struct.unpack(f"{endian}I", block[-4:])[0] if len(block) >= 4 else 0
        return (
            len(block) == block_length
            and closing_length == block_length
            and (major, minor) == (1, 0)
        )
    finally:
        upload.seek(position)


def _limit_analysis_process():
    """Constrain damage if a native packet parser is compromised."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(
        resource.RLIMIT_AS, (ANALYSIS_MEMORY_LIMIT_BYTES, ANALYSIS_MEMORY_LIMIT_BYTES)
    )
    resource.setrlimit(
        resource.RLIMIT_NOFILE,
        (ANALYSIS_FILE_DESCRIPTOR_LIMIT, ANALYSIS_FILE_DESCRIPTOR_LIMIT),
    )
    cpu_limit = max(1, TSHARK_TIMEOUT_SECONDS - 5)
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit, cpu_limit))


def _analysis_process_options():
    return {
        "env": {"HOME": tempfile.gettempdir(), "LANG": "C.UTF-8", "PATH": os.defpath},
        "start_new_session": True,
        "preexec_fn": _limit_analysis_process,
    }


def extract(file_path):
    try:
        if CAPINFOS_AVAILABLE:
            result = _extract_with_capinfos(file_path)
        else:
            result = _extract_from_headers(file_path)
    except Exception as error:  # noqa: BLE001 - extraction is best-effort by design
        logger.error("PcapMetadataExtractor failed: %s", error)
        result = dict(EMPTY_RESULT)

    if TSHARK_AVAILABLE:
        try:
            result["tshark_analysis"] = _extract_with_tshark(file_path, result.get("packet_count"))
        except Exception as error:  # noqa: BLE001 - analysis is best-effort by design
            logger.error("tshark analysis failed: %s", error)
            result["tshark_analysis"] = {}
    return result


def _extract_with_tshark(file_path, packet_count=None):
    """Return a bounded, JSON-serializable summary of tshark packet fields."""
    command = [
        TSHARK_PATH,
        "-n",
        "-r",
        str(file_path),
        "-c",
        str(TSHARK_PACKET_LIMIT),
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=a",
        "-E",
        "aggregator=,",
    ]
    fields = (
        "frame.protocols",
        "ip.src",
        "ipv6.src",
        "ip.dst",
        "ipv6.dst",
        "tcp.srcport",
        "tcp.dstport",
        "udp.srcport",
        "udp.dstport",
        "dns.qry.name",
        "http.host",
    )
    for field in fields:
        command.extend(("-e", field))

    try:
        completed = subprocess.run(  # nosec B603
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=TSHARK_TIMEOUT_SECONDS,
            **_analysis_process_options(),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        logger.warning("tshark analysis failed: %s", error)
        return {}
    if completed.returncode != 0:
        logger.warning("tshark analysis failed: %s", completed.stderr.strip())
        return {}
    return _summarize_tshark_output(completed.stdout, packet_count)


def _summarize_tshark_output(output, packet_count=None):
    protocols = set()
    endpoints = Counter()
    tcp_ports = set()
    udp_ports = set()
    conversations = Counter()
    dns_queries = set()
    http_hosts = set()
    analyzed_packets = 0

    for line in output.splitlines():
        columns = (line.split("\t") + [""] * 11)[:11]
        (
            layers,
            ipv4_source,
            ipv6_source,
            ipv4_destination,
            ipv6_destination,
            tcp_source_port,
            tcp_destination_port,
            udp_source_port,
            udp_destination_port,
            dns_query,
            http_host,
        ) = columns
        analyzed_packets += 1
        protocols.update(layer for layer in layers.split(":") if layer)

        source = _last_value(ipv4_source or ipv6_source)
        destination = _last_value(ipv4_destination or ipv6_destination)
        if source:
            endpoints[source] += 1
        if destination:
            endpoints[destination] += 1

        if tcp_source_port or tcp_destination_port:
            transport = "tcp"
        elif udp_source_port or udp_destination_port:
            transport = "udp"
        else:
            transport = "ip"
        source_port = _last_value(tcp_source_port or udp_source_port)
        destination_port = _last_value(tcp_destination_port or udp_destination_port)
        _add_ports(tcp_ports, tcp_source_port, tcp_destination_port)
        _add_ports(udp_ports, udp_source_port, udp_destination_port)
        if source and destination:
            conversations[(source, destination, transport, source_port, destination_port)] += 1

        dns_queries.update(value for value in dns_query.split(",") if value)
        http_hosts.update(value for value in http_host.split(",") if value)

    return {
        "analyzed_packets": analyzed_packets,
        "truncated": packet_count is not None and packet_count > TSHARK_PACKET_LIMIT,
        "protocols": sorted(protocols),
        "endpoints": [
            {"address": address, "packets": count}
            for address, count in endpoints.most_common(TSHARK_LIST_LIMIT)
        ],
        "tcp_ports": sorted(tcp_ports),
        "udp_ports": sorted(udp_ports),
        "conversations": [
            {
                "source": key[0],
                "destination": key[1],
                "transport": key[2],
                "source_port": int(key[3]) if key[3] else None,
                "destination_port": int(key[4]) if key[4] else None,
                "packets": count,
            }
            for key, count in conversations.most_common(TSHARK_LIST_LIMIT)
        ],
        "dns_queries": sorted(dns_queries)[:TSHARK_LIST_LIMIT],
        "http_hosts": sorted(http_hosts)[:TSHARK_LIST_LIMIT],
    }


def _add_ports(target, *values):
    for value in values:
        for port in value.split(","):
            if port.isdigit():
                target.add(int(port))


def _last_value(value):
    return value.rsplit(",", 1)[-1] if value else ""


def _extract_with_capinfos(file_path):
    result = subprocess.run(  # nosec B603
        [CAPINFOS_PATH, "-M", "-T", str(file_path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=TSHARK_TIMEOUT_SECONDS,
        **_analysis_process_options(),
    )
    if result.returncode != 0 or not result.stdout.strip():
        return _extract_from_headers(file_path)

    lines = result.stdout.strip().split("\n")
    if len(lines) < 2:
        return _extract_from_headers(file_path)

    data = dict(zip(lines[0].split("\t"), lines[1].split("\t")))
    file_type = (data.get("File type") or "").lower()
    return {
        "packet_count": _to_int(data.get("Number of packets")),
        "capture_start_time": _parse_time(data.get("Start time")),
        "capture_end_time": _parse_time(data.get("End time")),
        "capture_duration_seconds": _to_float(data.get("Capture duration (seconds)")),
        "file_format": ("pcapng" if "pcapng" in file_type else "pcap") if file_type else None,
        "snaplen": _to_int(data.get("Snapshot length")),
        "link_layer_type": data.get("Data link type"),
        "average_packet_size": _to_float(data.get("Average packet size (bytes)")),
        "data_rate_bytes_per_sec": _to_float(data.get("Data byte rate (bytes/sec)")),
    }


def _extract_from_headers(file_path):
    with open(file_path, "rb") as f:
        magic = f.read(4)
        if len(magic) < 4:
            return dict(EMPTY_RESULT)

        magic_int = struct.unpack(">I", magic)[0]
        if magic_int == 0xA1B2C3D4:
            return _parse_pcap(f, ">")
        if magic_int == 0xD4C3B2A1:
            return _parse_pcap(f, "<")
        if magic_int == 0x0A0D0D0A:
            return _parse_pcapng(f)
        return dict(EMPTY_RESULT)


def _parse_pcap(f, endian):
    f.seek(0)
    header = f.read(24)
    if len(header) < 24:
        return dict(EMPTY_RESULT)

    _magic, _major, _minor, _thiszone, _sigfigs, snaplen, network = struct.unpack(
        f"{endian}4sHHIIII", header
    )

    packet_count = 0
    first_ts = None
    last_ts = None

    while True:
        pkt_header = f.read(16)
        if len(pkt_header) < 16:
            break
        ts_sec, ts_usec, incl_len, _orig_len = struct.unpack(f"{endian}IIII", pkt_header)
        ts = _time_at(ts_sec, ts_usec)
        if first_ts is None:
            first_ts = ts
        last_ts = ts
        packet_count += 1
        f.seek(incl_len, 1)

    return {
        **EMPTY_RESULT,
        "packet_count": packet_count,
        "capture_start_time": first_ts,
        "capture_end_time": last_ts,
        "capture_duration_seconds": _duration(first_ts, last_ts),
        "file_format": "pcap",
        "snaplen": snaplen,
        "link_layer_type": _link_layer_name(network),
    }


def _parse_pcapng(f):
    f.seek(0)
    shb = f.read(12)
    if len(shb) < 12:
        return dict(EMPTY_RESULT)

    byte_order_magic = struct.unpack(">I", shb[8:12])[0]
    if byte_order_magic == 0x1A2B3C4D:
        endian = ">"
    elif byte_order_magic == 0x4D3C2B1A:
        endian = "<"
    else:
        return dict(EMPTY_RESULT)

    # The Rails fallback read this length big-endian regardless of the detected
    # byte order, which skipped the entire file for little-endian captures.
    shb_length = struct.unpack(f"{endian}I", shb[4:8])[0]
    f.seek(shb_length)

    snaplen = None
    link_type = None
    packet_count = 0
    first_ts = None
    last_ts = None

    while True:
        block_header = f.read(8)
        if len(block_header) < 8:
            break
        btype, blen = struct.unpack(f"{endian}II", block_header)
        body_len = blen - 12  # subtract type(4) + length(4) + trailing length(4)
        if body_len < 0:
            break

        if btype == 1 and body_len >= 8:  # Interface Description Block
            idb = f.read(8)
            if len(idb) < 8:
                break
            # Fields: link type (u16), reserved (u16), snaplen (u32). The Rails
            # fallback took the reserved field as snaplen; fixed here.
            lt, _reserved, sl = struct.unpack(f"{endian}HHI", idb)
            if link_type is None:
                link_type = lt
            if snaplen is None:
                snaplen = sl
            remaining = body_len - 8
            if remaining > 0:
                f.seek(remaining, 1)
        elif btype == 6 and body_len >= 20:  # Enhanced Packet Block
            epb = f.read(20)
            if len(epb) < 20:
                break
            _iface_id, ts_high, ts_low, _cap_len, _orig_len = struct.unpack(f"{endian}IIIII", epb)
            timestamp = (ts_high << 32) | ts_low
            ts = _time_at(
                timestamp // PCAPNG_TSRESOL,
                (timestamp % PCAPNG_TSRESOL) * 1_000_000 // PCAPNG_TSRESOL,
            )
            if first_ts is None:
                first_ts = ts
            last_ts = ts
            packet_count += 1
            remaining = body_len - 20
            if remaining > 0:
                f.seek(remaining, 1)
        else:
            f.seek(body_len, 1)

        f.read(4)  # trailing block length

    return {
        **EMPTY_RESULT,
        "packet_count": packet_count,
        "capture_start_time": first_ts,
        "capture_end_time": last_ts,
        "capture_duration_seconds": _duration(first_ts, last_ts),
        "file_format": "pcapng",
        "snaplen": snaplen,
        "link_layer_type": _link_layer_name(link_type),
    }


def _time_at(seconds, microseconds):
    return datetime.fromtimestamp(seconds, tz=UTC) + timedelta(microseconds=microseconds)


def _duration(first_ts, last_ts):
    if first_ts is None or last_ts is None:
        return None
    return (last_ts - first_ts).total_seconds()


def _parse_time(value):
    if not value or not value.strip():
        return None
    match = re.match(r"(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.(\d+))?", value.strip())
    if not match:
        return None
    date_part, time_part, fraction = match.groups()
    microseconds = int((fraction or "0")[:6].ljust(6, "0"))
    parsed = datetime.fromisoformat(f"{date_part}T{time_part}")
    return parsed.replace(microsecond=microseconds, tzinfo=UTC)


def _link_layer_name(code):
    if code is None:
        return None
    return LINK_LAYER_NAMES.get(code, f"Unknown ({code})")


def _to_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _to_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
