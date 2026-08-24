import struct
from unittest.mock import Mock, patch

from django.core.files.uploadedfile import SimpleUploadedFile

from kai import pcap_metadata


def write_classic_pcap(path, packet_timestamps):
    """Minimal little-endian classic pcap with empty packets at given (sec, usec)."""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        f.writelines(struct.pack("<IIII", sec, usec, 0, 0) for sec, usec in packet_timestamps)


def write_le_pcapng(path, timestamps_usec):
    """Minimal little-endian pcapng: SHB + IDB (Ethernet, snaplen 65535) + EPBs."""
    with open(path, "wb") as f:
        f.write(struct.pack("<IIIHHqI", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28))
        f.write(struct.pack("<IIHHII", 1, 20, 1, 0, 65535, 20))
        for ts in timestamps_usec:
            f.write(struct.pack("<IIIIIII", 6, 32, 0, ts >> 32, ts & 0xFFFFFFFF, 0, 0))
            f.write(struct.pack("<I", 32))


def test_returns_empty_result_for_corrupt_file(tmp_path):
    path = tmp_path / "corrupt.pcap"
    path.write_text("this is not a pcap file at all")
    result = pcap_metadata.extract(path)
    assert result["packet_count"] is None
    assert result["capture_start_time"] is None
    assert result["file_format"] is None


def test_valid_capture_checks_binary_container():
    valid = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    assert pcap_metadata.valid_capture(SimpleUploadedFile("capture.pcap", valid)) is True
    assert (
        pcap_metadata.valid_capture(SimpleUploadedFile("spoofed.pcap", b"not a capture")) is False
    )
    malformed = struct.pack("<IIIHHqI", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 32)
    assert pcap_metadata.valid_capture(SimpleUploadedFile("broken.pcapng", malformed)) is False


def test_returns_empty_result_for_empty_file(tmp_path):
    path = tmp_path / "empty.pcap"
    path.write_bytes(b"")
    result = pcap_metadata.extract(path)
    # capinfos may report 0 or the fallback returns None; either is acceptable
    assert result["packet_count"] in (None, 0)


def test_returns_empty_result_for_truncated_pcap_header(tmp_path):
    path = tmp_path / "truncated.pcap"
    path.write_bytes(struct.pack("<I", 0xA1B2C3D4) + b"\x00" * 5)
    result = pcap_metadata.extract(path)
    assert result["packet_count"] is None


def test_fake_fixture_returns_result_with_expected_keys():
    # The Rails fixture is plain text named .pcap; the fallback must not raise
    fixture = "tests/fixtures/files/test.pcap"
    result = pcap_metadata._extract_from_headers(fixture)
    assert "packet_count" in result
    assert "file_format" in result
    assert "capture_start_time" in result


def test_never_raises_always_returns_dict():
    result = pcap_metadata.extract("/nonexistent/file.pcap")
    assert isinstance(result, dict)
    assert result["packet_count"] is None


def test_parses_classic_pcap_via_fallback(tmp_path):
    path = tmp_path / "classic.pcap"
    write_classic_pcap(path, [(1_700_000_000, 0), (1_700_000_005, 500_000)])
    result = pcap_metadata._extract_from_headers(path)
    assert result["packet_count"] == 2
    assert result["file_format"] == "pcap"
    assert result["snaplen"] == 65535
    assert result["link_layer_type"] == "Ethernet"
    assert result["capture_duration_seconds"] == 5.5
    assert result["capture_start_time"].year == 2023


def test_parses_little_endian_pcapng_via_fallback(tmp_path):
    # Regression for two Rails fallback bugs: the SHB length was read
    # big-endian (skipping LE files entirely) and snaplen was read from the
    # IDB reserved field.
    path = tmp_path / "capture.pcapng"
    base = 1_700_000_000 * 1_000_000
    write_le_pcapng(path, [base, base + 2_000_000])
    result = pcap_metadata._extract_from_headers(path)
    assert result["packet_count"] == 2
    assert result["file_format"] == "pcapng"
    assert result["snaplen"] == 65535
    assert result["link_layer_type"] == "Ethernet"
    assert result["capture_duration_seconds"] == 2.0


def test_capinfos_parses_real_pcap_when_available(tmp_path):
    if not pcap_metadata.CAPINFOS_AVAILABLE:
        return
    path = tmp_path / "real.pcap"
    write_classic_pcap(path, [(1_700_000_000, 0), (1_700_000_001, 0)])
    result = pcap_metadata.extract(path)
    assert result["packet_count"] == 2
    assert result["file_format"] == "pcap"


def test_summarizes_tshark_packet_fields():
    output = (
        "eth:ethertype:ip:tcp:http\t10.0.0.1\t\t10.0.0.2\t\t49152\t80\t\t\t\texample.test\n"
        "eth:ethertype:ip:udp:dns\t10.0.0.2\t\t8.8.8.8\t\t\t\t53000\t53\texample.test\t\n"
    )
    result = pcap_metadata._summarize_tshark_output(output, packet_count=200_000)

    assert result["analyzed_packets"] == 2
    assert result["truncated"] is True
    assert result["protocols"] == ["dns", "eth", "ethertype", "http", "ip", "tcp", "udp"]
    assert result["tcp_ports"] == [80, 49152]
    assert result["udp_ports"] == [53, 53000]
    assert result["dns_queries"] == ["example.test"]
    assert result["http_hosts"] == ["example.test"]
    assert result["endpoints"][0] == {"address": "10.0.0.2", "packets": 2}
    assert result["conversations"][0]["transport"] == "tcp"


@patch("kai.pcap_metadata.subprocess.run")
def test_tshark_failure_is_non_fatal(run):
    run.return_value = Mock(returncode=1, stdout="", stderr="bad capture")
    assert pcap_metadata._extract_with_tshark("bad.pcap") == {}
