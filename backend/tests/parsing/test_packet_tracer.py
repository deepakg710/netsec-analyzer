"""
Unit tests for Packet Tracer (.pkt) format inspector and ingestion engine.
Verifies honest status assignment, archive extraction, stream carving, and defensible reporting.
"""

import io
import zipfile
import pytest
from app.ingestion.packet_tracer import PacketTracerInspector, PTImportStatus


def test_empty_pkt_file():
    inspector = PacketTracerInspector("empty.pkt")
    report = inspector.inspect_and_parse(b"")
    assert report.status == PTImportStatus.FAILED
    assert "empty" in report.summary.lower()


def test_plaintext_cisco_config_with_pkt_extension():
    cfg = (
        "hostname TestRouter\n"
        "interface GigabitEthernet0/0\n"
        " ip address 10.0.0.1 255.255.255.0\n"
        " no shutdown\n"
    ).encode("utf-8")

    inspector = PacketTracerInspector("router_export.pkt")
    report = inspector.inspect_and_parse(cfg)
    assert report.status == PTImportStatus.FULLY_PARSED
    assert len(report.extracted_devices) == 1
    assert report.extracted_devices[0].hostname == "TestRouter"


def test_pkz_zip_container_extraction():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(
            "switch1.cfg",
            "hostname Switch1\ninterface FastEthernet0/1\n switchport access vlan 10\n"
        )
    zip_bytes = buf.getvalue()

    inspector = PacketTracerInspector("topology.pkz")
    report = inspector.inspect_and_parse(zip_bytes)
    assert report.status == PTImportStatus.PARTIALLY_PARSED
    assert len(report.extracted_devices) == 1
    assert report.extracted_devices[0].hostname == "Switch1"


def test_proprietary_encrypted_pkt_detection():
    # Simulate binary payload with no recoverable ASCII configuration blocks
    fake_encrypted_pkt = b"\x00\x01PT\x99\x88\x77\x66" + (b"\xaa\xbb\xcc\xdd" * 64)

    inspector = PacketTracerInspector("lab8.pkt")
    report = inspector.inspect_and_parse(fake_encrypted_pkt)
    assert report.status == PTImportStatus.UNSUPPORTED
    assert "Proprietary" in report.summary or "encryption" in report.summary.lower()
    assert report.fallback_guidance is not None
    assert "show run" in report.fallback_guidance
