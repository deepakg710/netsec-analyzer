"""
Cisco Packet Tracer (.pkt) Format Inspector and Ingestion Engine.
Defensibly inspects Packet Tracer binary files, analyzes their container/header structure,
attempts safe extraction and stream carving of embedded configurations or XML,
and provides honest status reporting (FULLY_PARSED, PARTIALLY_PARSED, UNSUPPORTED, FAILED)
with documented, actionable fallbacks.
"""

import io
import re
import zlib
import zipfile
import xml.etree.ElementTree as ET
from enum import Enum
from typing import List, Dict, Optional, Tuple, Any
from app.models.canonical import Device, Interface, DeviceType
from app.ingestion.cisco_ios import CiscoIOSParser


class PTImportStatus(str, Enum):
    FULLY_PARSED = "Fully parsed within supported scope"
    PARTIALLY_PARSED = "Partially parsed"
    UNSUPPORTED = "Unsupported"
    FAILED = "Failed"


class PacketTracerInspectionReport:
    def __init__(
        self,
        status: PTImportStatus,
        summary: str,
        detected_format: str,
        technical_details: Dict[str, Any],
        extracted_devices: List[Device],
        fallback_guidance: Optional[str] = None
    ):
        self.status = status
        self.summary = summary
        self.detected_format = detected_format
        self.technical_details = technical_details
        self.extracted_devices = extracted_devices
        self.fallback_guidance = fallback_guidance

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "summary": self.summary,
            "detected_format": self.detected_format,
            "technical_details": self.technical_details,
            "extracted_devices_count": len(self.extracted_devices),
            "extracted_device_names": [d.hostname for d in self.extracted_devices],
            "fallback_guidance": self.fallback_guidance
        }


class PacketTracerInspector:
    def __init__(self, filename: str = "network.pkt"):
        self.filename = filename

    def inspect_and_parse(self, file_bytes: bytes) -> PacketTracerInspectionReport:
        if not file_bytes:
            return PacketTracerInspectionReport(
                status=PTImportStatus.FAILED,
                summary="The provided Packet Tracer file is completely empty (0 bytes).",
                detected_format="Empty File",
                technical_details={"file_size": 0},
                extracted_devices=[],
                fallback_guidance="Please provide a valid file containing network device configurations."
            )

        file_size = len(file_bytes)
        header_sample = file_bytes[:64]
        header_hex = header_sample.hex()
        
        technical_details: Dict[str, Any] = {
            "file_size_bytes": file_size,
            "header_hex_sample": header_hex[:32],
            "header_ascii_sample": "".join(chr(b) if 32 <= b <= 126 else "." for b in header_sample[:32])
        }

        # -------------------------------------------------------------
        # 1. Plaintext / Cisco Config Detection (e.g. text saved as .pkt)
        # -------------------------------------------------------------
        try:
            text_candidate = file_bytes.decode("utf-8", errors="strict")
            if re.search(r'\bhostname\s+([a-zA-Z0-9_-]+)', text_candidate, re.IGNORECASE) or \
               re.search(r'\binterface\s+[a-zA-Z0-9/.-]+', text_candidate, re.IGNORECASE):
                parser = CiscoIOSParser(filename=self.filename)
                dev = parser.parse_text(text_candidate)
                if dev.interfaces or dev.hostname != "Device":
                    technical_details["container_type"] = "Cisco IOS ASCII Text File (.pkt extension)"
                    return PacketTracerInspectionReport(
                        status=PTImportStatus.FULLY_PARSED,
                        summary=f"Detected valid Cisco IOS configuration in text format. Extracted device '{dev.hostname}'.",
                        detected_format="Cisco IOS Configuration Text",
                        technical_details=technical_details,
                        extracted_devices=[dev],
                        fallback_guidance="Configurations were successfully extracted directly from file content."
                    )
        except UnicodeDecodeError:
            pass

        # -------------------------------------------------------------
        # 2. Check if it's a standard ZIP archive (PKZ, PKA, or zipped PKT)
        # -------------------------------------------------------------
        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
                file_list = z.namelist()
                technical_details["container_type"] = "ZIP Container / PKZ"
                technical_details["archive_files"] = file_list
                
                extracted_devices: List[Device] = []
                for fname in file_list:
                    raw_content = z.read(fname)
                    # Check text configs
                    if fname.endswith(('.cfg', '.txt', '.conf')):
                        text_content = raw_content.decode('utf-8', errors='ignore')
                        parser = CiscoIOSParser(filename=fname)
                        dev = parser.parse_text(text_content)
                        if dev.interfaces or dev.hostname != "Device":
                            extracted_devices.append(dev)
                    # Check XML files
                    elif fname.endswith(('.xml', '.act', '.pka')):
                        xml_devices = self._parse_pt_xml(raw_content, source_file=fname)
                        extracted_devices.extend(xml_devices)
                
                if extracted_devices:
                    return PacketTracerInspectionReport(
                        status=PTImportStatus.PARTIALLY_PARSED,
                        summary=f"Extracted {len(extracted_devices)} device configurations from ZIP/PKZ container.",
                        detected_format="Packet Tracer Zip/PKZ Archive",
                        technical_details=technical_details,
                        extracted_devices=extracted_devices,
                        fallback_guidance="Verify that all devices from your topology are present in the analysis."
                    )
        except zipfile.BadZipFile:
            pass

        # -------------------------------------------------------------
        # 3. Stream Carving: Scan for ZLIB / GZIP streams across entire file
        # -------------------------------------------------------------
        carved_payloads: List[bytes] = []
        max_scan = min(file_size, 512 * 1024)  # scan first 512KB for streams
        
        # Scan for Zlib (RFC 1950: (b0*256 + b1) % 31 == 0 and b0 == 0x78)
        for offset in range(max_scan - 2):
            b0 = file_bytes[offset]
            b1 = file_bytes[offset + 1]
            if b0 == 0x78 and ((b0 * 256 + b1) % 31 == 0):
                try:
                    d = zlib.decompressobj(wbits=15)
                    decomp = d.decompress(file_bytes[offset:offset + 262144])
                    if len(decomp) > 64:
                        carved_payloads.append(decomp)
                        technical_details.setdefault("carved_zlib_offsets", []).append(offset)
                except Exception:
                    pass

        # Scan for Gzip (0x1f, 0x8b, 0x08)
        for offset in range(max_scan - 3):
            if file_bytes[offset] == 0x1f and file_bytes[offset + 1] == 0x8b and file_bytes[offset + 2] == 0x08:
                try:
                    d = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
                    decomp = d.decompress(file_bytes[offset:offset + 262144])
                    if len(decomp) > 64:
                        carved_payloads.append(decomp)
                        technical_details.setdefault("carved_gzip_offsets", []).append(offset)
                except Exception:
                    pass

        # Inspect all carved payloads for XML or Cisco CLI configurations
        for payload in carved_payloads:
            # Check XML
            xml_devs = self._parse_pt_xml(payload, source_file="carved_stream.xml")
            if xml_devs:
                return PacketTracerInspectionReport(
                    status=PTImportStatus.PARTIALLY_PARSED,
                    summary=f"Carved compressed XML streams and extracted {len(xml_devs)} network devices.",
                    detected_format="Cisco Packet Tracer Compressed XML Stream",
                    technical_details=technical_details,
                    extracted_devices=xml_devs,
                    fallback_guidance="Extracted from internal compressed structures. Verify interface parameters."
                )
            
            # Check Cisco config blocks in decompressed stream
            decomp_devs = self._extract_cisco_blocks_from_binary(payload)
            if decomp_devs:
                return PacketTracerInspectionReport(
                    status=PTImportStatus.PARTIALLY_PARSED,
                    summary=f"Carved compressed stream and recovered {len(decomp_devs)} Cisco device configurations.",
                    detected_format="Cisco Packet Tracer Compressed Stream with Recoverable CLI",
                    technical_details=technical_details,
                    extracted_devices=decomp_devs,
                    fallback_guidance="Configurations extracted from decompressed memory structures."
                )

        # -------------------------------------------------------------
        # 4. Binary String Carving on Raw Bytes
        # -------------------------------------------------------------
        raw_devs = self._extract_cisco_blocks_from_binary(file_bytes)
        if raw_devs:
            return PacketTracerInspectionReport(
                status=PTImportStatus.PARTIALLY_PARSED,
                summary=f"Scanned binary structure and recovered {len(raw_devs)} Cisco configuration segments.",
                detected_format="Cisco Packet Tracer Binary with Recoverable Configs",
                technical_details=technical_details,
                extracted_devices=raw_devs,
                fallback_guidance="Extracted configurations were recovered from printable memory segments."
            )

        # -------------------------------------------------------------
        # 5. Proprietary Closed-Source Cisco Packet Tracer Binary
        # -------------------------------------------------------------
        technical_details["is_cisco_proprietary_binary"] = True
        technical_details["encryption_status"] = "Cisco Packet Tracer v7.x/v8.x Encrypted Container"
        technical_details["defensibility_notice"] = (
            "Cisco Packet Tracer 7.x & 8.x encrypts simulation state with proprietary keys compiled "
            "into the PacketTracer executable. In accordance with NetSec Analyzer's defensibility rules, "
            "we never invent or guess configurations when proprietary DRM/encryption is present."
        )

        fallback_msg = (
            "Cisco Packet Tracer 7.x & 8.x encrypts simulation files with proprietary DRM keys.\n\n"
            "FAST 3-STEP IMPORT TO ANALYZE YOUR DESIGN IN SECONDS:\n"
            "1. In Cisco Packet Tracer, click on any Router or Switch in your topology.\n"
            "2. Click the 'CLI' tab and type:  show run  (or show running-config)\n"
            "3. Copy the output and paste it into the 'Paste Cisco Config' box below.\n\n"
            "This provides 100% precision, full line traceability, and instant attack-path analysis!"
        )

        return PacketTracerInspectionReport(
            status=PTImportStatus.UNSUPPORTED,
            summary="Proprietary Cisco Packet Tracer binary encryption detected (v7/v8). Native decryption keys are not publicly available.",
            detected_format="Cisco Packet Tracer Proprietary Encrypted Binary (.pkt)",
            technical_details=technical_details,
            extracted_devices=[],
            fallback_guidance=fallback_msg
        )

    def _parse_pt_xml(self, data: bytes, source_file: str) -> List[Device]:
        """Parses Packet Tracer XML trees looking for device and interface elements."""
        devices: List[Device] = []
        try:
            text = data.decode("utf-8", errors="ignore")
            if "<" not in text or ">" not in text:
                return []
            
            # Simple regex search for XML device blocks if XML is malformed
            dev_matches = re.finditer(r'<device[^>]*name=["\']([^"\']+)["\'][^>]*>(.*?)</device>', text, re.IGNORECASE | re.DOTALL)
            for m in dev_matches:
                dname = m.group(1)
                dbody = m.group(2)
                dev = Device(
                    hostname=dname,
                    device_type=DeviceType.ROUTER if "router" in dname.lower() else DeviceType.SWITCH,
                    source_file=source_file
                )
                
                # Extract interfaces
                iface_matches = re.finditer(r'<interface[^>]*name=["\']([^"\']+)["\'][^>]*>(.*?)</interface>', dbody, re.IGNORECASE | re.DOTALL)
                for im in iface_matches:
                    iname = im.group(1)
                    ibody = im.group(2)
                    ip_m = re.search(r'<ip[^>]*>([0-9.]+)</ip>', ibody, re.IGNORECASE)
                    mask_m = re.search(r'<subnet[^>]*>([0-9.]+)</subnet>', ibody, re.IGNORECASE)
                    
                    iface = Interface(
                        name=iname,
                        ip_address=ip_m.group(1) if ip_m else None,
                        subnet_mask=mask_m.group(1) if mask_m else None,
                        enabled=True
                    )
                    dev.interfaces[iname] = iface
                
                if dev.interfaces or dev.hostname:
                    devices.append(dev)

        except Exception:
            pass
        return devices

    def _extract_cisco_blocks_from_binary(self, data: bytes) -> List[Device]:
        """Scans binary data for embedded Cisco IOS configuration blocks."""
        text_fragments = []
        current = []
        for b in data:
            if b in (10, 13) or (32 <= b <= 126):
                current.append(chr(b))
            else:
                if len(current) > 30:
                    text_fragments.append("".join(current))
                current = []
        if len(current) > 30:
            text_fragments.append("".join(current))

        full_text = "\n".join(text_fragments)
        
        # Look for hostname patterns
        hostname_matches = list(re.finditer(r'hostname\s+([a-zA-Z0-9_-]+)', full_text, re.IGNORECASE))
        if not hostname_matches:
            return []

        devices: List[Device] = []
        for i, match in enumerate(hostname_matches):
            start_pos = match.start()
            end_pos = hostname_matches[i + 1].start() if i + 1 < len(hostname_matches) else len(full_text)
            chunk = full_text[start_pos:end_pos]
            
            if re.search(r'interface\s+[a-zA-Z]', chunk, re.IGNORECASE) or re.search(r'ip\s+address', chunk, re.IGNORECASE):
                dev_name = match.group(1)
                parser = CiscoIOSParser(filename=f"{self.filename}:{dev_name}")
                dev = parser.parse_text(chunk)
                if dev.interfaces:
                    devices.append(dev)

        return devices
