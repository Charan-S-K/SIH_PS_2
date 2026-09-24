"""
PCAP and PCAPNG file format validation and sanitization.
Performs magic byte sniffing, extension verification, and safe filename sanitization.
"""

import os
import re
from typing import Tuple

# Known PCAP magic byte constants
PCAP_MICROSECOND_LE = b"\xd4\xc3\xb2\xa1"
PCAP_MICROSECOND_BE = b"\xa1\xb2\xc3\xd4"
PCAP_NANOSECOND_LE = b"\x4d\x3c\xb2\xa1"
PCAP_NANOSECOND_BE = b"\xa1\xb2\x3c\x4d"
PCAPNG_SHB_MAGIC = b"\x0a\x0d\x0d\x0a"
PCAPNG_BYTE_ORDER_BE = b"\x1a\x2b\x3c\x4d"
PCAPNG_BYTE_ORDER_LE = b"\x4d\x3c\x2b\x1a"


def sanitize_filename(filename: str) -> str:
    """
    Sanitize uploaded filename to prevent directory traversal and injection.
    Strips directory separators and restricts to safe characters.
    """
    if not filename:
        return "unnamed_capture.pcap"
    
    # Strip any directory path components
    basename = os.path.basename(filename.strip().replace("\\", "/"))
    
    # Allow alphanumeric, dot, underscore, dash
    clean_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', basename)
    
    # Avoid hidden files or pure dot names
    clean_name = clean_name.lstrip(".")
    if not clean_name:
        clean_name = "capture.pcap"
        
    return clean_name[:255]


def validate_pcap_magic_bytes(header: bytes) -> Tuple[bool, str, str]:
    """
    Sniffs the initial bytes of a capture file to verify valid PCAP or PCAPNG structure.
    
    Returns:
        (is_valid: bool, format_type: str, description: str)
    """
    if len(header) < 4:
        return False, "unknown", "File header too short (< 4 bytes)"

    # Check 4-byte standard and nanosecond PCAP magic numbers
    magic_4 = header[:4]
    if magic_4 == PCAP_MICROSECOND_LE:
        return True, "pcap", "PCAP standard (microsecond resolution, little-endian)"
    if magic_4 == PCAP_MICROSECOND_BE:
        return True, "pcap", "PCAP standard (microsecond resolution, big-endian)"
    if magic_4 == PCAP_NANOSECOND_LE:
        return True, "pcap", "PCAP nanosecond (nanosecond resolution, little-endian)"
    if magic_4 == PCAP_NANOSECOND_BE:
        return True, "pcap", "PCAP nanosecond (nanosecond resolution, big-endian)"

    # Check PCAPNG Section Header Block (SHB)
    if magic_4 == PCAPNG_SHB_MAGIC:
        if len(header) >= 12:
            byte_order = header[8:12]
            if byte_order in (PCAPNG_BYTE_ORDER_LE, PCAPNG_BYTE_ORDER_BE):
                return True, "pcapng", "PCAPNG Next Generation capture format"
        # Even if under 12 bytes initially, first 4 match PCAPNG SHB
        return True, "pcapng", "PCAPNG Section Header Block detected"

    return False, "unknown", f"Invalid magic bytes: 0x{magic_4.hex()}"
