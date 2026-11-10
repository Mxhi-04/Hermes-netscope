"""
pcap_reader.py — Streaming reader for classic pcap and pcapng capture files.

Supports:
- Classic pcap: little/big endian, microsecond (0xa1b2c3d4) and nanosecond (0xa1b23c4d)
- pcapng: SHB, IDB, EPB, SPB; per-interface if_tsresol (default 1µs)
- Link types: Ethernet (1), Linux cooked SLL (113), raw IP (101/228/229)

Streaming, bounded: never loads the whole file. Configurable limits on file size,
packet count, and time budget.
"""

import struct
import time
import os
from pathlib import Path

# Classic pcap magic numbers
PCAP_MAGIC_LE_US = 0xa1b2c3d4       # little-endian, microsecond
PCAP_MAGIC_BE_US = 0xd4c3b2a1       # big-endian, microsecond (read as LE → this)
PCAP_MAGIC_LE_NS = 0xa1b23c4d       # little-endian, nanosecond
PCAP_MAGIC_BE_NS = 0x4d3cb2a1       # big-endian, nanosecond

# pcapng magic
PCAPNG_SHB_MAGIC = 0x0A0D0D0A       # Section Header Block type
PCAPNG_BOM = 0x1A2B3C4D             # Byte Order Magic (0x1A2B3C4D)
PCAPNG_BOM_SWAPPED = 0x4D3C2B1A     # Byte Order Magic swapped

# Block types
BT_IDB = 0x00000001    # Interface Description Block
BT_EPB = 0x00000006    # Enhanced Packet Block
BT_SPB = 0x00000003    # Simple Packet Block

# Supported link types
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW_IP = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_RAW_IPV4 = 228
LINKTYPE_RAW_IPV6 = 229

SUPPORTED_LINKTYPES = {LINKTYPE_ETHERNET, LINKTYPE_RAW_IP, LINKTYPE_LINUX_SLL,
                       LINKTYPE_RAW_IPV4, LINKTYPE_RAW_IPV6}

# Defaults
DEFAULT_MAX_FILE_SIZE = 256 * 1024 * 1024   # 256 MB
DEFAULT_MAX_PACKETS = 2_000_000
DEFAULT_TIME_BUDGET = 30.0                   # seconds


class PcapError(Exception):
    """Raised for unrecoverable pcap format errors."""
    pass


class Packet:
    """Represents a single captured packet."""
    __slots__ = ('timestamp', 'captured_len', 'original_len', 'data',
                 'link_type', 'interface_id')

    def __init__(self, timestamp, captured_len, original_len, data,
                 link_type, interface_id=0):
        self.timestamp = timestamp          # float, seconds since epoch
        self.captured_len = captured_len
        self.original_len = original_len
        self.data = data                    # bytes (memoryview-safe)
        self.link_type = link_type
        self.interface_id = interface_id


class ReadResult:
    """Result of reading a capture file."""
    __slots__ = ('packets', 'file_format', 'link_types', 'packet_count',
                 'truncated', 'truncation_reason', 'unsupported_packets',
                 'errors', 'file_size', 'duration_sec')

    def __init__(self):
        self.packets = []
        self.file_format = None         # 'pcap' or 'pcapng'
        self.link_types = set()
        self.packet_count = 0
        self.truncated = False
        self.truncation_reason = None
        self.unsupported_packets = 0
        self.errors = []
        self.file_size = 0
        self.duration_sec = 0.0


def _read_exact(f, n):
    """Read exactly n bytes or raise."""
    data = f.read(n)
    if len(data) < n:
        raise PcapError(f"Unexpected EOF: wanted {n} bytes, got {len(data)}")
    return data


def _read_classic_pcap(f, file_size, max_packets, time_budget):
    """Read a classic pcap file."""
    result = ReadResult()
    result.file_format = 'pcap'
    result.file_size = file_size
    start_time = time.monotonic()

    # Read file header
    f.seek(0)
    magic_bytes = _read_exact(f, 4)
    magic = struct.unpack('<I', magic_bytes)[0]

    if magic == PCAP_MAGIC_LE_US:
        endian = '<'
        ts_divisor = 1_000_000.0
    elif magic == PCAP_MAGIC_BE_US:
        endian = '>'
        ts_divisor = 1_000_000.0
    elif magic == PCAP_MAGIC_LE_NS:
        endian = '<'
        ts_divisor = 1_000_000_000.0
    elif magic == PCAP_MAGIC_BE_NS:
        endian = '>'
        ts_divisor = 1_000_000_000.0
    else:
        raise PcapError(f"Unknown pcap magic: 0x{magic:08x}")

    hdr = _read_exact(f, 20)
    snaplen = struct.unpack(endian + 'I', hdr[12:16])[0]
    link_type = struct.unpack(endian + 'I', hdr[16:20])[0]
    result.link_types.add(link_type)

    supported = link_type in SUPPORTED_LINKTYPES
    pkt_hdr_fmt = endian + 'IIII'
    pkt_hdr_size = 16

    while True:
        if result.packet_count >= max_packets:
            result.truncated = True
            result.truncation_reason = f"Packet limit reached ({max_packets})"
            break

        elapsed = time.monotonic() - start_time
        if elapsed > time_budget:
            result.truncated = True
            result.truncation_reason = f"Time budget exceeded ({time_budget}s)"
            break

        pkt_hdr_data = f.read(pkt_hdr_size)
        if len(pkt_hdr_data) == 0:
            break
        if len(pkt_hdr_data) < pkt_hdr_size:
            result.errors.append("Truncated packet header at EOF")
            result.truncated = True
            result.truncation_reason = "Truncated packet header"
            break

        try:
            ts_sec, ts_frac, incl_len, orig_len = struct.unpack(pkt_hdr_fmt, pkt_hdr_data)
        except struct.error:
            result.errors.append("Malformed packet header")
            break

        if incl_len > 262144:
            result.errors.append(f"Unreasonable packet length: {incl_len}")
            break

        pkt_data = f.read(incl_len)
        if len(pkt_data) < incl_len:
            result.errors.append("Truncated packet data at EOF")
            result.truncated = True
            result.truncation_reason = "Truncated packet data"
            break

        timestamp = ts_sec + ts_frac / ts_divisor

        if supported:
            pkt = Packet(
                timestamp=timestamp,
                captured_len=incl_len,
                original_len=orig_len,
                data=pkt_data,
                link_type=link_type,
            )
            result.packets.append(pkt)
        else:
            result.unsupported_packets += 1

        result.packet_count += 1

    result.duration_sec = time.monotonic() - start_time
    return result


def _parse_pcapng_options(data, endian):
    """Parse pcapng option block, return dict of option_code -> value."""
    opts = {}
    offset = 0
    while offset + 4 <= len(data):
        opt_code = struct.unpack(endian + 'H', data[offset:offset+2])[0]
        opt_len = struct.unpack(endian + 'H', data[offset+2:offset+4])[0]
        offset += 4
        if opt_code == 0:
            break
        if offset + opt_len > len(data):
            break
        opts[opt_code] = data[offset:offset+opt_len]
        offset += opt_len
        offset += (4 - (opt_len % 4)) % 4
    return opts


def _read_pcapng(f, file_size, max_packets, time_budget):
    """Read a pcapng file."""
    result = ReadResult()
    result.file_format = 'pcapng'
    result.file_size = file_size
    start_time = time.monotonic()

    interfaces = []   # list of (link_type, ts_resol) tuples
    endian = '<'

    f.seek(0)

    while True:
        if result.packet_count >= max_packets:
            result.truncated = True
            result.truncation_reason = f"Packet limit reached ({max_packets})"
            break

        elapsed = time.monotonic() - start_time
        if elapsed > time_budget:
            result.truncated = True
            result.truncation_reason = f"Time budget exceeded ({time_budget}s)"
            break

        blk_hdr = f.read(8)
        if len(blk_hdr) == 0:
            break
        if len(blk_hdr) < 8:
            result.errors.append("Truncated block header at EOF")
            result.truncated = True
            result.truncation_reason = "Truncated block header"
            break

        # Check block type with current endian
        btype = struct.unpack(endian + 'I', blk_hdr[0:4])[0]
        blen = struct.unpack(endian + 'I', blk_hdr[4:8])[0]

        # Handle SHB (Section Header Block) which sets endianness
        if btype == PCAPNG_SHB_MAGIC:
            # Read first 4 bytes of body to inspect BOM
            bom_raw = f.read(4)
            if len(bom_raw) < 4:
                result.errors.append("Truncated SHB BOM")
                break
            bom_val = struct.unpack('<I', bom_raw)[0]
            if bom_val == PCAPNG_BOM:
                endian = '<'
            elif bom_val == PCAPNG_BOM_SWAPPED:
                endian = '>'
            else:
                # Try big endian unpack
                bom_val_be = struct.unpack('>I', bom_raw)[0]
                if bom_val_be == PCAPNG_BOM:
                    endian = '>'
                else:
                    endian = '<'

            # Re-read block length with determined endian
            blen = struct.unpack(endian + 'I', blk_hdr[4:8])[0]
            if blen < 12:
                result.errors.append(f"Invalid SHB block length: {blen}")
                break
            # Skip remainder of SHB
            remaining = blen - 12
            if remaining > 0:
                f.read(remaining)
            interfaces = []  # new section resets interfaces
            continue

        if blen < 12:
            result.errors.append(f"Invalid block length: {blen}")
            break

        body_len = blen - 8
        body = f.read(body_len)
        if len(body) < body_len:
            result.errors.append("Truncated block body")
            result.truncated = True
            result.truncation_reason = "Truncated block"
            break

        body = body[:-4]  # strip trailing block length

        if btype == BT_IDB:
            if len(body) < 8:
                interfaces.append((LINKTYPE_ETHERNET, 1_000_000))
                continue
            lt = struct.unpack(endian + 'H', body[0:2])[0]
            result.link_types.add(lt)

            ts_resol_base = 1_000_000
            if len(body) > 8:
                opts = _parse_pcapng_options(body[8:], endian)
                if 9 in opts and len(opts[9]) >= 1:
                    tsresol_byte = opts[9][0]
                    if tsresol_byte & 0x80:
                        ts_resol_base = 2 ** (tsresol_byte & 0x7f)
                    else:
                        ts_resol_base = 10 ** tsresol_byte

            interfaces.append((lt, ts_resol_base))

        elif btype == BT_EPB:
            if len(body) < 20:
                result.errors.append("Truncated EPB")
                continue

            iface_id = struct.unpack(endian + 'I', body[0:4])[0]
            ts_high = struct.unpack(endian + 'I', body[4:8])[0]
            ts_low = struct.unpack(endian + 'I', body[8:12])[0]
            cap_len = struct.unpack(endian + 'I', body[12:16])[0]
            orig_len = struct.unpack(endian + 'I', body[16:20])[0]

            if iface_id < len(interfaces):
                lt, ts_resol = interfaces[iface_id]
            else:
                lt, ts_resol = (LINKTYPE_ETHERNET, 1_000_000)

            ts_raw = (ts_high << 32) | ts_low
            timestamp = ts_raw / ts_resol
            pkt_data = body[20:20+cap_len]

            if lt in SUPPORTED_LINKTYPES:
                pkt = Packet(
                    timestamp=timestamp,
                    captured_len=cap_len,
                    original_len=orig_len,
                    data=pkt_data,
                    link_type=lt,
                    interface_id=iface_id,
                )
                result.packets.append(pkt)
            else:
                result.unsupported_packets += 1

            result.packet_count += 1

        elif btype == BT_SPB:
            if len(body) < 4:
                result.errors.append("Truncated SPB")
                continue

            orig_len = struct.unpack(endian + 'I', body[0:4])[0]
            lt = interfaces[0][0] if interfaces else LINKTYPE_ETHERNET
            pkt_data = body[4:]
            cap_len = len(pkt_data)

            if lt in SUPPORTED_LINKTYPES:
                pkt = Packet(
                    timestamp=0.0,
                    captured_len=cap_len,
                    original_len=orig_len,
                    data=pkt_data,
                    link_type=lt,
                    interface_id=0,
                )
                result.packets.append(pkt)
            else:
                result.unsupported_packets += 1

            result.packet_count += 1

    result.duration_sec = time.monotonic() - start_time
    return result


def validate_path(pcap_path, max_file_size=DEFAULT_MAX_FILE_SIZE):
    """Validate a file path for reading."""
    try:
        p = Path(pcap_path).resolve()
    except (ValueError, OSError) as e:
        return None, f"Invalid path: {e}"

    if not p.exists():
        return None, f"File does not exist: {p}"
    if not p.is_file():
        return None, f"Not a regular file: {p}"
    if not os.access(str(p), os.R_OK):
        return None, f"File not readable: {p}"

    file_size = p.stat().st_size
    if file_size == 0:
        return None, "File is empty"
    if file_size > max_file_size:
        return None, (f"File too large: {file_size / (1024*1024):.1f} MB "
                      f"(limit: {max_file_size / (1024*1024):.0f} MB)")

    return str(p), None


def read_pcap(pcap_path, max_packets=DEFAULT_MAX_PACKETS,
              max_file_size=DEFAULT_MAX_FILE_SIZE,
              time_budget=DEFAULT_TIME_BUDGET):
    """Read a pcap or pcapng file."""
    resolved, err = validate_path(pcap_path, max_file_size)
    if err:
        raise PcapError(err)

    file_size = os.path.getsize(resolved)

    with open(resolved, 'rb') as f:
        magic_bytes = f.read(4)
        if len(magic_bytes) < 4:
            raise PcapError("File too small to be a capture file")

        magic = struct.unpack('<I', magic_bytes)[0]

        if magic in (PCAP_MAGIC_LE_US, PCAP_MAGIC_BE_US,
                     PCAP_MAGIC_LE_NS, PCAP_MAGIC_BE_NS):
            return _read_classic_pcap(f, file_size, max_packets, time_budget)

        if magic == PCAPNG_SHB_MAGIC:
            return _read_pcapng(f, file_size, max_packets, time_budget)

        magic_be = struct.unpack('>I', magic_bytes)[0]
        if magic_be == PCAPNG_SHB_MAGIC:
            return _read_pcapng(f, file_size, max_packets, time_budget)

        raise PcapError(f"Not a pcap or pcapng file (magic: 0x{magic:08x})")
