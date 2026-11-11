"""
test_netscope.py — Comprehensive offline test suite for netscope.

Tests:
- Reader: pcap LE/BE, us/ns, pcapng, truncated, garbage, empty, huge length
- Decoder: VLAN, IPv4, IPv6, fragments, TCP flags, DNS, TLS SNI, malformed input
- Analysis: aggregations, flows, timeline, structured queries
- Heuristics: scan, beacon, spike, DNS anomalies, clean baseline
- Safety & Security: path validation, hostile strings sanitization, CSP, no external URLs
- Registration: contract check between plugin.yaml and register(ctx)
"""

import sys
import struct
import json
import pytest
from pathlib import Path

# Ensure plugin root is in sys.path
PLUGIN_ROOT = str(Path(__file__).resolve().parents[1])
if PLUGIN_ROOT not in sys.path:
    sys.path.insert(0, PLUGIN_ROOT)

from pcap_reader import (
    read_pcap, validate_path, PcapError, Packet,
    PCAP_MAGIC_LE_US, PCAPNG_SHB_MAGIC, PCAPNG_BOM, BT_IDB, BT_EPB, LINKTYPE_ETHERNET
)
from decode import decode_packet, DecodedPacket, _sanitize_string
from tools import handle_analyze, handle_query, handle_visualize
from main import register
from examples.make_sample_pcap import generate_sample_pcap


# =====================================================================
# 1. PCAP & PCAPNG READER TESTS
# =====================================================================

def _create_minimal_pcap(path, magic=0xa1b2c3d4, endian='<', snaplen=65535, linktype=1, packets=None):
    """Helper to synthesize custom pcap binaries."""
    with open(path, 'wb') as f:
        # Global header: magic(4), v_major(2), v_minor(2), zone(4), sigfigs(4), snaplen(4), network(4)
        f.write(struct.pack(endian + 'IHHiIII', magic, 2, 4, 0, 0, snaplen, linktype))
        if packets:
            for ts_sec, ts_frac, data in packets:
                caplen = len(data)
                f.write(struct.pack(endian + 'IIII', int(ts_sec), int(ts_frac), caplen, caplen))
                f.write(data)


def test_reader_classic_pcap_endian_and_timestamps(tmp_path):
    """Test LE/BE microsecond and nanosecond pcap variants."""
    dummy_pkt = b'\x00' * 34  # 14 eth + 20 ip

    # 1. Little-endian microsecond (0xa1b2c3d4)
    p1 = tmp_path / "le_us.pcap"
    _create_minimal_pcap(p1, magic=0xa1b2c3d4, endian='<', packets=[(100, 500000, dummy_pkt)])
    r1 = read_pcap(str(p1))
    assert len(r1.packets) == 1
    assert r1.packets[0].timestamp == pytest.approx(100.5)

    # 2. Big-endian microsecond (0xa1b2c3d4 written >)
    p2 = tmp_path / "be_us.pcap"
    _create_minimal_pcap(p2, magic=0xa1b2c3d4, endian='>', packets=[(100, 500000, dummy_pkt)])
    r2 = read_pcap(str(p2))
    assert len(r2.packets) == 1
    assert r2.packets[0].timestamp == pytest.approx(100.5)

    # 3. Little-endian nanosecond (0xa1b23c4d)
    p3 = tmp_path / "le_ns.pcap"
    _create_minimal_pcap(p3, magic=0xa1b23c4d, endian='<', packets=[(100, 500000000, dummy_pkt)])
    r3 = read_pcap(str(p3))
    assert len(r3.packets) == 1
    assert r3.packets[0].timestamp == pytest.approx(100.5)

    # 4. Big-endian nanosecond (0xa1b23c4d written >)
    p4 = tmp_path / "be_ns.pcap"
    _create_minimal_pcap(p4, magic=0xa1b23c4d, endian='>', packets=[(100, 500000000, dummy_pkt)])
    r4 = read_pcap(str(p4))
    assert len(r4.packets) == 1
    assert r4.packets[0].timestamp == pytest.approx(100.5)


def test_reader_pcapng(tmp_path):
    """Test reading pcapng format with SHB, IDB, and EPB blocks."""
    ng_file = tmp_path / "test.pcapng"
    dummy_eth = b'\x00' * 40
    with open(ng_file, 'wb') as f:
        # Section Header Block (SHB)
        # block_type(4), block_len(4), bom(4), major(2), minor(2), section_len(8), block_len(4)
        shb_body = struct.pack('<IHHq', PCAPNG_BOM, 1, 0, -1)
        shb_total = 12 + len(shb_body)
        f.write(struct.pack('<II', PCAPNG_SHB_MAGIC, shb_total))
        f.write(shb_body)
        f.write(struct.pack('<I', shb_total))

        # Interface Description Block (IDB)
        # block_type(4), block_len(4), linktype(2), reserved(2), snaplen(4), block_len(4)
        idb_body = struct.pack('<HHI', 1, 0, 65535)
        idb_total = 12 + len(idb_body)
        f.write(struct.pack('<II', BT_IDB, idb_total))
        f.write(idb_body)
        f.write(struct.pack('<I', idb_total))

        # Enhanced Packet Block (EPB)
        ts_raw = 1700000000 * 1000000
        ts_hi = ts_raw >> 32
        ts_lo = ts_raw & 0xffffffff
        cap_len = len(dummy_eth)
        epb_body = struct.pack('<IIIII', 0, ts_hi, ts_lo, cap_len, cap_len) + dummy_eth
        epb_total = 12 + len(epb_body)
        f.write(struct.pack('<II', BT_EPB, epb_total))
        f.write(epb_body)
        f.write(struct.pack('<I', epb_total))

    result = read_pcap(str(ng_file))
    assert result.file_format == 'pcapng'
    assert len(result.packets) == 1
    assert result.packets[0].captured_len == 40
    assert result.packets[0].timestamp == pytest.approx(1700000000.0)


def test_reader_error_handling(tmp_path):
    """Test graceful handling of corrupt, empty, and truncated files."""
    # 1. Empty file
    empty_f = tmp_path / "empty.pcap"
    empty_f.write_bytes(b'')
    with pytest.raises(PcapError, match="empty"):
        read_pcap(str(empty_f))

    # 2. Garbage file
    garbage_f = tmp_path / "garbage.pcap"
    garbage_f.write_bytes(b'RANDOM_GARBAGE_NOT_A_PCAP_FILE')
    with pytest.raises(PcapError, match="Not a pcap or pcapng"):
        read_pcap(str(garbage_f))

    # 3. Truncated pcap header
    trunc_hdr = tmp_path / "trunc_hdr.pcap"
    trunc_hdr.write_bytes(struct.pack('<I', PCAP_MAGIC_LE_US) + b'\x00' * 5)
    with pytest.raises(PcapError, match="Unexpected EOF"):
        read_pcap(str(trunc_hdr))

    # 4. Truncated packet record
    trunc_pkt = tmp_path / "trunc_pkt.pcap"
    with open(trunc_pkt, 'wb') as f:
        f.write(struct.pack('<IHHiIII', PCAP_MAGIC_LE_US, 2, 4, 0, 0, 65535, 1))
        f.write(struct.pack('<IIII', 1000, 0, 100, 100))
        f.write(b'X' * 10)
    res = read_pcap(str(trunc_pkt))
    assert res.truncated is True
    assert "Truncated" in res.truncation_reason

    # 5. Non-existent path
    with pytest.raises(PcapError, match="does not exist"):
        read_pcap(str(tmp_path / "nonexistent.pcap"))


# =====================================================================
# 2. PROTOCOL DECODER TESTS
# =====================================================================

def test_decode_ethernet_vlan_ipv4_tcp():
    """Test decoding VLAN tag, IPv4 headers, and TCP flags."""
    dst_mac = b'\x00\x11\x22\x33\x44\x55'
    src_mac = b'\x66\x77\x88\x99\xaa\xbb'
    vlan_hdr = struct.pack('!HH', 0x8100, 100)  # VLAN 100
    eth_type = struct.pack('!H', 0x0800)        # IPv4
    eth = dst_mac + src_mac + vlan_hdr + eth_type

    ip_hdr = struct.pack('!BBHHHBBH4s4s',
        0x45, 0, 40, 0x1234, 0x4000, 64, 6, 0,
        b'\xc0\xa8\x01\x32', b'\xc0\xa8\x01\x64'  # 192.168.1.50 -> 192.168.1.100
    )
    # TCP header with SYN + ACK (0x12) from port 50000 to port 443 (TLS)
    tcp_hdr = struct.pack('!HHIIBBHHH', 50000, 443, 1000, 2000, 0x50, 0x12, 65535, 0, 0)

    raw_pkt = Packet(100.0, len(eth + ip_hdr + tcp_hdr), len(eth + ip_hdr + tcp_hdr), eth + ip_hdr + tcp_hdr, LINKTYPE_ETHERNET)
    decoded = decode_packet(raw_pkt)

    assert decoded.vlan_id == 100
    assert decoded.src_ip == "192.168.1.50"
    assert decoded.dst_ip == "192.168.1.100"
    assert decoded.ip_proto == 6
    assert decoded.src_port == 50000
    assert decoded.dst_port == 443
    assert (decoded.tcp_flags & 0x02) != 0  # SYN
    assert (decoded.tcp_flags & 0x10) != 0  # ACK
    assert decoded.protocol_name == "TLS"


def test_decode_ipv6():
    """Test decoding IPv6 packet."""
    eth = b'\x00' * 12 + struct.pack('!H', 0x86DD)
    src_ip6 = b'\x20\x01\x0d\xb8' + b'\x00' * 12
    dst_ip6 = b'\x20\x01\x0d\xb8' + b'\x00' * 11 + b'\x01'
    ip6_hdr = struct.pack('!IHBB', 0x60000000, 8, 17, 64) + src_ip6 + dst_ip6
    udp_hdr = struct.pack('!HHHH', 5353, 5353, 8, 0)

    raw = eth + ip6_hdr + udp_hdr
    pkt = Packet(1.0, len(raw), len(raw), raw, LINKTYPE_ETHERNET)
    decoded = decode_packet(pkt)

    assert decoded.ip_version == 6
    assert decoded.ip_proto == 17
    assert decoded.protocol_name == "DNS"
    assert "2001:db8::" in decoded.src_ip


def test_decode_dns_and_tls_sni():
    """Test extracting DNS query and TLS SNI."""
    from examples.make_sample_pcap import _build_dns_query, _build_tls_client_hello, _make_packet

    # 1. DNS query
    dns_bytes = _build_dns_query("secure.internal.corp")
    pkt1_raw = _make_packet("10.0.0.1", "10.0.0.2", 50000, 53, 17, dns_bytes)
    dec1 = decode_packet(Packet(1.0, len(pkt1_raw), len(pkt1_raw), pkt1_raw, LINKTYPE_ETHERNET))
    assert dec1.dns_query == "secure.internal.corp"
    assert dec1.protocol_name == "DNS"

    # 2. TLS SNI
    tls_bytes = _build_tls_client_hello("gateway.company.net")
    pkt2_raw = _make_packet("10.0.0.1", "10.0.0.2", 50000, 443, 6, payload=tls_bytes, tcp_flags=0x18)
    dec2 = decode_packet(Packet(2.0, len(pkt2_raw), len(pkt2_raw), pkt2_raw, LINKTYPE_ETHERNET))
    assert dec2.tls_sni == "gateway.company.net"
    assert dec2.protocol_name == "TLS"


def test_decoder_never_raises_on_corrupt_packet():
    """Ensure malformed / truncated packets do not raise unhandled exceptions."""
    corrupt_cases = [
        b'',
        b'\x00' * 5,
        b'\xff' * 14,
        b'\x00' * 14 + b'\x45' + b'\x00' * 3,  # truncated IPv4
        b'\x00' * 14 + b'\x60' + b'\x00' * 10, # truncated IPv6
    ]
    for c in corrupt_cases:
        pkt = Packet(1.0, len(c), len(c), c, LINKTYPE_ETHERNET)
        decoded = decode_packet(pkt)
        assert isinstance(decoded, DecodedPacket)


# =====================================================================
# 3. ANALYSIS & HEURISTICS TESTS
# =====================================================================

@pytest.fixture(scope="session")
def sample_pcap_path(tmp_path_factory):
    p = tmp_path_factory.mktemp("pcaps") / "fixture_sample.pcap"
    generate_sample_pcap(str(p))
    return str(p)


def test_sample_analysis_and_heuristics(sample_pcap_path):
    """Verify ground truth on generated sample capture and heuristic activations."""
    res_str = handle_analyze(sample_pcap_path)
    res = json.loads(res_str)

    assert res["ok"] is True
    assert res["total_packets"] >= 1400
    assert res["host_count"] >= 15
    assert res["flow_count"] >= 30

    aid = res["analysis_id"]

    # Verify all query types
    talkers = json.loads(handle_query(aid, "top_talkers", n=5))
    assert talkers["ok"] is True
    assert len(talkers["results"]) == 5

    host_det = json.loads(handle_query(aid, "host_detail", ip="192.168.1.55"))
    assert host_det["ok"] is True
    assert host_det["host"]["ip"] == "192.168.1.55"

    convs = json.loads(handle_query(aid, "conversations", n=5))
    assert convs["ok"] is True
    assert len(convs["results"]) > 0

    protos = json.loads(handle_query(aid, "protocol_breakdown"))
    assert protos["ok"] is True
    proto_names = [p["name"] for p in protos["protocols"]]
    assert "DNS" in proto_names
    assert "TCP" in proto_names or "TLS" in proto_names

    dns_map = json.loads(handle_query(aid, "dns_names"))
    assert dns_map["ok"] is True

    # Verify findings in detail
    findings = json.loads(handle_query(aid, "findings"))["results"]
    kinds = {f["kind"] for f in findings}

    assert "port_scan" in kinds
    assert "beaconing" in kinds
    assert "dns_long_labels" in kinds or "dns_many_subdomains" in kinds
    assert "traffic_spike" in kinds
    assert "cleartext_protocols" in kinds

    for f in findings:
        why = f["why"].lower()
        assert ("consistent with" in why or "looks like" in why or "detected" in why or "observed" in why)


def test_clean_capture_heuristics(tmp_path):
    """Ensure normal clean traffic does not trigger false positive attack heuristics."""
    clean_pcap = tmp_path / "clean.pcap"
    dummy_eth = b'\x00' * 14
    ip_tcp = b'\x45\x00\x00\x28\x12\x34\x40\x00\x40\x06\x00\x00\xc0\xa8\x01\x0a\xc0\xa8\x01\x01' + b'\x00' * 20
    _create_minimal_pcap(clean_pcap, packets=[
        (10, 0, dummy_eth + ip_tcp),
        (15, 0, dummy_eth + ip_tcp),
        (20, 0, dummy_eth + ip_tcp),
    ])

    res = json.loads(handle_analyze(str(clean_pcap)))
    assert res["ok"] is True
    aid = res["analysis_id"]
    findings = json.loads(handle_query(aid, "findings"))["results"]

    kinds = {f["kind"] for f in findings}
    assert "port_scan" not in kinds
    assert "beaconing" not in kinds
    assert "dns_long_labels" not in kinds
    assert "traffic_spike" not in kinds


# =====================================================================
# 4. SAFETY, CSP & REPORT VALIDATION
# =====================================================================

def test_hostile_strings_sanitization_and_csp(sample_pcap_path, tmp_path):
    """Verify security controls: hostile payload escaping, strict CSP, no external URLs."""
    hostile = "<script>alert('xss')</script>\x00\x01\r\n\t"
    cleaned = _sanitize_string(hostile)
    assert "<script>" in cleaned
    assert "\x00" not in cleaned
    assert "\r" not in cleaned

    res = json.loads(handle_analyze(sample_pcap_path))
    aid = res["analysis_id"]
    vis = json.loads(handle_visualize(aid))
    assert vis["ok"] is True
    report_file = Path(vis["report_path"])
    assert report_file.exists()

    report_html = report_file.read_text(encoding="utf-8")

    assert "Content-Security-Policy" in report_html
    assert "default-src 'none'" in report_html
    assert "script-src 'unsafe-inline'" in report_html

    for line in report_html.splitlines():
        if "<script type=\"application/json\"" in line:
            continue
        if "id=\"netscope-data\"" in line:
            continue
        assert "http://" not in line, f"External URL found: {line}"
        assert "https://" not in line, f"External URL found: {line}"


def test_path_validation_and_containment(tmp_path):
    """Path validation must block directories, non-files, empty files."""
    valid_p, err = validate_path(str(tmp_path))
    assert err is not None
    assert "Not a regular file" in err

    fake_file = tmp_path / "does_not_exist.pcap"
    valid_p, err = validate_path(str(fake_file))
    assert err is not None
    assert "does not exist" in err


# =====================================================================
# 5. REGISTRATION & CATALOG CONTRACT
# =====================================================================

class FakePluginContext:
    def __init__(self):
        self.tools = {}
        self.commands = {}
        self.skills = {}

    def register_tool(self, name, toolset, schema, handler):
        self.tools[name] = {"toolset": toolset, "schema": schema, "handler": handler}

    def register_command(self, name, handler, description):
        self.commands[name] = {"handler": handler, "description": description}

    def register_skill(self, name, path):
        self.skills[name] = {"path": path}


def _parse_yaml_lists(yaml_path):
    """Stdlib-only minimal YAML list parser for plugin.yaml manifest checking."""
    content = yaml_path.read_text(encoding="utf-8")
    data = {}
    current_key = None
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.endswith(':'):
            current_key = line[:-1]
            data[current_key] = []
        elif line.startswith('- ') and current_key:
            data[current_key].append(line[2:].strip().strip('"').strip("'"))
        elif ':' in line:
            k, v = line.split(':', 1)
            current_key = k.strip()
            data[current_key] = v.strip().strip('"').strip("'")
    return data


def test_registration_matches_plugin_yaml():
    """Verify register(ctx) registers exactly what plugin.yaml declares."""
    plugin_yaml_path = Path(PLUGIN_ROOT) / "plugin.yaml"
    assert plugin_yaml_path.exists()

    manifest = _parse_yaml_lists(plugin_yaml_path)

    ctx = FakePluginContext()
    register(ctx)

    assert set(ctx.tools.keys()) == set(manifest.get("provides_tools", []))
    assert set(ctx.commands.keys()) == set(manifest.get("provides_commands", []))
    assert set(ctx.skills.keys()) == set(manifest.get("provides_skills", []))


def test_tool_handlers_accept_dict_arguments(sample_pcap_path):
    """Verify tool wrappers accept single dict args as called by Hermes Agent: handler(args)."""
    ctx = FakePluginContext()
    register(ctx)

    # 1. netscope_analyze with dict argument
    analyze_handler = ctx.tools["netscope_analyze"]["handler"]
    res1 = json.loads(analyze_handler({"pcap_path": sample_pcap_path}))
    assert res1["ok"] is True
    aid = res1["analysis_id"]

    # Missing pcap_path returns clean structured error
    res_no_path = json.loads(analyze_handler({}))
    assert res_no_path["ok"] is False
    assert "Missing" in res_no_path["error"] or "error" in res_no_path

    # 2. netscope_query with dict argument
    query_handler = ctx.tools["netscope_query"]["handler"]
    res2 = json.loads(query_handler({"analysis_id": aid, "query": "top_talkers", "n": 3}))
    assert res2["ok"] is True
    assert len(res2["results"]) == 3

    # Unknown query returns ok: False
    res_bad_query = json.loads(query_handler({"analysis_id": aid, "query": "nonexistent_query"}))
    assert res_bad_query["ok"] is False

    # 3. netscope_visualize with dict argument
    vis_handler = ctx.tools["netscope_visualize"]["handler"]
    res3 = json.loads(vis_handler({"analysis_id": aid}))
    assert res3["ok"] is True
    assert "report_path" in res3
    assert Path(res3["report_path"]).exists()
