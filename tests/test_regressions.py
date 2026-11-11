"""Behavioral regressions for hostile captures, accurate findings and host loading."""
import importlib.util
import json
import random
import struct
import sys
from pathlib import Path

import pytest
from analyze import analyze_packets, query_analysis
from decode import DecodedPacket, decode_packet, _decode_dns_name
from examples.make_sample_pcap import _make_packet, _build_dns_query, _build_tls_client_hello
from heuristics import detect_port_scan, detect_beaconing
from pcap_reader import Packet, PcapError, read_pcap
from report import _build_report_data, generate_report
from tools import handle_analyze, handle_query, handle_visualize
from main import register
from test_netscope import FakePluginContext, _create_minimal_pcap


def block(kind, body, endian='<'):
    length = len(body) + 12
    return struct.pack(endian + 'II', kind, length) + body + struct.pack(endian + 'I', length)


def section(endian='<'):
    return block(0x0a0d0d0a, struct.pack(endian + 'IHHq', 0x1a2b3c4d, 1, 0, -1), endian)


def interface(endian='<', snaplen=65535, opts=b''):
    return block(1, struct.pack(endian + 'HHI', 1, 0, snaplen) + opts, endian)


def enhanced(data=b'x' * 40, endian='<', iface=0, caplen=None):
    size = len(data) if caplen is None else caplen
    return block(6, struct.pack(endian + 'IIIII', iface, 0, 1000000, size, size) + data + b'\0' * (-len(data) % 4), endian)


def read_bytes(tmp_path, data, **kwargs):
    path = tmp_path / 'input.pcap'
    path.write_bytes(data)
    return read_pcap(path, **kwargs)


@pytest.mark.parametrize('value', [0, -1, True, 1.5, '10', 2000001])
def test_reject_invalid_packet_limits(tmp_path, value):
    with pytest.raises(PcapError, match='max_packets'):
        read_bytes(tmp_path, b'bad!', max_packets=value)


@pytest.mark.parametrize('field', ['time_budget', 'max_file_size'])
@pytest.mark.parametrize('value', [0, -1, True, float('nan'), float('inf')])
def test_reject_invalid_resource_limits(tmp_path, field, value):
    with pytest.raises(PcapError, match=field):
        read_bytes(tmp_path, b'bad!', **{field: value})


def test_packet_limit_exact_eof_is_not_truncated(tmp_path):
    path = tmp_path / 'one.pcap'
    _create_minimal_pcap(path, packets=[(1, 0, b'x')])
    assert not read_pcap(path, max_packets=1).truncated
    assert not read_bytes(tmp_path, section() + interface() + enhanced(), max_packets=1).truncated


@pytest.mark.parametrize('data', [
    section() + interface() + enhanced(iface=1),
    section() + interface() + enhanced(caplen=100),
    section() + interface() + enhanced()[:-4] + b'xxxx',
    section()[:8] + b'xxxx' + section()[12:],
    section() + struct.pack('<II', 6, 0xffffffff),
    section() + block(1, b'bad!'),
    section() + block(3, b'\0' * 4),
])
def test_pcapng_malformed_blocks_are_visible(tmp_path, data):
    result = read_bytes(tmp_path, data)
    assert result.truncated and result.errors
    assert not result.packets


def test_pcapng_multiple_sections_offsets_and_simple_padding(tmp_path):
    opts = struct.pack('>HHq', 14, 8, -10) + struct.pack('>HHB3x', 9, 1, 0x8a)
    spb = block(3, struct.pack('<I', 3) + b'abc\0')
    data = section() + interface() + spb + section('>') + interface('>', opts=opts) + enhanced(endian='>')
    result = read_bytes(tmp_path, data)
    assert not result.errors
    assert result.packets[0].data == b'abc'
    assert result.packets[0].timestamp is None
    assert result.packets[1].timestamp == pytest.approx(1000000 / 1024 - 10)


def decode(data, timestamp=1):
    return decode_packet(Packet(timestamp, len(data), len(data), data, 1))


def ipv6(payload, next_header):
    header = struct.pack('!IHBB16s16s', 6 << 28, len(payload), next_header, 64, b'\x20\x01' + b'\0' * 14, b'\x20\x02' + b'\0' * 14)
    return b'\0' * 12 + b'\x86\xdd' + header + payload


def test_ipv6_noninitial_fragment_is_not_tcp():
    p = decode(ipv6(struct.pack('!BBHI', 6, 0, 9, 123) + b'x' * 32, 44))
    assert p.is_fragment and p.frag_offset == 8
    assert p.protocol_name == 'IPv6-fragment' and p.src_port is None


def test_ipv6_auth_header_and_esp():
    udp = struct.pack('!HHHH', 123, 123, 8, 0)
    p = decode(ipv6(struct.pack('!BB10x', 17, 1) + udp, 51))
    assert p.protocol_name == 'NTP'
    p = decode(ipv6(b'x' * 32, 50))
    assert p.src_port is None and p.ip_proto == 50


def test_ipv4_padding_cannot_invent_http_host():
    data = _make_packet('10.0.0.1', '10.0.0.2', 12345, 80, 6, tcp_flags=16)
    p = decode(data + b'GET / HTTP/1.1\r\nHost: forged.example\r\n\r\n')
    assert p.http_host is None and p.payload_len == 0


def test_dns_over_tcp_length_prefix():
    dns = _build_dns_query('test.example')
    p = decode(_make_packet('10.0.0.1', '10.0.0.2', 40000, 53, 6, struct.pack('!H', len(dns)) + dns))
    assert p.dns_query == 'test.example'


def test_tcp_and_udp_declared_lengths_are_enforced():
    data = bytearray(_make_packet('10.0.0.1', '10.0.0.2', 12345, 80, 6))
    data[46] = 0  # TCP data offset
    assert 'Invalid TCP data offset' in decode(bytes(data)).decode_errors
    dns = _build_dns_query('forged.example')
    data = bytearray(_make_packet('10.0.0.1', '10.0.0.2', 40000, 53, 17, dns))
    data[38:40] = struct.pack('!H', 8)
    assert decode(bytes(data)).dns_query is None


def test_tls_sni_cannot_read_past_declared_record():
    hello = bytearray(_build_tls_client_hello('test.example'))
    hello[3:5] = b'\x00\x04'
    p = decode(_make_packet('10.0.0.1', '10.0.0.2', 40000, 443, 6, bytes(hello)))
    assert p.tls_sni is None


def test_dns_compression_cycles_are_rejected():
    assert _decode_dns_name(b'\xc0\x00', 0)[0] == ''


def test_successful_connections_do_not_look_like_scan():
    packets = []
    for port in range(20, 45):
        packets.append(decode(_make_packet('10.0.0.1', '10.0.0.2', 40000, port, 6, tcp_flags=2), port))
        packets.append(decode(_make_packet('10.0.0.2', '10.0.0.1', port, 40000, 6, tcp_flags=18), port + .01))
    assert not detect_port_scan(analyze_packets(list(reversed(packets))))


def test_beacon_reusing_same_tuple():
    packets = [decode(_make_packet('10.0.0.1', '10.0.0.2', 40000, 4444, 6, tcp_flags=2), i * 30) for i in range(10)]
    assert detect_beaconing(analyze_packets(packets))


@pytest.mark.parametrize('timestamps', [[0], [0, 1], [5, 5], [0, 20000000]])
def test_timeline_preserves_all_packets(timestamps):
    packets = []
    for ts in timestamps:
        p = DecodedPacket();p.timestamp = ts;p.original_len = 100
        packets.append(p)
    result = analyze_packets(packets)
    assert sum(b['packets'] for b in result.timeline_buckets) == len(packets)
    assert len(result.timeline_buckets) <= 500


@pytest.mark.parametrize('kwargs', [{'n': -1}, {'n': True}, {'n': 1001}, {'by': 'bogus'}])
def test_query_validation(kwargs):
    assert 'error' in query_analysis(analyze_packets([]), 'top_talkers', **kwargs)


def test_window_overlap_and_invalid_bounds():
    p = DecodedPacket();p.timestamp = 10;p.original_len = 100
    result = analyze_packets([p])
    assert query_analysis(result, 'time_window', start=10.01, end=10.02)['buckets']
    assert 'error' in query_analysis(result, 'time_window', start=20, end=10)
    assert 'error' in query_analysis(result, 'time_window', start=float('nan'))


def test_report_filter_contract():
    p = DecodedPacket();p.timestamp = 10;p.protocol_name = 'TCP'
    result = analyze_packets([p])
    data = _build_report_data(result, [], protocol_filter='TCP', time_start=10)
    assert data['initial_protocol'] == 'TCP' and data['initial_window'] == [10, None]
    with pytest.raises(ValueError):
        _build_report_data(result, [], protocol_filter='NONEXISTENT')
    with pytest.raises(ValueError):
        _build_report_data(result, [], time_start=20, time_end=10)


def test_hostile_capture_strings_never_break_script(tmp_path):
    p = decode(_make_packet('10.0.0.1', '10.0.0.2', 40000, 80, 6, b'GET / HTTP/1.1\r\nHost: </script><script>window.pwned=1</script>\r\n\r\n'))
    path = tmp_path / 'hostile.html'
    generate_report(analyze_packets([p]), [], path)
    content = path.read_text()
    assert '</script><script>window.pwned' not in content
    assert '\\u003c/script\\u003e' in content


def test_package_loading_ignores_unrelated_top_level_modules():
    root = Path(__file__).resolve().parents[1]
    name = 'netscope_test_package'
    spec = importlib.util.spec_from_file_location(name, root / '__init__.py', submodule_search_locations=[str(root)])
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
        ctx = FakePluginContext();module.register(ctx)
        assert len(ctx.tools) == 3
        assert sys.modules[name + '.decode'] is not sys.modules['decode']
    finally:
        for key in list(sys.modules):
            if key == name or key.startswith(name + '.'):
                del sys.modules[key]


def test_slash_command_quoted_paths_and_report_failures(tmp_path, monkeypatch):
    path = tmp_path / 'capture with spaces.pcap'
    _create_minimal_pcap(path, packets=[(1, 0, b'x')])
    ctx = FakePluginContext();register(ctx)
    command = ctx.commands['netscope']['handler']
    monkeypatch.setenv('HERMES_HOME', str(tmp_path))
    assert 'Interactive Report:' in command(f'"{path}"')
    monkeypatch.setattr('main.handle_visualize', lambda _: json.dumps({'ok': False, 'error': 'disk full'}))
    output = command(str(path))
    assert 'Report generation failed: disk full' in output
    assert 'Interactive Report:' not in output


def test_handlers_return_json_errors_for_invalid_input():
    assert not json.loads(handle_analyze(None))['ok']
    assert not json.loads(handle_query([], 'findings'))['ok']
    assert not json.loads(handle_visualize('missing'))['ok']


def test_seeded_random_decoder_corpus():
    rng = random.Random(827)
    for lt in [1, 101, 113, 228, 229]:
        for _ in range(200):
            size = rng.randrange(512)
            data = bytes(rng.randrange(256) for _ in range(size))
            p = decode_packet(Packet(1, size, size, data, lt))
            assert isinstance(p, DecodedPacket)


def test_report_atomic_write_does_not_follow_symlink(tmp_path):
    target = tmp_path / 'original.txt';target.write_text('preserve')
    output = tmp_path / 'report.html'
    try:
        output.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip('Symlink creation unavailable')
    generate_report(analyze_packets([]), [], output)
    assert target.read_text() == 'preserve'
    assert not output.is_symlink()
    assert '<!DOCTYPE html>' in output.read_text()
    if sys.platform != 'win32':
        assert output.stat().st_mode & 0o077 == 0


def test_partial_capture_errors_survive_tool_boundary(tmp_path):
    path = tmp_path / 'invalid.pcapng'
    path.write_bytes(section() + interface() + enhanced(caplen=100))
    result = json.loads(handle_analyze(str(path)))
    assert result['ok'] and result['truncated'] and result['errors']


def test_decode_errors_are_visible_in_summary():
    result = analyze_packets([decode(b'invalid')])
    assert result.summary_dict()['decode_error_packets'] == 1


@pytest.mark.parametrize('timestamps', [[-20, -10], [-10, 0]])
def test_signed_timestamp_offsets_keep_duration(timestamps):
    packets = [decode(_make_packet('10.0.0.1', '10.0.0.2', 40000, 443, 6), t) for t in timestamps]
    result = analyze_packets(packets)
    assert result.capture_duration == 10
    assert sum(b['packets'] for b in result.timeline_buckets) == 2
    assert result.hosts['10.0.0.1'].last_seen == timestamps[-1]


def test_empty_capture_window_is_empty():
    assert query_analysis(analyze_packets([]), 'time_window')['buckets'] == []


def test_scan_rst_explanation_counts_response_direction():
    packets = []
    for port in range(100, 120):
        packets += [decode(_make_packet('10.0.0.1', '10.0.0.2', 40000, port, 6, tcp_flags=2), port),
                    decode(_make_packet('10.0.0.2', '10.0.0.1', port, 40000, 6, tcp_flags=20), port + .01)]
    findings = detect_port_scan(analyze_packets(packets))
    assert len(findings) == 1
    assert '20 RST packets observed' in findings[0]['why']
