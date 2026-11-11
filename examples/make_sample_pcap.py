"""
make_sample_pcap.py — Pure Python capture synthesizer.

Generates a realistic demo capture (classic pcap, Little-Endian, microsecond)
using ONLY standard library (struct, random, ipaddress).
No scapy, no pyshark, no external dependencies.

Includes:
- Baseline browsing & DNS for ~10 internal hosts (RFC 1918 192.168.1.0/24)
- RFC 5737 documentation IPs (198.51.100.0/24, 203.0.113.0/24) and example.com domains
- Port scan: 192.168.1.55 scans 192.168.1.20 across 25 ports with mostly RST/no-reply
- Beaconing: 192.168.1.88 connects to 203.0.113.44:8443 every ~30 seconds (12 connections)
- DNS tunneling / high-entropy burst: 192.168.1.99 queries long base32 subdomains under tunnel.example.com
- Traffic spike: Sudden 500 KB burst from 192.168.1.10 to 198.51.100.20
"""

import sys
import struct
import random
import ipaddress
from pathlib import Path


def _ip_to_bytes(ip_str):
    return ipaddress.IPv4Address(ip_str).packed


def _calc_ip_checksum(header):
    if len(header) % 2 == 1:
        header += b'\x00'
    s = sum(struct.unpack(f'!{len(header)//2}H', header))
    while (s >> 16):
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def _build_dns_query(qname, qtype=1, tx_id=0x1234):
    header = struct.pack('!HHHHHH', tx_id, 0x0100, 1, 0, 0, 0)
    qbody = bytearray()
    for part in qname.split('.'):
        p_bytes = part.encode('ascii')
        qbody.append(len(p_bytes))
        qbody.extend(p_bytes)
    qbody.append(0)
    qbody.extend(struct.pack('!HH', qtype, 1))
    return bytes(header + qbody)


def _build_dns_response(qname, ip_resp="198.51.100.1", tx_id=0x1234, rcode=0):
    flags = 0x8180 | (rcode & 0x0F)
    ancount = 1 if rcode == 0 else 0
    header = struct.pack('!HHHHHH', tx_id, flags, 1, ancount, 0, 0)
    qbody = bytearray()
    for part in qname.split('.'):
        p_bytes = part.encode('ascii')
        qbody.append(len(p_bytes))
        qbody.extend(p_bytes)
    qbody.append(0)
    qbody.extend(struct.pack('!HH', 1, 1))

    if rcode == 0:
        # Answer RR: pointer to name (0xc00c), type 1 (A), class 1 (IN), ttl 300, len 4, ip
        answer = struct.pack('!HHHIH', 0xc00c, 1, 1, 300, 4) + _ip_to_bytes(ip_resp)
        return bytes(header + qbody + answer)
    return bytes(header + qbody)


def _build_tls_client_hello(sni_hostname):
    sni_bytes = sni_hostname.encode('ascii')
    # Server Name extension
    sni_ext_data = struct.pack('!H', len(sni_bytes) + 3) + b'\x00' + struct.pack('!H', len(sni_bytes)) + sni_bytes
    extensions = struct.pack('!HH', 0x0000, len(sni_ext_data)) + sni_ext_data

    random_bytes = b'\x01\x02\x03\x04' * 8
    cipher_suites = struct.pack('!HH', 2, 0xc02f)
    compression = b'\x01\x00'

    client_hello = (
        b'\x03\x03' +  # client version TLS 1.2
        random_bytes +
        b'\x00' +      # session ID len
        cipher_suites +
        compression +
        struct.pack('!H', len(extensions)) +
        extensions
    )

    hs_header = struct.pack('!B', 1) + struct.pack('!I', len(client_hello))[1:]  # 3-byte len
    record_payload = hs_header + client_hello
    record = struct.pack('!BHH', 22, 0x0303, len(record_payload)) + record_payload
    return record


def _make_packet(src_ip, dst_ip, src_port, dst_port, proto, payload=b'', tcp_flags=0, seq=1000, ack=0):
    eth = b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00'

    if proto == 6:  # TCP
        data_offset = 5
        tcp_hdr = struct.pack('!HHIIBBHHH',
            src_port, dst_port,
            seq, ack,
            (data_offset << 4), tcp_flags,
            64240, 0, 0
        )
        transport = tcp_hdr + payload
    elif proto == 17:  # UDP
        udp_len = 8 + len(payload)
        transport = struct.pack('!HHHH', src_port, dst_port, udp_len, 0) + payload
    elif proto == 1:  # ICMP echo request
        transport = struct.pack('!BBHHH', 8, 0, 0, 1, 1) + payload
    else:
        transport = payload

    total_len = 20 + len(transport)
    ip_hdr_no_cksum = struct.pack('!BBHHHBBH4s4s',
        0x45, 0, total_len, 0x1234, 0x4000, 64, proto, 0,
        _ip_to_bytes(src_ip), _ip_to_bytes(dst_ip)
    )
    cksum = _calc_ip_checksum(ip_hdr_no_cksum)
    ip_hdr = ip_hdr_no_cksum[:10] + struct.pack('!H', cksum) + ip_hdr_no_cksum[12:]

    return eth + ip_hdr + transport


def generate_sample_pcap(output_path, seed=42):
    """Synthesize sample.pcap with normal traffic + 4 distinct anomalies."""
    rng = random.Random(seed)
    packets = []  # list of (timestamp_sec, raw_bytes)

    base_time = 1700000000.0  # reference epoch
    dns_server = "192.168.1.1"
    internal_hosts = [f"192.168.1.{10 + i}" for i in range(10)]
    public_servers = ["198.51.100.10", "198.51.100.20", "203.0.113.5", "203.0.113.50"]
    domains = ["web.example.com", "api.example.com", "service.example.org", "cdn.example.net"]

    # 1. Normal baseline traffic across 10 internal hosts over 300 seconds
    for host in internal_hosts:
        t = base_time + rng.uniform(0, 10)
        for _ in range(15):
            t += rng.uniform(5, 18)
            domain = rng.choice(domains)
            srv = rng.choice(public_servers)
            txid = rng.randint(1000, 65000)

            # DNS Query & Response
            q_payload = _build_dns_query(domain, tx_id=txid)
            pkt_q = _make_packet(host, dns_server, rng.randint(49152, 65535), 53, 17, q_payload)
            packets.append((t, pkt_q))

            t += 0.005
            r_payload = _build_dns_response(domain, ip_resp=srv, tx_id=txid)
            pkt_r = _make_packet(dns_server, host, 53, rng.randint(49152, 65535), 17, r_payload)
            packets.append((t, pkt_r))

            # HTTP or TLS
            sport = rng.randint(50000, 60000)
            t += 0.01
            # SYN -> SYN-ACK -> ACK
            packets.append((t, _make_packet(host, srv, sport, 443, 6, tcp_flags=0x02)))
            t += 0.015
            packets.append((t, _make_packet(srv, host, 443, sport, 6, tcp_flags=0x12)))
            t += 0.002
            packets.append((t, _make_packet(host, srv, sport, 443, 6, tcp_flags=0x10)))

            # TLS ClientHello with SNI
            t += 0.005
            tls_data = _build_tls_client_hello(domain)
            packets.append((t, _make_packet(host, srv, sport, 443, 6, payload=tls_data, tcp_flags=0x18)))

            # HTTP plain request from some hosts
            if host in internal_hosts[:3]:
                t += 0.02
                http_port = rng.randint(50000, 60000)
                packets.append((t, _make_packet(host, srv, http_port, 80, 6, tcp_flags=0x02)))
                packets.append((t + 0.01, _make_packet(srv, host, 80, http_port, 6, tcp_flags=0x12)))
                http_req = f"GET /status HTTP/1.1\r\nHost: {domain}\r\n\r\n".encode('ascii')
                packets.append((t + 0.02, _make_packet(host, srv, http_port, 80, 6, payload=http_req, tcp_flags=0x18)))

    # 2. Port Scan: 192.168.1.55 scans 192.168.1.20 across 25 ports within 30s
    scan_src = "192.168.1.55"
    scan_dst = "192.168.1.20"
    scan_start = base_time + 40.0
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8000, 8080, 8443, 8888, 9000]
    for i, port in enumerate(scan_ports):
        t_pkt = scan_start + (i * 0.8)
        c_sport = 40000 + i
        # SYN sent
        packets.append((t_pkt, _make_packet(scan_src, scan_dst, c_sport, port, 6, tcp_flags=0x02)))
        # Unsuccessful: target sends RST-ACK or drops
        if port in (80, 443):
            packets.append((t_pkt + 0.005, _make_packet(scan_dst, scan_src, port, c_sport, 6, tcp_flags=0x12)))
            packets.append((t_pkt + 0.010, _make_packet(scan_src, scan_dst, c_sport, port, 6, tcp_flags=0x04)))  # RST
        else:
            packets.append((t_pkt + 0.005, _make_packet(scan_dst, scan_src, port, c_sport, 6, tcp_flags=0x14)))  # RST-ACK

    # 3. Beaconing: 192.168.1.88 connects to 203.0.113.44:8443 every ~30s (10 connections, CV < 0.1)
    beacon_src = "192.168.1.88"
    beacon_dst = "203.0.113.44"
    beacon_time = base_time + 15.0
    for i in range(10):
        t_b = beacon_time + (i * 30.0) + rng.uniform(-0.4, 0.4)
        b_port = 52000 + i
        # SYN -> SYN-ACK -> ACK
        packets.append((t_b, _make_packet(beacon_src, beacon_dst, b_port, 8443, 6, tcp_flags=0x02)))
        packets.append((t_b + 0.02, _make_packet(beacon_dst, beacon_src, 8443, b_port, 6, tcp_flags=0x12)))
        packets.append((t_b + 0.03, _make_packet(beacon_src, beacon_dst, b_port, 8443, 6, tcp_flags=0x10)))
        # Small keepalive data
        packets.append((t_b + 0.05, _make_packet(beacon_src, beacon_dst, b_port, 8443, 6, payload=b'\x17\x03\x03\x00\x20' + b'\xcc'*32, tcp_flags=0x18)))

    # 4. DNS Tunneling-style burst: 192.168.1.99 queries 25 long random subdomains under tunnel.example.com
    dns_tun_src = "192.168.1.99"
    tun_start = base_time + 120.0
    charset = "abcdefghijklmnopqrstuvwxyz0123456789"
    for i in range(25):
        t_d = tun_start + (i * 0.15)
        sub_label = ''.join(rng.choice(charset) for _ in range(48))
        tun_qname = f"{sub_label}.tunnel.example.com"
        txid = 0x5000 + i
        q_data = _build_dns_query(tun_qname, tx_id=txid)
        packets.append((t_d, _make_packet(dns_tun_src, dns_server, 54000 + i, 53, 17, q_data)))
        # Respond with NXDOMAIN (rcode=3)
        r_data = _build_dns_response(tun_qname, tx_id=txid, rcode=3)
        packets.append((t_d + 0.005, _make_packet(dns_server, dns_tun_src, 53, 54000 + i, 17, r_data)))

    # 5. Traffic Spike: 192.168.1.10 bursts ~400 KB to 198.51.100.20 around t = base_time + 210.0
    spike_src = "192.168.1.10"
    spike_dst = "198.51.100.20"
    spike_time = base_time + 210.0
    spike_sport = 49999
    # Handshake
    packets.append((spike_time, _make_packet(spike_src, spike_dst, spike_sport, 443, 6, tcp_flags=0x02)))
    packets.append((spike_time + 0.01, _make_packet(spike_dst, spike_src, 443, spike_sport, 6, tcp_flags=0x12)))
    packets.append((spike_time + 0.02, _make_packet(spike_src, spike_dst, spike_sport, 443, 6, tcp_flags=0x10)))
    # 300 bulk packets of 1400 bytes each = 420 KB within 2 seconds
    chunk = b'\xaa' * 1400
    for j in range(300):
        t_p = spike_time + 0.03 + (j * 0.005)
        packets.append((t_p, _make_packet(spike_src, spike_dst, spike_sport, 443, 6, payload=chunk, tcp_flags=0x10, seq=1000 + j*1400)))

    # Sort packets strictly by timestamp
    packets.sort(key=lambda p: p[0])

    # Write classic pcap file
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, 'wb') as f:
        # Global header: magic(4), v_major(2), v_minor(2), zone(4), sigfigs(4), snaplen(4), linktype(4)
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

        for ts, raw_pkt in packets:
            ts_sec = int(ts)
            ts_usec = int((ts - ts_sec) * 1_000_000)
            caplen = len(raw_pkt)
            origlen = len(raw_pkt)
            hdr = struct.pack('<IIII', ts_sec, ts_usec, caplen, origlen)
            f.write(hdr)
            f.write(raw_pkt)

    print(f"Generated sample capture with {len(packets)} packets at {output_path}")
    return str(out)


if __name__ == '__main__':
    dest = sys.argv[1] if len(sys.argv) > 1 else 'sample.pcap'
    generate_sample_pcap(dest)
