"""
decode.py — Protocol decoder for Ethernet/IP/TCP/UDP/ICMP/ARP packets.

Decodes: 802.1Q VLAN, IPv4 (incl. fragment detection), IPv6 (skip extension
headers), TCP (flags, ports), UDP, ICMP/ICMPv6, ARP. Light app-layer:
DNS (query name, qtype, rcode), TLS ClientHello SNI, HTTP Host, SSH banner.

Never retains payload content beyond protocol metadata.
"""

import struct
import ipaddress

from pcap_reader import (LINKTYPE_ETHERNET, LINKTYPE_RAW_IP,
                         LINKTYPE_LINUX_SLL, LINKTYPE_RAW_IPV4,
                         LINKTYPE_RAW_IPV6)


# Ethernet types
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_IPV6 = 0x86DD

# IP protocols
PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMPV6 = 58

# TCP flags
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20

# IPv6 extension header next-header values to skip
IPV6_EXT_HEADERS = {0, 43, 44, 50, 51, 60, 135, 139, 140}

# Maximum string lengths for sanitized output
MAX_DNS_NAME_LEN = 253
MAX_SNI_LEN = 253
MAX_HTTP_HOST_LEN = 253
MAX_BANNER_LEN = 120


class DecodedPacket:
    """Decoded protocol information from a single packet."""
    __slots__ = (
        'timestamp', 'captured_len', 'original_len',
        'src_mac', 'dst_mac', 'vlan_id',
        'ethertype', 'ip_version',
        'src_ip', 'dst_ip', 'ip_proto', 'ttl',
        'is_fragment', 'frag_offset', 'frag_id',
        'src_port', 'dst_port', 'tcp_flags', 'payload_len',
        'protocol_name',
        'dns_query', 'dns_qtype', 'dns_rcode', 'dns_is_response',
        'tls_sni', 'http_host', 'ssh_banner',
        'arp_op', 'arp_sender_ip', 'arp_target_ip',
        'icmp_type', 'icmp_code',
        'decode_errors',
    )

    def __init__(self):
        self.timestamp = 0.0
        self.captured_len = 0
        self.original_len = 0
        self.src_mac = None
        self.dst_mac = None
        self.vlan_id = None
        self.ethertype = None
        self.ip_version = None
        self.src_ip = None
        self.dst_ip = None
        self.ip_proto = None
        self.ttl = None
        self.is_fragment = False
        self.frag_offset = 0
        self.frag_id = None
        self.src_port = None
        self.dst_port = None
        self.tcp_flags = None
        self.payload_len = 0
        self.protocol_name = 'unknown'
        self.dns_query = None
        self.dns_qtype = None
        self.dns_rcode = None
        self.dns_is_response = None
        self.tls_sni = None
        self.http_host = None
        self.ssh_banner = None
        self.arp_op = None
        self.arp_sender_ip = None
        self.arp_target_ip = None
        self.icmp_type = None
        self.icmp_code = None
        self.decode_errors = []


def _sanitize_string(s, max_len=120):
    """Strip control chars and truncate a string from capture data."""
    if not s:
        return s
    # Strip control characters (keep printable ASCII + common UTF-8)
    cleaned = ''.join(c for c in s if ord(c) >= 32 and ord(c) != 127)
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len]
    return cleaned


def _parse_mac(data, offset):
    """Parse a 6-byte MAC address."""
    if offset + 6 > len(data):
        return None
    return ':'.join(f'{b:02x}' for b in data[offset:offset+6])


def _decode_dns_name(data, offset, max_jumps=10):
    """Decode a DNS name from wire format with compression pointer support."""
    parts = []
    jumps = 0
    original_offset = None

    while offset < len(data) and jumps < max_jumps:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            # Compression pointer
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if original_offset is None:
                original_offset = offset + 2
            offset = pointer
            jumps += 1
            continue
        offset += 1
        if offset + length > len(data):
            break
        try:
            parts.append(data[offset:offset+length].decode('ascii', errors='replace'))
        except Exception:
            parts.append('?')
        offset += length

    name = '.'.join(parts)
    final_offset = original_offset if original_offset is not None else offset
    return name, final_offset


def _decode_dns(data, pkt):
    """Decode DNS query/response."""
    if len(data) < 12:
        return

    try:
        flags = struct.unpack('!H', data[2:4])[0]
        qdcount = struct.unpack('!H', data[4:6])[0]
        pkt.dns_is_response = bool(flags & 0x8000)
        pkt.dns_rcode = flags & 0x000F

        if qdcount >= 1:
            qname, offset = _decode_dns_name(data, 12)
            pkt.dns_query = _sanitize_string(qname, MAX_DNS_NAME_LEN)
            if offset + 4 <= len(data):
                pkt.dns_qtype = struct.unpack('!H', data[offset:offset+2])[0]
    except Exception:
        pass


def _decode_tls_sni(data, pkt):
    """Extract SNI from TLS ClientHello."""
    if len(data) < 6:
        return

    try:
        # TLS record: content_type(1), version(2), length(2)
        content_type = data[0]
        if content_type != 22:   # Handshake
            return

        # Handshake header: type(1), length(3)
        if len(data) < 10:
            return
        hs_type = data[5]
        if hs_type != 1:   # ClientHello
            return

        # Skip to extensions
        offset = 5 + 4   # record header + handshake type + length
        # client_version(2) + random(32)
        offset += 2 + 32
        if offset >= len(data):
            return

        # session_id
        sid_len = data[offset]
        offset += 1 + sid_len
        if offset + 2 > len(data):
            return

        # cipher_suites
        cs_len = struct.unpack('!H', data[offset:offset+2])[0]
        offset += 2 + cs_len
        if offset >= len(data):
            return

        # compression_methods
        cm_len = data[offset]
        offset += 1 + cm_len
        if offset + 2 > len(data):
            return

        # Extensions
        ext_len = struct.unpack('!H', data[offset:offset+2])[0]
        offset += 2
        ext_end = offset + ext_len

        while offset + 4 <= ext_end and offset + 4 <= len(data):
            ext_type = struct.unpack('!H', data[offset:offset+2])[0]
            ext_data_len = struct.unpack('!H', data[offset+2:offset+4])[0]
            offset += 4

            if ext_type == 0 and ext_data_len > 2:   # server_name
                # SNI list length(2)
                if offset + 2 > len(data):
                    break
                sni_list_len = struct.unpack('!H', data[offset:offset+2])[0]
                pos = offset + 2
                sni_end = pos + sni_list_len

                while pos + 3 <= sni_end and pos + 3 <= len(data):
                    name_type = data[pos]
                    name_len = struct.unpack('!H', data[pos+1:pos+3])[0]
                    pos += 3
                    if name_type == 0 and pos + name_len <= len(data):
                        try:
                            sni = data[pos:pos+name_len].decode('ascii', errors='replace')
                            pkt.tls_sni = _sanitize_string(sni, MAX_SNI_LEN)
                        except Exception:
                            pass
                        return
                    pos += name_len
                return

            offset += ext_data_len
    except Exception:
        pass


def _decode_http_host(data, pkt):
    """Extract Host header from HTTP request."""
    try:
        # Quick check for HTTP method
        if not (data[:4] in (b'GET ', b'POST', b'PUT ', b'HEAD')
                or data[:5] in (b'PATCH', b'DELET')
                or data[:7] == b'OPTIONS'
                or data[:5] == b'CONNE'):
            return

        # Find Host header
        header_end = data.find(b'\r\n\r\n')
        if header_end == -1:
            header_end = min(len(data), 2048)
        else:
            header_end = min(header_end, 2048)

        headers = data[:header_end]
        for line in headers.split(b'\r\n'):
            lower = line.lower()
            if lower.startswith(b'host:'):
                host = line[5:].strip()
                try:
                    pkt.http_host = _sanitize_string(
                        host.decode('ascii', errors='replace'), MAX_HTTP_HOST_LEN)
                except Exception:
                    pass
                return
    except Exception:
        pass


def _decode_ssh_banner(data, pkt):
    """Extract SSH banner."""
    try:
        if data[:4] == b'SSH-':
            end = data.find(b'\r\n')
            if end == -1:
                end = data.find(b'\n')
            if end == -1:
                end = min(len(data), MAX_BANNER_LEN)
            banner = data[:end]
            pkt.ssh_banner = _sanitize_string(
                banner.decode('ascii', errors='replace'), MAX_BANNER_LEN)
    except Exception:
        pass


def _decode_ipv4(data, pkt):
    """Decode IPv4 header and transport layer."""
    if len(data) < 20:
        pkt.decode_errors.append("IPv4 header too short")
        return

    version_ihl = data[0]
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or ihl > len(data):
        pkt.decode_errors.append(f"Invalid IHL: {ihl}")
        return

    pkt.ip_version = 4
    total_len = struct.unpack('!H', data[2:4])[0]
    pkt.frag_id = struct.unpack('!H', data[4:6])[0]

    flags_frag = struct.unpack('!H', data[6:8])[0]
    pkt.frag_offset = (flags_frag & 0x1FFF) * 8
    mf = bool(flags_frag & 0x2000)
    pkt.is_fragment = (pkt.frag_offset > 0) or mf

    pkt.ttl = data[8]
    pkt.ip_proto = data[9]

    try:
        pkt.src_ip = str(ipaddress.IPv4Address(data[12:16]))
        pkt.dst_ip = str(ipaddress.IPv4Address(data[16:20]))
    except Exception:
        pkt.decode_errors.append("Invalid IPv4 address")
        return

    transport_data = data[ihl:]
    _decode_transport(transport_data, pkt)


def _decode_ipv6(data, pkt):
    """Decode IPv6 header (skip extension headers safely)."""
    if len(data) < 40:
        pkt.decode_errors.append("IPv6 header too short")
        return

    pkt.ip_version = 6
    # payload_length = struct.unpack('!H', data[4:6])[0]
    next_header = data[6]
    pkt.ttl = data[7]   # hop limit

    try:
        pkt.src_ip = str(ipaddress.IPv6Address(data[8:24]))
        pkt.dst_ip = str(ipaddress.IPv6Address(data[24:40]))
    except Exception:
        pkt.decode_errors.append("Invalid IPv6 address")
        return

    offset = 40
    # Skip extension headers
    max_extensions = 10
    for _ in range(max_extensions):
        if next_header not in IPV6_EXT_HEADERS:
            break
        if offset + 2 > len(data):
            pkt.decode_errors.append("Truncated IPv6 extension header")
            return
        next_header = data[offset]
        ext_len = (data[offset + 1] + 1) * 8
        offset += ext_len

    pkt.ip_proto = next_header
    transport_data = data[offset:]
    _decode_transport(transport_data, pkt)


def _decode_transport(data, pkt):
    """Decode transport layer (TCP/UDP/ICMP)."""
    if pkt.is_fragment and pkt.frag_offset > 0:
        # Not the first fragment — no transport header
        pkt.protocol_name = 'IPv4-fragment'
        return

    if pkt.ip_proto == PROTO_TCP:
        _decode_tcp(data, pkt)
    elif pkt.ip_proto == PROTO_UDP:
        _decode_udp(data, pkt)
    elif pkt.ip_proto == PROTO_ICMP:
        _decode_icmp(data, pkt)
    elif pkt.ip_proto == PROTO_ICMPV6:
        _decode_icmpv6(data, pkt)
    else:
        pkt.protocol_name = f'IP-proto-{pkt.ip_proto}'


def _decode_tcp(data, pkt):
    """Decode TCP header."""
    if len(data) < 20:
        pkt.protocol_name = 'TCP'
        pkt.decode_errors.append("TCP header too short")
        return

    pkt.src_port = struct.unpack('!H', data[0:2])[0]
    pkt.dst_port = struct.unpack('!H', data[2:4])[0]
    data_offset = ((data[12] >> 4) & 0xF) * 4
    pkt.tcp_flags = data[13]
    pkt.payload_len = max(0, len(data) - data_offset) if data_offset <= len(data) else 0

    # Determine protocol name based on ports
    ports = {pkt.src_port, pkt.dst_port}
    if ports & {80, 8080, 8000, 8888}:
        pkt.protocol_name = 'HTTP'
        if pkt.payload_len > 0:
            _decode_http_host(data[data_offset:], pkt)
    elif ports & {443, 8443}:
        pkt.protocol_name = 'TLS'
        if pkt.payload_len > 0 and (pkt.tcp_flags & TCP_SYN) == 0:
            _decode_tls_sni(data[data_offset:], pkt)
    elif ports & {22}:
        pkt.protocol_name = 'SSH'
        if pkt.payload_len > 0:
            _decode_ssh_banner(data[data_offset:], pkt)
    elif ports & {23}:
        pkt.protocol_name = 'Telnet'
    elif ports & {21, 20}:
        pkt.protocol_name = 'FTP'
    elif ports & {53, 5353}:
        pkt.protocol_name = 'DNS'
        if pkt.payload_len > 0:
            _decode_dns(data[data_offset:], pkt)
    elif ports & {25, 587, 465}:
        pkt.protocol_name = 'SMTP'
    elif ports & {143, 993}:
        pkt.protocol_name = 'IMAP'
    elif ports & {110, 995}:
        pkt.protocol_name = 'POP3'
    else:
        pkt.protocol_name = 'TCP'


def _decode_udp(data, pkt):
    """Decode UDP header."""
    if len(data) < 8:
        pkt.protocol_name = 'UDP'
        pkt.decode_errors.append("UDP header too short")
        return

    pkt.src_port = struct.unpack('!H', data[0:2])[0]
    pkt.dst_port = struct.unpack('!H', data[2:4])[0]
    udp_len = struct.unpack('!H', data[4:6])[0]
    pkt.payload_len = max(0, udp_len - 8)

    ports = {pkt.src_port, pkt.dst_port}
    if ports & {53, 5353}:
        pkt.protocol_name = 'DNS'
        if pkt.payload_len > 0:
            _decode_dns(data[8:], pkt)
    elif ports & {67, 68}:
        pkt.protocol_name = 'DHCP'
    elif ports & {123}:
        pkt.protocol_name = 'NTP'
    elif ports & {161, 162}:
        pkt.protocol_name = 'SNMP'
    elif ports & {443}:
        pkt.protocol_name = 'QUIC'
    elif ports & {1900}:
        pkt.protocol_name = 'SSDP'
    else:
        pkt.protocol_name = 'UDP'


def _decode_icmp(data, pkt):
    """Decode ICMP header."""
    pkt.protocol_name = 'ICMP'
    if len(data) < 4:
        pkt.decode_errors.append("ICMP header too short")
        return
    pkt.icmp_type = data[0]
    pkt.icmp_code = data[1]


def _decode_icmpv6(data, pkt):
    """Decode ICMPv6 header."""
    pkt.protocol_name = 'ICMPv6'
    if len(data) < 4:
        pkt.decode_errors.append("ICMPv6 header too short")
        return
    pkt.icmp_type = data[0]
    pkt.icmp_code = data[1]


def _decode_arp(data, pkt):
    """Decode ARP packet."""
    pkt.protocol_name = 'ARP'
    if len(data) < 28:
        pkt.decode_errors.append("ARP packet too short")
        return

    try:
        pkt.arp_op = struct.unpack('!H', data[6:8])[0]
        pkt.arp_sender_ip = str(ipaddress.IPv4Address(data[14:18]))
        pkt.arp_target_ip = str(ipaddress.IPv4Address(data[24:28]))
    except Exception:
        pkt.decode_errors.append("Invalid ARP data")


def decode_packet(raw_packet):
    """Decode a raw packet from pcap_reader.Packet to DecodedPacket.

    Args:
        raw_packet: A pcap_reader.Packet object.

    Returns:
        A DecodedPacket with all decoded fields populated.
        Never raises — decode errors are captured in decode_errors list.
    """
    pkt = DecodedPacket()
    pkt.timestamp = raw_packet.timestamp
    pkt.captured_len = raw_packet.captured_len
    pkt.original_len = raw_packet.original_len

    data = raw_packet.data
    if not data:
        pkt.decode_errors.append("Empty packet data")
        return pkt

    try:
        link_type = raw_packet.link_type

        if link_type == LINKTYPE_ETHERNET:
            _decode_ethernet(data, pkt)
        elif link_type == LINKTYPE_LINUX_SLL:
            _decode_linux_sll(data, pkt)
        elif link_type == LINKTYPE_RAW_IP:
            _decode_raw_ip(data, pkt)
        elif link_type == LINKTYPE_RAW_IPV4:
            _decode_ipv4(data, pkt)
        elif link_type == LINKTYPE_RAW_IPV6:
            _decode_ipv6(data, pkt)
        else:
            pkt.decode_errors.append(f"Unsupported link type: {link_type}")
    except Exception as e:
        pkt.decode_errors.append(f"Decode exception: {e}")

    return pkt


def _decode_ethernet(data, pkt):
    """Decode Ethernet frame."""
    if len(data) < 14:
        pkt.decode_errors.append("Ethernet frame too short")
        return

    pkt.dst_mac = _parse_mac(data, 0)
    pkt.src_mac = _parse_mac(data, 6)
    ethertype = struct.unpack('!H', data[12:14])[0]
    offset = 14

    # Handle VLAN tags
    while ethertype == ETHERTYPE_VLAN:
        if offset + 4 > len(data):
            pkt.decode_errors.append("Truncated VLAN tag")
            return
        tci = struct.unpack('!H', data[offset:offset+2])[0]
        pkt.vlan_id = tci & 0x0FFF
        ethertype = struct.unpack('!H', data[offset+2:offset+4])[0]
        offset += 4

    pkt.ethertype = ethertype

    if ethertype == ETHERTYPE_IPV4:
        _decode_ipv4(data[offset:], pkt)
    elif ethertype == ETHERTYPE_IPV6:
        _decode_ipv6(data[offset:], pkt)
    elif ethertype == ETHERTYPE_ARP:
        _decode_arp(data[offset:], pkt)
    else:
        pkt.protocol_name = f'Ether-0x{ethertype:04x}'


def _decode_linux_sll(data, pkt):
    """Decode Linux cooked capture (SLL)."""
    if len(data) < 16:
        pkt.decode_errors.append("SLL header too short")
        return

    protocol = struct.unpack('!H', data[14:16])[0]
    payload = data[16:]

    if protocol == ETHERTYPE_IPV4:
        _decode_ipv4(payload, pkt)
    elif protocol == ETHERTYPE_IPV6:
        _decode_ipv6(payload, pkt)
    elif protocol == ETHERTYPE_ARP:
        _decode_arp(payload, pkt)
    else:
        pkt.protocol_name = f'SLL-0x{protocol:04x}'


def _decode_raw_ip(data, pkt):
    """Decode raw IP (link type 101) — could be IPv4 or IPv6."""
    if len(data) < 1:
        pkt.decode_errors.append("Empty raw IP packet")
        return

    version = (data[0] >> 4) & 0x0F
    if version == 4:
        _decode_ipv4(data, pkt)
    elif version == 6:
        _decode_ipv6(data, pkt)
    else:
        pkt.protocol_name = f'RawIP-v{version}'

