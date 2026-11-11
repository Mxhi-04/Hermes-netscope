"""
analyze.py — Network capture analysis engine.

Builds host/flow/protocol/timeline aggregations from decoded packets.
All analysis is deterministic and stateless.
"""

import ipaddress
import math
from collections import defaultdict


def _is_private_ip(ip_str):
    """Check if an IP address is private/reserved."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_reserved or addr.is_loopback or addr.is_link_local
    except (ValueError, TypeError):
        return False


def _auto_bucket_size(duration_sec):
    """Select a bucket size to produce ~120-300 buckets."""
    if duration_sec <= 0:
        return 1.0
    # Target ~200 buckets
    # Snap to nice intervals
    nice = [0.1, 0.25, 0.5, 1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600]
    for n in nice:
        if duration_sec / n <= 300:
            return n
    return nice[-1]


class HostStats:
    """Per-host traffic statistics."""
    __slots__ = ('ip', 'bytes_in', 'bytes_out', 'packets_in', 'packets_out',
                 'first_seen', 'last_seen', 'dns_names', 'sni_names',
                 'is_private', 'protocols', 'peers')

    def __init__(self, ip):
        self.ip = ip
        self.bytes_in = 0
        self.bytes_out = 0
        self.packets_in = 0
        self.packets_out = 0
        self.first_seen = float('inf')
        self.last_seen = 0.0
        self.dns_names = set()
        self.sni_names = set()
        self.is_private = _is_private_ip(ip)
        self.protocols = defaultdict(int)   # protocol -> packet count
        self.peers = set()

    @property
    def total_bytes(self):
        return self.bytes_in + self.bytes_out

    @property
    def total_packets(self):
        return self.packets_in + self.packets_out

    def to_dict(self):
        return {
            'ip': self.ip,
            'bytes_in': self.bytes_in,
            'bytes_out': self.bytes_out,
            'packets_in': self.packets_in,
            'packets_out': self.packets_out,
            'total_bytes': self.total_bytes,
            'total_packets': self.total_packets,
            'first_seen': self.first_seen if self.first_seen != float('inf') else 0,
            'last_seen': self.last_seen,
            'dns_names': sorted(self.dns_names)[:20],
            'sni_names': sorted(self.sni_names)[:20],
            'is_private': self.is_private,
            'role': 'internal' if self.is_private else 'external',
            'protocols': dict(self.protocols),
            'peer_count': len(self.peers),
        }


class FlowKey:
    """5-tuple flow key."""
    __slots__ = ('src_ip', 'dst_ip', 'src_port', 'dst_port', 'proto')

    def __init__(self, src_ip, dst_ip, src_port, dst_port, proto):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto = proto

    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.proto))

    def __eq__(self, other):
        return (self.src_ip == other.src_ip and self.dst_ip == other.dst_ip and
                self.src_port == other.src_port and self.dst_port == other.dst_port and
                self.proto == other.proto)


class FlowStats:
    """Per-flow statistics."""
    __slots__ = ('key', 'bytes_total', 'packets', 'first_seen', 'last_seen',
                 'syn_seen', 'syn_ack_seen', 'rst_count', 'protocol_name', 'syn_starts')

    def __init__(self, key):
        self.key = key
        self.bytes_total = 0
        self.packets = 0
        self.first_seen = float('inf')
        self.last_seen = 0.0
        self.syn_seen = False
        self.syn_ack_seen = False
        self.rst_count = 0
        self.protocol_name = 'unknown'
        self.syn_starts = []

    def to_dict(self):
        return {
            'src_ip': self.key.src_ip,
            'dst_ip': self.key.dst_ip,
            'src_port': self.key.src_port,
            'dst_port': self.key.dst_port,
            'proto': self.key.proto,
            'bytes': self.bytes_total,
            'packets': self.packets,
            'first_seen': self.first_seen if self.first_seen != float('inf') else 0,
            'last_seen': self.last_seen,
            'syn_seen': self.syn_seen,
            'syn_ack_seen': self.syn_ack_seen,
            'rst_count': self.rst_count,
            'protocol_name': self.protocol_name,
        }


class ConversationKey:
    """Bidirectional conversation key (IP pair)."""
    __slots__ = ('ip_a', 'ip_b')

    def __init__(self, ip1, ip2):
        self.ip_a, self.ip_b = (ip1, ip2) if ip1 <= ip2 else (ip2, ip1)

    def __hash__(self):
        return hash((self.ip_a, self.ip_b))

    def __eq__(self, other):
        return self.ip_a == other.ip_a and self.ip_b == other.ip_b


class ConversationStats:
    """Bidirectional conversation statistics."""
    __slots__ = ('key', 'bytes_total', 'packets', 'protocols', 'first_seen', 'last_seen')

    def __init__(self, key):
        self.key = key
        self.bytes_total = 0
        self.packets = 0
        self.protocols = defaultdict(int)
        self.first_seen = float('inf')
        self.last_seen = 0.0

    def to_dict(self):
        return {
            'ip_a': self.key.ip_a,
            'ip_b': self.key.ip_b,
            'bytes': self.bytes_total,
            'packets': self.packets,
            'protocols': dict(self.protocols),
            'first_seen': self.first_seen if self.first_seen != float('inf') else 0,
            'last_seen': self.last_seen,
        }


class AnalysisResult:
    """Complete analysis result."""

    def __init__(self):
        self.total_packets = 0
        self.total_bytes = 0
        self.capture_start = float('inf')
        self.capture_end = 0.0
        self.hosts = {}                  # ip -> HostStats
        self.flows = {}                  # FlowKey -> FlowStats
        self.conversations = {}          # ConversationKey -> ConversationStats
        self.protocol_counts = defaultdict(int)
        self.protocol_bytes = defaultdict(int)
        self.timeline_buckets = []       # list of bucket dicts
        self.bucket_size = 1.0
        self.fragment_count = 0
        self.decode_error_packets = 0
        self.dns_queries = []            # (timestamp, query_name, qtype, rcode, src_ip)
        self.truncated = False
        self.truncation_reason = None
        self.unsupported_packets = 0
        self.errors = []
        self.file_format = None
        self.file_size = 0
        self.parse_duration = 0.0

    @property
    def capture_duration(self):
        if self.capture_start == float('inf'):
            return 0.0
        return self.capture_end - self.capture_start

    @property
    def host_count(self):
        return len(self.hosts)

    @property
    def flow_count(self):
        return len(self.flows)

    def summary_dict(self):
        """Compact summary for tool output."""
        top_talkers = sorted(self.hosts.values(),
                             key=lambda h: h.total_bytes, reverse=True)[:10]

        proto_list = sorted(self.protocol_counts.items(),
                            key=lambda x: x[1], reverse=True)

        return {
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'capture_start': self.capture_start if self.capture_start != float('inf') else 0,
            'capture_end': self.capture_end,
            'capture_duration_sec': round(self.capture_duration, 3),
            'host_count': self.host_count,
            'flow_count': self.flow_count,
            'conversation_count': len(self.conversations),
            'fragment_count': self.fragment_count,
            'decode_error_packets': self.decode_error_packets,
            'file_format': self.file_format,
            'file_size': self.file_size,
            'parse_duration_sec': round(self.parse_duration, 3),
            'truncated': self.truncated,
            'truncation_reason': self.truncation_reason,
            'unsupported_packets': self.unsupported_packets,
            'errors': self.errors[:50],
            'protocols': [{'name': n, 'packets': c, 'bytes': self.protocol_bytes.get(n, 0)}
                          for n, c in proto_list],
            'top_talkers': [t.to_dict() for t in top_talkers],
            'strings_are_untrusted': True,
        }


# TCP flag constants (from decode.py)
TCP_SYN = 0x02
TCP_ACK = 0x10
TCP_RST = 0x04


def analyze_packets(decoded_packets, read_result=None):
    """Build analysis from a list of DecodedPacket objects.

    Args:
        decoded_packets: List of decode.DecodedPacket objects.
        read_result: Optional pcap_reader.ReadResult for metadata.

    Returns:
        AnalysisResult with all aggregations populated.
    """
    result = AnalysisResult()

    if read_result:
        result.truncated = read_result.truncated
        result.truncation_reason = read_result.truncation_reason
        result.unsupported_packets = read_result.unsupported_packets
        result.errors = list(read_result.errors)
        result.file_format = read_result.file_format
        result.file_size = read_result.file_size
        result.parse_duration = read_result.duration_sec

    # Collect all timestamps for timeline bucketing
    timestamps_bytes = []   # (timestamp, bytes, protocol_name)

    for pkt in decoded_packets:
        result.total_packets += 1
        if pkt.decode_errors:
            result.decode_error_packets += 1
        pkt_bytes = pkt.original_len or pkt.captured_len
        result.total_bytes += pkt_bytes

        ts = pkt.timestamp
        if ts is not None and math.isfinite(ts):
            if result.capture_start == float('inf'):
                result.capture_end = ts
            if ts < result.capture_start:
                result.capture_start = ts
            if ts > result.capture_end:
                result.capture_end = ts

        proto = pkt.protocol_name

        # Protocol stats
        result.protocol_counts[proto] += 1
        result.protocol_bytes[proto] += pkt_bytes

        # Fragment tracking
        if pkt.is_fragment:
            result.fragment_count += 1

        src_ip = pkt.src_ip
        dst_ip = pkt.dst_ip

        if not src_ip or not dst_ip:
            # ARP or non-IP
            if pkt.arp_sender_ip:
                src_ip = pkt.arp_sender_ip
            if pkt.arp_target_ip:
                dst_ip = pkt.arp_target_ip
            if not src_ip and not dst_ip:
                timestamps_bytes.append((ts, pkt_bytes, proto))
                continue

        # Host stats
        if src_ip:
            if src_ip not in result.hosts:
                result.hosts[src_ip] = HostStats(src_ip)
            h = result.hosts[src_ip]
            h.bytes_out += pkt_bytes
            h.packets_out += 1
            if ts is not None:
                h.last_seen = ts if h.first_seen == float('inf') else max(h.last_seen, ts)
                h.first_seen = min(h.first_seen, ts)
            h.protocols[proto] += 1
            if dst_ip:
                h.peers.add(dst_ip)

        if dst_ip:
            if dst_ip not in result.hosts:
                result.hosts[dst_ip] = HostStats(dst_ip)
            h = result.hosts[dst_ip]
            h.bytes_in += pkt_bytes
            h.packets_in += 1
            if ts is not None:
                h.last_seen = ts if h.first_seen == float('inf') else max(h.last_seen, ts)
                h.first_seen = min(h.first_seen, ts)
            h.protocols[proto] += 1
            if src_ip:
                h.peers.add(src_ip)

        # DNS names / SNI association
        if pkt.dns_query and pkt.dns_is_response and src_ip:
            # The DNS server responded — associate the name
            # (In real captures we'd need to check answers, but this is lightweight)
            if dst_ip and dst_ip in result.hosts:
                pass  # Query was from dst_ip, not helpful for IP→name
            result.dns_queries.append((ts, pkt.dns_query, pkt.dns_qtype,
                                       pkt.dns_rcode, src_ip))

        if pkt.dns_query and not pkt.dns_is_response and dst_ip:
            result.dns_queries.append((ts, pkt.dns_query, pkt.dns_qtype,
                                       None, src_ip))

        if pkt.tls_sni and dst_ip and dst_ip in result.hosts:
            result.hosts[dst_ip].sni_names.add(pkt.tls_sni)
        if pkt.http_host and dst_ip and dst_ip in result.hosts:
            result.hosts[dst_ip].dns_names.add(pkt.http_host)

        # Flow stats (5-tuple)
        if src_ip and dst_ip:
            src_port = pkt.src_port or 0
            dst_port = pkt.dst_port or 0
            ip_proto = pkt.ip_proto or 0

            fk = FlowKey(src_ip, dst_ip, src_port, dst_port, ip_proto)
            if fk not in result.flows:
                result.flows[fk] = FlowStats(fk)
            flow = result.flows[fk]
            flow.bytes_total += pkt_bytes
            flow.packets += 1
            if ts is not None:
                flow.last_seen = ts if flow.first_seen == float('inf') else max(flow.last_seen, ts)
                flow.first_seen = min(flow.first_seen, ts)
            flow.protocol_name = proto

            if pkt.tcp_flags is not None:
                if pkt.tcp_flags & TCP_SYN:
                    if pkt.tcp_flags & TCP_ACK:
                        flow.syn_ack_seen = True
                    else:
                        flow.syn_seen = True
                        if ts is not None:
                            flow.syn_starts.append(ts)
                if pkt.tcp_flags & TCP_RST:
                    flow.rst_count += 1

            # Conversation stats (bidirectional)
            ck = ConversationKey(src_ip, dst_ip)
            if ck not in result.conversations:
                result.conversations[ck] = ConversationStats(ck)
            conv = result.conversations[ck]
            conv.bytes_total += pkt_bytes
            conv.packets += 1
            conv.protocols[proto] += 1
            if ts is not None:
                conv.last_seen = ts if conv.first_seen == float('inf') else max(conv.last_seen, ts)
                conv.first_seen = min(conv.first_seen, ts)

        timestamps_bytes.append((ts, pkt_bytes, proto))

    # Replies belong to the reverse directional flow, including when the
    # capture is out of order. Link them after all packets have been read.
    for fk, flow in result.flows.items():
        reverse = result.flows.get(FlowKey(fk.dst_ip, fk.src_ip, fk.dst_port, fk.src_port, fk.proto))
        if reverse and flow.syn_seen:
            flow.syn_ack_seen = flow.syn_ack_seen or reverse.syn_ack_seen

    # Build timeline buckets
    _build_timeline(result, timestamps_bytes)

    # Associate DNS names with IPs (from queries)
    _associate_dns_names(result)

    return result


def _build_timeline(result, timestamps_bytes):
    """Build time-series buckets for the timeline chart."""
    if not timestamps_bytes or result.capture_start == float('inf'):
        return

    result.bucket_size = _auto_bucket_size(result.capture_duration)
    num_buckets = int(math.ceil(result.capture_duration / result.bucket_size)) + 1
    # Cap at 500 buckets
    if num_buckets > 500:
        result.bucket_size = result.capture_duration / 499
        num_buckets = 500

    buckets = []
    for i in range(num_buckets):
        buckets.append({
            'time_offset': round(i * result.bucket_size, 3),
            'bytes': 0,
            'packets': 0,
            'protocols': defaultdict(int),
        })

    for ts, nbytes, proto in timestamps_bytes:
        if ts is None:
            continue
        idx = min(len(buckets) - 1, int((ts - result.capture_start) / result.bucket_size))
        if 0 <= idx < len(buckets):
            buckets[idx]['bytes'] += nbytes
            buckets[idx]['packets'] += 1
            buckets[idx]['protocols'][proto] += 1

    # Convert defaultdicts to dicts
    for b in buckets:
        b['protocols'] = dict(b['protocols'])

    result.timeline_buckets = buckets


def _associate_dns_names(result):
    """Attach observed query names only where SNI corroborates the endpoint."""
    queried = {qname for _, qname, _, _, _ in result.dns_queries if qname}
    for host in result.hosts.values():
        host.dns_names.update(host.sni_names & queried)


def get_top_hosts(result, n=300):
    """Get top N hosts by total bytes for visualization (cap graph size)."""
    sorted_hosts = sorted(result.hosts.values(),
                          key=lambda h: h.total_bytes, reverse=True)

    if len(sorted_hosts) <= n:
        return sorted_hosts, None

    top = sorted_hosts[:n]
    rest = sorted_hosts[n:]
    other_bytes = sum(h.total_bytes for h in rest)
    other_packets = sum(h.total_packets for h in rest)
    other_info = {
        'count': len(rest),
        'total_bytes': other_bytes,
        'total_packets': other_packets,
        'note': f'{len(rest)} hosts aggregated into "other" for visualization'
    }
    return top, other_info


def query_analysis(result, query_type, **kwargs):
    """Execute a structured query against an analysis result.

    Args:
        result: AnalysisResult
        query_type: One of 'top_talkers', 'host_detail', 'conversations',
                    'protocol_breakdown', 'time_window', 'findings', 'dns_names'
        **kwargs: Query-specific parameters

    Returns:
        dict with query results
    """
    if query_type in ('top_talkers', 'conversations'):
        n = kwargs.get('n', 10)
        if isinstance(n, bool) or not isinstance(n, int) or not 1 <= n <= 1000:
            return {'error': 'n must be an integer between 1 and 1000'}
    if kwargs.get('by', 'bytes') not in ('bytes', 'packets'):
        return {'error': 'by must be bytes or packets'}
    if query_type == 'top_talkers':
        n = kwargs.get('n', 10)
        by = kwargs.get('by', 'bytes')
        if by == 'packets':
            sorted_hosts = sorted(result.hosts.values(),
                                  key=lambda h: h.total_packets, reverse=True)
        else:
            sorted_hosts = sorted(result.hosts.values(),
                                  key=lambda h: h.total_bytes, reverse=True)
        return {
            'query': 'top_talkers',
            'results': [h.to_dict() for h in sorted_hosts[:n]],
            'strings_are_untrusted': True,
        }

    elif query_type == 'host_detail':
        ip = kwargs.get('ip')
        if not ip or ip not in result.hosts:
            return {'query': 'host_detail', 'error': f'Host not found: {ip}'}
        host = result.hosts[ip]
        # Get conversations for this host
        host_convs = []
        for ck, conv in result.conversations.items():
            if ck.ip_a == ip or ck.ip_b == ip:
                host_convs.append(conv.to_dict())
        host_convs.sort(key=lambda c: c['bytes'], reverse=True)

        return {
            'query': 'host_detail',
            'host': host.to_dict(),
            'conversations': host_convs[:20],
            'strings_are_untrusted': True,
        }

    elif query_type == 'conversations':
        n = kwargs.get('n', 20)
        sorted_convs = sorted(result.conversations.values(),
                              key=lambda c: c.bytes_total, reverse=True)
        return {
            'query': 'conversations',
            'results': [c.to_dict() for c in sorted_convs[:n]],
            'strings_are_untrusted': True,
        }

    elif query_type == 'protocol_breakdown':
        protos = sorted(result.protocol_counts.items(),
                        key=lambda x: x[1], reverse=True)
        return {
            'query': 'protocol_breakdown',
            'protocols': [{'name': n, 'packets': c,
                           'bytes': result.protocol_bytes.get(n, 0)}
                          for n, c in protos],
        }

    elif query_type == 'time_window':
        start = kwargs.get('start', result.capture_start if result.capture_start != float('inf') else 0)
        end = kwargs.get('end', result.capture_end)
        if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v)
               for v in (start, end)) or start > end:
            return {'error': 'start and end must be finite timestamps with start <= end'}
        # Filter buckets
        filtered = [b for b in result.timeline_buckets
                    if (result.capture_start + b['time_offset'] + result.bucket_size > start and
                        result.capture_start + b['time_offset'] <= end)]
        return {
            'query': 'time_window',
            'start': start,
            'end': end,
            'bucket_size': result.bucket_size,
            'buckets': filtered[:300],
        }

    elif query_type == 'dns_names':
        names = {}
        for ip, host in result.hosts.items():
            all_names = sorted(host.dns_names | host.sni_names)
            if all_names:
                names[ip] = all_names
        return {
            'query': 'dns_names',
            'mappings': names,
            'strings_are_untrusted': True,
        }

    elif query_type == 'findings':
        # Delegate to heuristics — caller should pass findings
        return {
            'query': 'findings',
            'results': kwargs.get('findings', []),
            'strings_are_untrusted': True,
        }

    else:
        return {'query': query_type, 'error': f'Unknown query type: {query_type}', 'ok': False}

