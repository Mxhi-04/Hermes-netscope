"""
heuristics.py — Deterministic, explainable anomaly detection.

Every finding has: kind, severity, confidence, hosts, time_range, and a
plain-English 'why' listing the numbers that triggered it.
Language: "looks like / consistent with", never "is". No verdicts.
"""

import math
from collections import Counter, defaultdict

if __package__:
    from .analyze import FlowKey
else:
    from analyze import FlowKey


def _median(values):
    """Compute median of a list of numbers."""
    if not values:
        return 0.0
    s = sorted(values)
    n = len(s)
    if n % 2 == 1:
        return float(s[n // 2])
    return (s[n // 2 - 1] + s[n // 2]) / 2.0


def _mad(values, med=None):
    """Compute Median Absolute Deviation."""
    if not values:
        return 0.0
    if med is None:
        med = _median(values)
    return _median([abs(v - med) for v in values])


def _robust_zscore(value, med, mad_val):
    """Compute robust z-score using median/MAD."""
    if mad_val <= 0:
        return 0.0
    return 0.6745 * (value - med) / mad_val


def detect_all(analysis_result):
    """Run all heuristic detectors on an AnalysisResult.

    Returns a list of finding dicts, each with:
        kind, severity, confidence, hosts, time_range, why
    """
    findings = []
    findings.extend(detect_traffic_spikes(analysis_result))
    findings.extend(detect_port_scan(analysis_result))
    findings.extend(detect_beaconing(analysis_result))
    findings.extend(detect_dns_oddities(analysis_result))
    findings.extend(detect_cleartext(analysis_result))
    return findings


def detect_traffic_spikes(result):
    """Detect traffic spikes using robust z-score (median/MAD) on per-bucket bytes.

    Triggers when z-score > 3.5 AND above an absolute floor.
    """
    findings = []
    buckets = result.timeline_buckets
    if len(buckets) < 10:
        return findings

    byte_values = [b['bytes'] for b in buckets]
    med = _median(byte_values)
    mad_val = _mad(byte_values, med)

    non_zero = [v for v in byte_values if v > 0]
    mean_val = sum(byte_values) / len(byte_values) if byte_values else 0.0

    # If data is sparse (>50% buckets zero), use dispersion of non-zero buckets
    if mad_val == 0:
        if non_zero:
            nz_med = _median(non_zero)
            mad_val = _mad(non_zero, nz_med)
        if mad_val == 0:
            mad_val = max(1.0, mean_val)

    # Absolute floor: at least 4x mean/median AND at least 10KB
    abs_floor = max(med * 4, mean_val * 3, 10240)

    for i, bucket in enumerate(buckets):
        bval = bucket['bytes']
        if bval <= abs_floor:
            continue
        zscore = _robust_zscore(bval, med, mad_val)
        if zscore > 3.5 or (bval > mean_val * 4):
            time_offset = bucket['time_offset']
            ts = result.capture_start + time_offset

            findings.append({
                'kind': 'traffic_spike',
                'severity': 'medium' if (zscore < 5 and bval < 100000) else 'high',
                'confidence': 'high' if zscore > 4 else 'medium',
                'hosts': [],
                'time_range': [ts, ts + result.bucket_size],
                'why': (f"Traffic spike detected: {bval:,} bytes in a "
                        f"{result.bucket_size:.1f}s bucket "
                        f"(robust z-score: {zscore:.1f}, median: {med:,.0f} bytes, "
                        f"mean: {mean_val:,.0f} bytes). This looks like a sudden burst "
                        f"of traffic compared to the baseline."),
            })

    return findings


def detect_port_scan(result):
    """Detect port/host scanning behavior.

    Triggers when one source contacts >= 20 distinct (dst, dport) pairs
    within 60s, mostly without SYN-ACK or with RSTs.
    Only checks flows where the source sent a SYN (initiator).
    """
    findings = []

    # Group flows by source IP where SYN was initiated
    src_flows = defaultdict(list)
    for fk, flow in result.flows.items():
        if fk.proto == 6 and flow.syn_seen:  # TCP initiator only
            src_flows[fk.src_ip].append(flow)

    for src_ip, flows in src_flows.items():
        flows_sorted = sorted((f for f in flows if math.isfinite(f.first_seen)),
                              key=lambda f: f.first_seen)

        # Incremental counters keep dense, successful traffic linear after
        # sorting, instead of rebuilding every growing 60-second window.
        window_start = 0
        targets = Counter()
        no_synack_count = 0
        rst_count = 0

        def rsts(flow):
            fk = flow.key
            reverse = result.flows.get(FlowKey(fk.dst_ip, fk.src_ip, fk.dst_port, fk.src_port, fk.proto))
            return flow.rst_count + (reverse.rst_count if reverse else 0)

        for i, flow in enumerate(flows_sorted):
            if not math.isfinite(flow.first_seen):
                break
            targets[(flow.key.dst_ip, flow.key.dst_port)] += 1
            no_synack_count += not flow.syn_ack_seen
            rst_count += rsts(flow)
            while (window_start < i and
                   flow.first_seen - flows_sorted[window_start].first_seen > 60):
                old = flows_sorted[window_start]
                target = (old.key.dst_ip, old.key.dst_port)
                targets[target] -= 1
                if not targets[target]:
                    del targets[target]
                no_synack_count -= not old.syn_ack_seen
                rst_count -= rsts(old)
                window_start += 1
            window_length = i - window_start + 1
            if window_length < 20:
                continue

            if len(targets) < 20:
                continue

            # Check if mostly unsuccessful
            failure_ratio = no_synack_count / window_length
            if failure_ratio < 0.7:
                continue

            ts_start = flows_sorted[window_start].first_seen
            ts_end = flow.first_seen
            dst_ips = set(t[0] for t in targets)
            dst_ports = set(t[1] for t in targets)

            scan_type = 'port scan' if len(dst_ips) <= 3 else 'host/port scan'

            findings.append({
                'kind': 'port_scan',
                'severity': 'medium',
                'confidence': 'high' if failure_ratio > 0.9 else 'medium',
                'hosts': [src_ip],
                'time_range': [ts_start, ts_end],
                'why': (f"Activity consistent with a {scan_type}: {src_ip} "
                        f"initiated connections to {len(targets)} distinct (host, port) pairs "
                        f"across {len(dst_ips)} hosts and {len(dst_ports)} ports "
                        f"within {ts_end - ts_start:.0f}s. "
                        f"{no_synack_count}/{window_length} connections "
                        f"({failure_ratio:.0%}) had no SYN-ACK response, "
                        f"with {rst_count} RST packets observed."),
            })
            break  # One finding per source

    return findings


def detect_beaconing(result):
    """Detect beaconing behavior.

    Triggers when >= 8 connection starts from one src to one (dst, dport) with
    inter-arrival coefficient of variation < 0.2 and mean interval 1s-1h.
    """
    findings = []

    # Group SYN flows by (src, dst, dport)
    beacon_groups = defaultdict(list)
    for fk, flow in result.flows.items():
        if fk.proto == 6 and flow.syn_seen:  # TCP with SYN
            key = (fk.src_ip, fk.dst_ip, fk.dst_port)
            # Use all observed starts, so reusing a five-tuple does not hide
            # periodic activity. Deduplicate identical timestamps below.
            if flow.syn_starts:
                beacon_groups[key].extend(flow.syn_starts)
            elif flow.first_seen != float('inf'):
                beacon_groups[key].append(flow.first_seen)

    # Also check UDP flows
    udp_groups = defaultdict(list)
    for fk, flow in result.flows.items():
        if fk.proto == 17:  # UDP
            key = (fk.src_ip, fk.dst_ip, fk.dst_port)
            ts = flow.first_seen if flow.first_seen != float('inf') else 0
            if ts > 0:
                udp_groups[key].append(ts)

    for groups in [beacon_groups, udp_groups]:
        for (src, dst, dport), timestamps in groups.items():
            if len(timestamps) < 8:
                continue

            timestamps = sorted(set(timestamps))
            if len(timestamps) < 8:
                continue
            intervals = [timestamps[i+1] - timestamps[i]
                         for i in range(len(timestamps) - 1)]

            if not intervals:
                continue

            mean_interval = sum(intervals) / len(intervals)

            # Check mean interval range: 1s to 1h
            if mean_interval < 1.0 or mean_interval > 3600:
                continue

            # Coefficient of variation
            if mean_interval == 0:
                continue
            variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
            std_dev = math.sqrt(variance)
            cv = std_dev / mean_interval

            if cv >= 0.2:
                continue

            findings.append({
                'kind': 'beaconing',
                'severity': 'medium',
                'confidence': 'high' if cv < 0.1 else 'medium',
                'hosts': [src, dst],
                'time_range': [timestamps[0], timestamps[-1]],
                'why': (f"Pattern consistent with beaconing: {src} → {dst}:{dport} "
                        f"with {len(timestamps)} connections. Mean interval: "
                        f"{mean_interval:.1f}s (CV: {cv:.3f}). "
                        f"The regularity of these connections (CV < 0.2) "
                        f"looks like automated periodic communication."),
            })

    return findings


def detect_dns_oddities(result):
    """Detect DNS anomalies: long/high-entropy labels, high NXDOMAIN ratio,
    many unique subdomains under one parent.
    Only attributes findings to client IPs (not DNS server IPs responding).
    """
    findings = []

    if not result.dns_queries:
        return findings

    # Group by source IP of query (only queries, not responses)
    # in result.dns_queries: (ts, qname, qtype, rcode_or_none, src_ip)
    # When rcode is None, it was a client query from src_ip!
    src_client_queries = defaultdict(list)

    for ts, qname, qtype, rcode, src_ip in result.dns_queries:
        if rcode is None:
            src_client_queries[src_ip].append((ts, qname, qtype))

    for src_ip, queries in src_client_queries.items():
        # Check for long/high-entropy labels
        long_queries = []
        for ts, qname, qtype in queries:
            if not qname:
                continue
            labels = qname.split('.')
            for label in labels:
                if len(label) > 40:
                    long_queries.append((ts, qname, label))
                    break
                if len(label) > 15:
                    frequencies = {c: label.lower().count(c) / len(label) for c in set(label.lower())}
                    entropy = -sum(p * math.log2(p) for p in frequencies.values())
                    if entropy > 4.0 and len(label) > 20:
                        long_queries.append((ts, qname, label))
                        break

        if len(long_queries) >= 3:
            findings.append({
                'kind': 'dns_long_labels',
                'severity': 'medium',
                'confidence': 'medium',
                'hosts': [src_ip],
                'time_range': [long_queries[0][0], long_queries[-1][0]],
                'why': (f"DNS queries with unusually long or high-entropy labels "
                        f"from {src_ip}: {len(long_queries)} queries found. "
                        f"Example: '{long_queries[0][2][:60]}...' "
                        f"This pattern looks like it could be consistent with "
                        f"DNS tunnelling or data exfiltration."),
            })

        # Check for many unique subdomains under one parent
        parent_domains = defaultdict(set)
        for ts, qname, qtype in queries:
            if not qname:
                continue
            parts = qname.split('.')
            if len(parts) >= 3:
                parent = '.'.join(parts[-2:])
                subdomain = '.'.join(parts[:-2])
                parent_domains[parent].add(subdomain)

        for parent, subdomains in parent_domains.items():
            if len(subdomains) >= 20:
                findings.append({
                    'kind': 'dns_many_subdomains',
                    'severity': 'low',
                    'confidence': 'medium',
                    'hosts': [src_ip],
                    'time_range': [queries[0][0], queries[-1][0]],
                    'why': (f"Many unique subdomains queried under {parent} "
                            f"from {src_ip}: {len(subdomains)} unique subdomains. "
                            f"This looks like it could be consistent with DNS "
                            f"tunnelling, data exfiltration, or domain generation."),
                })

    return findings


def detect_cleartext(result):
    """Flag presence of cleartext protocols (Telnet, FTP, plain HTTP).

    Never extracts or displays credentials or payload content.
    """
    findings = []
    cleartext_protos = {'Telnet', 'FTP', 'HTTP'}

    observed = {}
    for proto_name, count in result.protocol_counts.items():
        if proto_name in cleartext_protos and count > 0:
            observed[proto_name] = count

    if observed:
        hosts_using = set()
        for fk, flow in result.flows.items():
            if flow.protocol_name in cleartext_protos:
                hosts_using.add(fk.src_ip)
                hosts_using.add(fk.dst_ip)

        proto_list = ', '.join(f"{k} ({v} packets)" for k, v in observed.items())
        findings.append({
            'kind': 'cleartext_protocols',
            'severity': 'info',
            'confidence': 'high',
            'hosts': sorted(hosts_using)[:10],
            'time_range': [result.capture_start
                           if result.capture_start != float('inf') else 0,
                           result.capture_end],
            'why': (f"Cleartext protocols observed: {proto_list}. "
                    f"These port assignments suggest traffic that may be unencrypted; "
                    f"ports alone do not prove the protocol. Only protocol metadata "
                    f"was extracted; credentials and payload bodies were not retained."),
        })

    return findings
