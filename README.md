# ⬡ netScope: Offline Network Capture Analyzer for Hermes Agent

**netScope** brings deep, offline packet capture analysis to [Hermes Agent](https://github.com/NousResearch/hermes-agent). Feed Hermes any `.pcap` or `.pcapng` file to inspect hosts, conversations, protocol breakdowns, and timeline bursts, detect deterministic anomalies, and explore an interactive HTML report featuring force-directed graphs and animated traffic replay.

Pure Python standard library only. Zero external dependencies. Zero network calls. No telemetry.

---

## Features

- **Multi-Format Streaming Reader**: Parses classic pcap (little/big endian, microsecond and nanosecond timestamps) and modern pcapng (SHB, IDB, EPB, SPB) with interface timestamp resolution.
- **Protocol Decoding**: Decodes Ethernet, 802.1Q VLAN, IPv4, IPv6 (with extension header traversal), TCP (flags, ports, payload size), UDP, ICMP/ICMPv6, and ARP.
- **Lightweight App-Layer Extraction**: Extracts DNS query names, types, and response codes; TLS ClientHello Server Name Indication (SNI); and HTTP request `Host` headers without storing packet payloads.
- **Explainable Anomaly Heuristics**: Deterministic detectors for traffic spikes (robust z-score with MAD), port/host scans, periodic beaconing (CV < 0.2), DNS oddities (long labels, high-entropy tunneling patterns, high NXDOMAIN ratio), and cleartext protocol usage.
- **Interactive HTML Report**: Generates a self-contained, zero-external-URL dark-mode dashboard with:
  - Force-directed network topology graph (internal vs. external hosts, draggable nodes, zoom/pan).
  - Protocol chip filters.
  - Interactive timeline with spike markers.
  - Traffic replay with scrubber, variable speed (1x, 4x, 16x), and animated packet pulses across edges.
  - Host inspection side panel and finding-to-timeline jump links.
- **Strict Security & Sandboxing**: Input validation, strict Content Security Policy (`default-src 'none'`), HTML control-character sanitization, and output isolation.

---

## Installation

Install directly from the Hermes plugin catalog or by cloning the repository:

```bash
# Via Hermes plugin manager
hermes plugins install netscope
hermes plugins enable netscope
```

Or clone into your local Hermes plugins folder:

```bash
git clone https://github.com/Mxhi-04/hermes-netscope.git ~/.hermes/plugins/netscope
hermes plugins enable netscope
```

Verify your installation:

```bash
hermes plugins doctor ~/.hermes/plugins/netscope --ci
```

---

## Usage

### Slash Command

The fastest way to analyze a capture and generate a visual report is using the slash command:

```text
/netscope /path/to/capture.pcap
```

This outputs a summary of hosts, flows, and heuristic findings, and generates a standalone HTML report saved to `~/.hermes/netscope/reports/`. Open the report file in any modern web browser.

### Natural Language Workflows

Hermes can query the capture conversationally using the registered tools:

```text
User: "Can you analyze this network capture at ./demo.pcap and tell me what's in it?"
Hermes: [Calls netscope_analyze] Summarizes total traffic, top talkers, and protocols.

User: "Which host is sending the most data?"
Hermes: [Calls netscope_query with query="top_talkers"] Answers with byte counts and peer counts.

User: "Did you find any signs of port scanning or beaconing?"
Hermes: [Calls netscope_query with query="findings"] Explains the detected scan and beaconing behavior with timestamps.

User: "Generate the interactive report for me."
Hermes: [Calls netscope_visualize] Provides the local path to the generated HTML report.
```

---

## Generating Sample Demo Data

netScope includes a pure-Python capture synthesizer (`examples/make_sample_pcap.py`) that generates a realistic demo capture using only standard library packages and RFC-reserved IP addresses (RFC 1918 / RFC 5737):

```bash
python3 examples/make_sample_pcap.py sample.pcap
```

This demo capture includes:
- Baseline DNS and web browsing across 10 internal hosts.
- Port scan activity against an internal subnet.
- Periodic beaconing every ~30 seconds to an external host.
- High-entropy DNS queries consistent with tunneling.
- Sudden 400 KB traffic spike.

---

## Heuristics, Not Verdicts

All anomaly findings produced by netScope are **heuristic observations**, never definitive security verdicts. Findings indicate patterns consistent with specific behaviors (e.g., automated scanning or periodic polling), but benign software, vulnerability scanners, health checks, and misconfigured services often exhibit similar traffic characteristics. Always confirm findings with endpoint and server logs.

---

## Limits & Boundaries

- Maximum file size default: 256 MB.
- Maximum packet count default: 2,000,000 packets.
- Streaming time budget: 30 seconds soft limit.
- Report graph cap: Top 300 hosts by total volume are rendered in the visual graph; remaining hosts are grouped into aggregate statistics to ensure smooth 60fps browser rendering.

---

## Disclosure

> **Disclosure.** netScope makes no network calls, runs no shell commands or subprocesses, starts no background processes, stores or reads no credentials, and sends no telemetry. It reads only the capture file the user names (a read outside the plugin's own data) and writes HTML reports only under `$HERMES_HOME/netscope/reports/`. Reports contain IP addresses and DNS/SNI/HTTP-host names found in the capture and should be treated as sensitive. Packet payloads are not stored or displayed. It does not auto-update.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
