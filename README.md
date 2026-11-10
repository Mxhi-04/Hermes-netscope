<p align="center">
  <img src="assets/hero-banner.svg" alt="netScope — Offline Network Capture Intelligence for Hermes Agent" width="100%">
</p>

<p align="center">
  <a href="https://github.com/NousResearch/hermes-agent"><img src="https://img.shields.io/badge/HERMES_AGENT-PLUGIN-FF5500?style=for-the-badge&logoColor=white" alt="Hermes Agent"></a>
  <a href="#-architecture--pipeline"><img src="https://img.shields.io/badge/DEPENDENCIES-0%20(STDLIB%20ONLY)-00F0FF?style=for-the-badge" alt="Zero Dependencies"></a>
  <a href="#-security--sandbox-guarantees"><img src="https://img.shields.io/badge/TELEMETRY-NONE%20(AIR--GAPPED)-00E599?style=for-the-badge" alt="Air Gapped"></a>
  <a href="#-license"><img src="https://img.shields.io/badge/LICENSE-MIT-A0AEC0?style=for-the-badge" alt="MIT License"></a>
</p>

---

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│  NOUS RESEARCH // HERMES AGENT ECOSYSTEM                                              │
│  PROJECT      : netScope                                                               │
│  PURPOSE      : Offline PCAP/PCAPNG Forensics, Heuristic Anomaly Engine & Visualizer   │
│  SECURITY     : 100% Offline • Strict CSP • Zero Cloud Calls • Zero Native Binaries    │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

**netScope** brings deep, deterministic, offline packet capture analysis to [Hermes Agent](https://github.com/NousResearch/hermes-agent). 

Feed Hermes any `.pcap` or `.pcapng` capture file to dissect flows, trace conversations, surface deterministic network anomalies, and interact with a cybernetic, self-contained HTML visual dashboard featuring force-directed network topology graphs and temporal traffic replay.

Built purely on the Python standard library with **zero external dependencies**, **zero network calls**, and **zero telemetry**.

---

## 📑 Table of Contents

- [⬡ Architecture & Pipeline](#-architecture--pipeline)
- [🖥️ Interactive Dashboard Deep Dive](#-interactive-dashboard-deep-dive)
- [🚀 Quickstart Tutorial: Zero to Insights](#-quickstart-tutorial-zero-to-insights)
  - [1. Installation & Doctor Verification](#1-installation--doctor-verification)
  - [2. Generate Synthetic Capture Data](#2-generate-synthetic-capture-data)
  - [3. Instant Slash Command Analysis](#3-instant-slash-command-analysis)
  - [4. Conversational Investigation with Hermes](#4-conversational-investigation-with-hermes)
  - [5. Visualizing & Replaying Traffic](#5-visualizing--replaying-traffic)
- [🧠 Deterministic Heuristics Matrix](#-deterministic-heuristics-matrix)
- [🛠️ Tool Reference & Natural Language Integration](#-tool-reference--natural-language-integration)
- [🛡️ Security & Sandbox Guarantees](#-security--sandbox-guarantees)
- [⚖️ Limits & Heuristics Disclaimer](#-limits--heuristics-disclaimer)
- [📄 License](#-license)

---

## ⬡ Architecture & Pipeline

netScope streams packets incrementally through a four-stage standard library pipeline designed for high performance and minimal memory footprint:

<p align="center">
  <img src="assets/pipeline.svg" alt="netScope Pipeline Architecture" width="100%">
</p>

1. **Multi-Format Streaming Reader (`pcap_reader.py`)**  
   Reads classic `.pcap` (microsecond & nanosecond timestamps, big/little endian) and modern `.pcapng` (Section Header, Interface Description, Enhanced Packet, and Simple Packet blocks) using Python's `struct` without loading the full file into RAM.
2. **Layer 2–7 Protocol Dissector (`decode.py`)**  
   Extracts Ethernet II, 802.1Q VLAN, IPv4, IPv6 (with chained extension header traversal), TCP, UDP, ICMP/ICMPv6, and ARP. Lightweight extraction captures DNS queries/responses, TLS Server Name Indication (SNI), and HTTP `Host` headers without persisting payload contents.
3. **Deterministic Anomaly Heuristics (`heuristics.py`)**  
   Evaluates traffic distributions mathematically using robust statistics (Median Absolute Deviation for bursts, Coefficient of Variation for beaconing, and Shannon entropy for DNS exfiltration).
4. **Interactive Delivery & Replay (`report.py` & `tools.py`)**  
   Supplies Hermes Agent with direct conversational context while compiling a single-file, self-contained dark-mode HTML dashboard.

---

## 🖥️ Interactive Dashboard Deep Dive

Every analysis can generate a standalone, self-contained HTML dashboard saved to `~/.hermes/netscope/reports/`. It contains no external dependencies, CDNs, or remote font calls, adhering to a strict Content Security Policy (`default-src 'none'`).

<p align="center">
  <img src="assets/dashboard-preview.svg" alt="netScope Interactive Dashboard Preview" width="100%">
</p>

### Key Dashboard Modules

| Component | Capabilities & Interaction |
| :--- | :--- |
| **🌐 Force-Directed Topology** | Automatically clusters internal subnets (`192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`) away from external infrastructure. Nodes scale by volume; edges scale by total bytes transferred. Nodes are draggable with physics relaxation, zoomable, and clickable. |
| **⏱️ Temporal Replay Engine** | Step through capture playback with the interactive scrubber. Supports `1x`, `4x`, and `16x` speeds with animated particle pulses traveling along active conversation paths in real time. |
| **🔍 Protocol Filter Chips** | Instant canvas filtering by protocol (`ALL`, `TCP`, `UDP`, `DNS`, `TLS`, `HTTP`, `ICMP`, `ARP`) with instantaneous graph re-weighting. |
| **📊 Traffic Burst Timeline** | 1-second bucket histogram highlighting volume surges. Anomaly markers flag statistically significant traffic bursts computed via robust Z-scores. |
| **🎯 Finding-to-Timeline Link** | Clicking any finding in the side drawer navigates the graph directly to involved host nodes and snaps the playback scrubber to the exact occurrence timestamp. |
| **📋 Host Inspection Drawer** | Deep inspection of selected endpoints displaying total ingress/egress bytes, associated DNS query names, TLS SNI certificates, active peers, and flow counts. |

---

## 🚀 Quickstart Tutorial: Zero to Insights

Follow this hands-on tutorial to go from installation to visual forensics in under 60 seconds.

### 1. Installation & Doctor Verification

Install netScope into your Hermes Agent environment:

```bash
# Install via Hermes plugin catalog
hermes plugins install netscope
hermes plugins enable netscope
```

Or clone into your local Hermes plugins folder:

```bash
git clone https://github.com/Mxhi-04/hermes-netscope.git ~/.hermes/plugins/netscope
hermes plugins enable netscope
```

Verify your environment using Hermes Doctor:

```bash
hermes plugins doctor ~/.hermes/plugins/netscope --ci
```

```text
[✓] Plugin manifests valid: plugin.yaml, SKILL.md
[✓] Zero external Python dependencies required
[✓] Stdlib struct, socket, math, json modules verified
[✓] Output directory writable: ~/.hermes/netscope/reports
[✓] netScope plugin status: READY
```

---

### 2. Generate Synthetic Capture Data

netScope includes a pure Python synthesizer that generates realistic network traffic using RFC-reserved subnets (`RFC 1918` and `RFC 5737`):

```bash
python3 examples/make_sample_pcap.py sample.pcap
```

This generates a test `.pcap` containing:
- Baseline web & DNS activity across 10 internal nodes.
- High-rate SYN port scan targeting an internal host.
- Periodic C2 beaconing every ~30 seconds with low jitter.
- DNS tunneling queries exhibiting high Shannon entropy.
- A sudden 400 KB traffic burst.

---

### 3. Instant Slash Command Analysis

Run the built-in slash command to perform a complete sweep:

```text
/netscope sample.pcap
```

Hermes immediately analyzes the capture and responds:

```text
⬡ netScope Capture Summary: sample.pcap
────────────────────────────────────────────────────────────────────────────
Duration    : 64.20s (1,248 packets, 842.1 KB)
Endpoints   : 14 unique hosts across 42 active flows
Dominant    : TCP (68.4%), UDP/DNS (24.1%), TLS (5.2%), HTTP (2.3%)

Heuristic Observations:
  [HIGH] SYN Port Scan Detected
         Host 192.168.1.105 probed 64 unique ports on 192.168.1.10 (t=14.2s - 17.4s)
  [MED]  Periodic Beaconing
         Host 192.168.1.45 -> 198.51.100.24 every 30.1s (CV = 0.082 < 0.20 threshold)
  [MED]  High-Entropy DNS Exfiltration
         Host 192.168.1.10 made 18 queries with entropy > 4.2 bits/char (tunneling pattern)

Visual Report Generated:
file:///Users/username/.hermes/netscope/reports/sample_report.html
```

---

### 4. Conversational Investigation with Hermes

Ask Hermes targeted follow-up questions in natural language:

````text
User: "Which host sent the highest volume of outbound data, and what domains did it contact?"

Hermes: [Invokes netscope_query with query="top_talkers"]
Host 192.168.1.10 was the top talker:
  • Outbound Data : 421.8 KB across 312 packets
  • Resolved SNIs : api.github.com, updates.microsoft.com
  • External DNS  : one.one.one.one (1.1.1.1)

User: "Tell me more about the beaconing detection. Why did it trigger?"

Hermes: [Invokes netscope_query with query="findings", filter_host="192.168.1.45"]
Finding #2 triggered because host 192.168.1.45 initiated 12 connections to 
198.51.100.24 with regular inter-arrival intervals:
  • Mean Interval : 30.12 seconds
  • Std Deviation : 2.47 seconds
  • Coefficient of Variation (CV) : 0.082

Because the CV is well below the 0.20 anomaly threshold, the timing exhibits 
programmatic, low-jitter beaconing characteristics consistent with automated C2 or telemetry.
````

---

### 5. Visualizing & Replaying Traffic

Open the generated HTML report in any browser (Safari, Chrome, Firefox, Edge):

```bash
open ~/.hermes/netscope/reports/sample_report.html
```

- **Inspect Top Talkers**: Hover over `192.168.1.1` to view total ingress/egress bytes.
- **Trace the Attack**: Click on `[HIGH] SYN Port Scan` in the sidebar to center the camera on `192.168.1.105` and highlight its probed ports.
- **Replay the Incident**: Hit `[ ▶ PLAY ]` at `4x` speed and watch packet pulses traverse the network as the scan and beaconing unfold chronologically.

---

## 🧠 Deterministic Heuristics Matrix

netScope deliberately avoids opaque black-box machine learning models in favor of **explainable, deterministic mathematics**:

```
┌─────────────────────────┬──────────────────────────────────┬───────────────────────────────────────────┐
│ HEURISTIC               │ MATHEMATICAL MODEL               │ DETECTION THRESHOLD                       │
├─────────────────────────┼──────────────────────────────────┼───────────────────────────────────────────┤
│ Traffic Spikes          │ Robust Z-Score via MAD           │ Absolute Modified Z > 3.5 across 1s bins  │
│ Port / Host Scanning    │ Unique Dest Ports / IPs per sec  │ > 30 unique ports in < 5 seconds          │
│ Periodic C2 Beaconing   │ Coefficient of Variation (σ / μ) │ CV < 0.20 across ≥ 5 intervals            │
│ DNS Tunneling / Exfil   │ Shannon Entropy & Label Length   │ Entropy > 4.0 bits/char or labels > 45ch  │
│ Cleartext Protocols     │ Plaintext Port & Header Match    │ Telnet (23), FTP (21), HTTP basic auth    │
└─────────────────────────┴──────────────────────────────────┴───────────────────────────────────────────┘
```

> **Note on MAD (Median Absolute Deviation)**: Standard deviation is distorted by outliers. netScope uses Median Absolute Deviation:  
> $$MAD = \text{median}(|X_i - \tilde{X}|)$$  
> yielding an anomaly score robust against baseline contamination.

---

## 🛠️ Tool Reference & Natural Language Integration

netScope exposes four atomic tools to Hermes Agent:

### `netscope_analyze`
Ingests a `.pcap` or `.pcapng` file, constructs connection states, executes heuristics, and returns structured summary metrics:
```json
{
  "pcap_path": "/path/to/capture.pcap",
  "focus_host": "192.168.1.105",
  "max_packets": 2000000
}
```

### `netscope_query`
Performs in-memory queries against an existing analysis ID without re-parsing the capture:
- `query="top_talkers"`: Ranked host byte & packet metrics.
- `query="conversations"`: Peer-to-peer flows filtered by host or protocol.
- `query="dns_queries"`: DNS resolutions, question types, and response codes.
- `query="tls_hosts"`: Extracted SNIs and certificate hostnames.
- `query="findings"`: Filtered list of heuristic anomaly records.

### `netscope_visualize`
Generates the self-contained HTML dashboard with embedded JSON data, canvas topology, and timeline replay:
```json
{
  "analysis_id": "ns_a1b2c3d4e5f6",
  "focus_host": "192.168.1.10"
}
```

---

## 🛡️ Security & Sandbox Guarantees

netScope is engineered for sensitive enterprise, security operations, and air-gapped forensic environments:

- **🔒 Zero Network Egress**: Makes no socket connections, no telemetry beacons, and no external DNS lookups.
- **🧱 Strict Content Security Policy**: Generated reports enforce `default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:`. No scripts or stylesheets can ever load from external origins.
- **🧹 Sanitized Dissection**: All packet-derived metadata (DNS domain labels, TLS SNI headers, HTTP hosts) is strictly sanitized against control characters and length-truncated prior to display.
- **🚫 Zero Payload Retention**: Raw packet payloads are never persisted in memory or written into HTML reports. Only structural protocol headers and metadata are analyzed.

---

## ⚖️ Limits & Heuristics Disclaimer

### Engine Boundaries
- **Default File Cap**: 256 MB soft limit per capture.
- **Default Packet Cap**: 2,000,000 packets per stream.
- **Graph Node Cap**: The visual topology graph renders the top 300 active hosts to ensure 60fps canvas performance; remaining hosts are grouped into aggregate metrics.

### Heuristics are Observations, Not Verdicts
> Anomaly flags represent patterns consistent with specific network behaviors (e.g., automated scanning or periodic polling). Benign software, vulnerability scanners, health check monitors, NTP synchronizations, and misconfigured services frequently display identical traffic profiles. Always correlate netScope findings with endpoint logs, auth logs, and host-level telemetry.

---

## 📄 License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.

Developed with open intelligence for the [Hermes Agent](https://github.com/NousResearch/hermes-agent) ecosystem by [Nous Research](https://nousresearch.com/).
