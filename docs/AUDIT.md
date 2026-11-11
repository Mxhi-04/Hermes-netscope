# Audit and validation

Audited November 11, 2026. Scope: every runtime module, manifest and registration surface, bundled skills, synthetic capture generator, existing tests, report browser behavior, and README claims. This is a source and behavior audit, not a guarantee against every possible defect or a security certification.

## Verified result

- **69 pytest cases passed**, up from 13 original cases.
- **84% statement coverage** across the seven runtime modules selected below.
- Ruff's **F** rules passed across Python source, tests, and media scripts.
- Current upstream Hermes **Plugin Doctor passed with no findings**.
- Current upstream Hermes **catalog validation passed**, with security scan verdict **safe**, no warnings, and matching tool registrations.
- The plugin was loaded by the **real Hermes plugin manager** and all three tools were dispatched successfully through the **real tool registry**. This checks more than the fake context used in the original tests.
- Chromium checks passed for desktop and mobile layouts, protocol selection, host inspection, replay and pause/resume, no uncaught JavaScript errors, and no external resource requests from the report.

Host reference: [NousResearch/hermes-agent at `78abaafcccec20a546c94e8734a70e38c08a6a69`](https://github.com/NousResearch/hermes-agent/tree/78abaafcccec20a546c94e8734a70e38c08a6a69). Validation used its unmodified `doctor_plugin`, `validate_plugin_dir`, plugin manager, and registry in a temporary environment. The full Hermes chat application and an LLM-driven end-to-end conversation were not exercised.

Evidence: [doctor output](plugin-doctor.txt), [catalog checks](catalog-validation.json), [runtime dispatch](runtime-validation.json).

## Corrections

| Area | Verified defect or misleading behavior | Correction |
| --- | --- | --- |
| Plugin imports | Injecting the plugin root into `sys.path` and using absolute sibling imports could collide with Hermes's own `tools` package and unrelated modules. | Package-relative imports throughout, with direct-script fallback chosen explicitly by `__package__`; no runtime path injection. A package-load regression verifies isolated sibling modules. |
| Classic pcap | Exact packet-limit EOF was reported as truncation. Version, snaplen, timestamp fraction and contradictory lengths were not consistently checked. | EOF checked before the cap; header and record validation; link type extracted from the defined low bits. Partial parse warnings stay visible in tool output. |
| pcapng framing | Block trailers, alignment, BOM, section version, remaining file size and body bounds were unchecked; a declared giant block could drive a giant allocation. | Structural checks before body reads; 1 MiB limit for recognized packet/interface blocks; unknown blocks skipped without allocating their bodies. |
| pcapng interfaces | Undefined interface references silently became Ethernet; timestamp offsets were ignored; simple packet padding was counted as captured data. | Reject invalid references; handle decimal/binary resolution and signed offsets; respect snaplen/original length and remove padding. Timestamp-less simple packets stay out of the timeline. |
| Resource arguments | Negative, non-integer, boolean and non-finite limits could produce misleading results or disable intended limits. | Explicit ranges and finite-number checks, matching schema bounds. Opened capture descriptors are checked again for regular-file type and size. |
| IPv4 | Link-layer padding could be interpreted as transport/application bytes beyond the declared IP length. | Enforce version and IHL/total-length consistency; slice transport data to the declared IP extent; record capture truncation. |
| IPv6 | Fragment, AH and ESP headers were treated as ordinary eight-byte-unit extension headers. | Dedicated fragment and AH layouts, bounded traversal, fragment offset handling, payload-length boundary, and opaque ESP handling. |
| TCP / UDP | Invalid TCP data offsets and short/oversized UDP lengths were not consistently respected. | Validate transport bounds and bound application parsing to captured, declared bytes. |
| DNS / TLS | DNS-over-TCP's two-byte prefix was passed to the DNS decoder. TLS SNI could extend beyond the declared record/extension. DNS compression cycles could return partial names. | Honor DNS framing, bound SNI nested lengths, reject compression cycles and invalid labels. No stream reassembly is claimed. |
| ARP / VLAN | ARP assumed Ethernet/IPv4 layout; provider VLAN tags were not recognized. | Verify ARP hardware/protocol lengths; accept 802.1ad tags. |
| Scan findings | SYN-ACK replies lived in reverse flows, so successful scans of services could be counted as unanswered probes. | Link reverse responses after aggregation, including out-of-order captures; count reverse-direction resets in the explanation; use incremental sliding-window counters to avoid quadratic work on dense successful connections. A fully successful 25-service connection fixture now produces no port-scan finding. |
| Beacon findings | Repeated SYNs on one five-tuple were collapsed into one flow start. | Preserve observed SYN timestamps and deduplicate identical timestamps. Retransmissions remain a possible source of periodic observations; this is not full session reconstruction. |
| DNS heuristics | A character-uniqueness ratio was described as entropy. | Compute Shannon entropy for the relevant label test. Removed unused response bookkeeping. |
| Analysis cost | DNS-name association nested every query over every host. | Use a set intersection per host, avoiding that cross product. |
| Timeline | Epoch zero and single-timestamp captures disappeared; the final packet of long captures could fall beyond the bucket cap. | Preserve valid epoch zero and signed timestamp offsets, make one bucket for instantaneous captures, and include the endpoint when limiting to 500 buckets. |
| Queries | Negative or huge result counts and reversed/non-finite time bounds were accepted. A window inside a bucket omitted that bucket. | Validate result count and sort field; validate bounds; return overlapping aggregate buckets. |
| Cache | Cache eviction was unsynchronized and decoded packet objects were retained unnecessarily. | Lock cache operations, keep local references safe during eviction, use random IDs, release raw buffers, and retain aggregate analysis only. The five-entry process cache is not durable or per-conversation storage. |
| Reports | The accepted protocol and time filters were ignored. Timeline selection did not filter graph edges. Pause/resume reset playback. The timeline was pushed outside the viewport. | Apply initial filters; filter by conversation lifetime overlap; preserve playback position; use a flex layout with a visible timeline and a reset control. |
| Responsive graph | Desktop positions could put the graph outside a narrow viewport; disconnected hosts could drift out of view. | Deterministic initial positions, bounded velocities, stronger center gravity, and fitting on container resize. |
| Report persistence | Direct writes could leave partial files or follow an existing output symlink. | Write a private temporary file and atomically replace the destination. A regression verifies that a symlink target remains untouched. |
| Slash command | Quoted file paths were not normalized; visualization failure could still be presented as an available report. | Parse quoted paths; report visualization failures and capture warnings explicitly. |
| Documentation | Invented example output, catalog-install assumptions, false official branding, exaggerated privacy/streaming claims, and unrelated old media. | Replace the README and all five old assets; use observed output, direct-repository installation, limited metadata disclosures, explicit limitations, attributed artwork and actual report captures. |
| Report visual design | The old dark UI did not match the requested Nous reference. | Restyle the actual report with electric blue, warm paper, editorial typography, restrained controls and responsive layouts; recapture the real result. |

## Test environment and coverage

Local tests ran on macOS/Apple Silicon with Python 3.9.6 and Python 3.11.18. Upstream Hermes validation ran with Python 3.11.18 in a temporary environment. CI is configured for Python 3.11 and 3.13 on Linux, macOS and Windows; those remote jobs have not run in this local session.

```text
analyze.py       95%
decode.py        76%
heuristics.py    90%
main.py          72%
pcap_reader.py   82%
report.py        93%
tools.py         91%
TOTAL            84%
```

Reproduce runtime tests:

```bash
python -m pip install -r requirements-dev.txt
python -m coverage run --source=pcap_reader,decode,analyze,heuristics,report,tools,main -m pytest -q
python -m coverage report --fail-under=75
python -m ruff check . --select F
```

The seeded decoder corpus includes 1,000 random frames across all five supported link types. Regression fixtures cover both pcap byte orders, pcapng mixed sections, binary timestamp resolution/offsets, padding, malformed blocks, fragments, nested length bounds, malicious HTML strings, successful connection false positives, time bounds, package imports and atomic output.

Optional real-browser verification and capture:

```bash
python -m pip install -r requirements-media.txt
python -m playwright install chromium
python scripts/capture_report.py /absolute/path/to/generated-report.html
```

The capture script uses the locally installed Google Chrome on macOS when present; otherwise it uses Playwright Chromium. It writes showcase captures to `assets/` and intermediate recordings to the ignored `media-work/` directory. See [media provenance](MEDIA.md).

## Remaining boundaries

- This is a lightweight parser with port-based labeling and packet-local application extraction. It does not reassemble TCP or fragments, decrypt traffic, validate checksums, or parse full DNS answer mappings.
- The file/packet/time limits bound ingestion, but the reader budget does not cover all subsequent computation. Memory is proportional to captured data and aggregate cardinality. The tool cache is shared within the plugin process and evicts after five analyses.
- Time filtering and replay use aggregate buckets and conversation lifetimes. They do not replay individual packets or recompute summary counters for filtered intervals.
- Finding thresholds are heuristics, not validated classifier performance. Legitimate retries, periodic jobs and scanning can trigger observations.
- The source tree in this workspace is modified and uncommitted. Catalog submission must pin a published, reviewed commit containing the final files and rerun validation on that exact commit. Local success is not marketplace acceptance.
