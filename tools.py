"""
tools.py — Tool handlers for netscope.

All handlers return JSON strings, never raise. Errors are
{"ok": false, "error": "..."}.
"""

import json
import os
import uuid
import logging
from pathlib import Path
from threading import RLock

if __package__:
    from .pcap_reader import read_pcap, PcapError, DEFAULT_MAX_PACKETS
    from .decode import decode_packet
    from .analyze import analyze_packets, query_analysis
    from .heuristics import detect_all
    from .report import generate_report
else:
    from pcap_reader import read_pcap, PcapError, DEFAULT_MAX_PACKETS
    from decode import decode_packet
    from analyze import analyze_packets, query_analysis
    from heuristics import detect_all
    from report import generate_report

logger = logging.getLogger(__name__)

# In-memory analysis cache (bounded)
_analysis_cache = {}
_MAX_CACHE_SIZE = 5
_cache_lock = RLock()


def _get_reports_dir():
    """Get the reports output directory."""
    hermes_home = os.environ.get('HERMES_HOME', '')
    if hermes_home:
        reports_dir = Path(hermes_home) / 'netscope' / 'reports'
    else:
        reports_dir = Path.home() / '.hermes' / 'netscope' / 'reports'
    reports_dir.mkdir(parents=True, exist_ok=True)
    return reports_dir


def _make_analysis_id(pcap_path):
    """Generate an unguessable process-local analysis identifier."""
    return f"ns_{uuid.uuid4().hex[:16]}"


def _cache_put(analysis_id, data):
    """Store analysis in cache, evicting oldest if needed."""
    with _cache_lock:
        if len(_analysis_cache) >= _MAX_CACHE_SIZE:
            oldest = next(iter(_analysis_cache))
            del _analysis_cache[oldest]
        _analysis_cache[analysis_id] = data


def _cache_get(analysis_id):
    with _cache_lock:
        return _analysis_cache.get(analysis_id)



def handle_analyze(pcap_path, max_packets=None):
    """Handle netscope_analyze tool call.

    Args:
        pcap_path: Path to pcap/pcapng file.
        max_packets: Optional max packets to read.

    Returns:
        JSON string with analysis summary.
    """
    try:
        if not pcap_path:
            return json.dumps({'ok': False, 'error': 'Missing required argument: pcap_path'})
        if max_packets is None:
            max_packets = DEFAULT_MAX_PACKETS

        # Parse
        read_result = read_pcap(pcap_path, max_packets=max_packets)

        # Decode
        decoded = []
        for raw_pkt in read_result.packets:
            decoded.append(decode_packet(raw_pkt))

        # Release raw payloads before aggregation and never cache them.
        read_result.packets.clear()

        # Analyze
        analysis = analyze_packets(decoded, read_result)

        # Heuristics
        findings = detect_all(analysis)

        # Cache
        analysis_id = _make_analysis_id(pcap_path)
        _cache_put(analysis_id, {
            'analysis': analysis,
            'findings': findings,
            'pcap_path': pcap_path,
        })

        summary = analysis.summary_dict()
        summary['ok'] = True
        summary['analysis_id'] = analysis_id
        summary['findings_count'] = len(findings)
        summary['findings_summary'] = [
            {'kind': f['kind'], 'severity': f['severity'],
             'confidence': f['confidence'],
             'why': f['why'][:200]}
            for f in findings[:10]
        ]

        return json.dumps(summary, default=str)

    except PcapError as e:
        return json.dumps({'ok': False, 'error': str(e)})
    except Exception as e:
        logger.exception("netscope_analyze failed")
        return json.dumps({'ok': False, 'error': f"Analysis failed: {e}"})


def handle_query(analysis_id, query, **kwargs):
    """Handle netscope_query tool call.

    Args:
        analysis_id: ID from previous analyze call.
        query: Query type string.
        **kwargs: Query-specific parameters.

    Returns:
        JSON string with query results.
    """
    try:
        cached = _cache_get(analysis_id)
        if cached is None:
            return json.dumps({
                'ok': False,
                'error': f"Analysis not found: {analysis_id}. Run netscope_analyze first."
            })

        analysis = cached['analysis']
        findings = cached['findings']

        if query == 'findings':
            kwargs['findings'] = findings

        result = query_analysis(analysis, query, **kwargs)
        result['ok'] = ('error' not in result) and result.get('ok', True)
        result['analysis_id'] = analysis_id

        return json.dumps(result, default=str)

    except Exception as e:
        logger.exception("netscope_query failed")
        return json.dumps({'ok': False, 'error': f"Query failed: {e}"})


def handle_visualize(analysis_id, focus_host=None, protocol=None,
                     start=None, end=None):
    """Handle netscope_visualize tool call.

    Args:
        analysis_id: ID from previous analyze call.
        focus_host: Optional IP to highlight.
        protocol: Optional protocol filter.
        start: Optional start timestamp.
        end: Optional end timestamp.

    Returns:
        JSON string with report path and file size.
    """
    try:
        cached = _cache_get(analysis_id)
        if cached is None:
            return json.dumps({
                'ok': False,
                'error': f"Analysis not found: {analysis_id}. Run netscope_analyze first."
            })

        analysis = cached['analysis']
        findings = cached['findings']

        reports_dir = _get_reports_dir()
        report_name = f"netscope_{analysis_id}.html"
        report_path = reports_dir / report_name

        generate_report(
            analysis=analysis,
            findings=findings,
            output_path=str(report_path),
            focus_host=focus_host,
            protocol_filter=protocol,
            time_start=start,
            time_end=end,
        )

        file_size = report_path.stat().st_size

        return json.dumps({
            'ok': True,
            'analysis_id': analysis_id,
            'report_path': str(report_path),
            'file_size': file_size,
            'file_size_human': f"{file_size / 1024:.1f} KB",
            'message': f"HTML report saved to {report_path}. Open it in a web browser to explore the interactive network graph, timeline, and findings.",
        })

    except Exception as e:
        logger.exception("netscope_visualize failed")
        return json.dumps({'ok': False, 'error': f"Visualization failed: {e}"})
