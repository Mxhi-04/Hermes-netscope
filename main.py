"""
main.py — Hermes Agent plugin entry point for netscope.

Registers tools, slash command, and bundled skill.
No hooks or middleware registered (minimal capability footprint).
"""

import sys
import logging
from pathlib import Path

_plugin_dir = str(Path(__file__).parent.resolve())
if _plugin_dir not in sys.path:
    sys.path.insert(0, _plugin_dir)

try:
    from .tools import handle_analyze, handle_query, handle_visualize
    from .schemas import ANALYZE_SCHEMA, QUERY_SCHEMA, VISUALIZE_SCHEMA
except ImportError:
    from tools import handle_analyze, handle_query, handle_visualize
    from schemas import ANALYZE_SCHEMA, QUERY_SCHEMA, VISUALIZE_SCHEMA

logger = logging.getLogger(__name__)


def register(ctx):
    """Entry point called by Hermes PluginManager when the plugin is loaded.

    Registers:
    - netscope_analyze tool
    - netscope_query tool
    - netscope_visualize tool
    - /netscope slash command
    - netscope skill
    """
    logger.info("Initializing netscope plugin...")

    # 1. Register tools
    def analyze_tool(pcap_path: str, max_packets: int = None) -> str:
        """Parse and analyze a pcap/pcapng capture file."""
        return handle_analyze(pcap_path, max_packets)

    def query_tool(analysis_id: str, query: str, ip: str = None,
                   n: int = 10, by: str = "bytes",
                   start: float = None, end: float = None) -> str:
        """Query an analyzed capture by analysis_id."""
        kwargs = {}
        if ip is not None:
            kwargs['ip'] = ip
        if n is not None:
            kwargs['n'] = n
        if by is not None:
            kwargs['by'] = by
        if start is not None:
            kwargs['start'] = start
        if end is not None:
            kwargs['end'] = end
        return handle_query(analysis_id, query, **kwargs)

    def visualize_tool(analysis_id: str, focus_host: str = None,
                       protocol: str = None, start: float = None,
                       end: float = None) -> str:
        """Generate a self-contained interactive HTML report."""
        return handle_visualize(analysis_id, focus_host, protocol, start, end)

    ctx.register_tool(
        name="netscope_analyze",
        toolset="netscope",
        schema=ANALYZE_SCHEMA,
        handler=analyze_tool,
    )

    ctx.register_tool(
        name="netscope_query",
        toolset="netscope",
        schema=QUERY_SCHEMA,
        handler=query_tool,
    )

    ctx.register_tool(
        name="netscope_visualize",
        toolset="netscope",
        schema=VISUALIZE_SCHEMA,
        handler=visualize_tool,
    )

    # 2. Register slash command: /netscope <path>
    def handle_netscope_cmd(raw_args: str) -> str:
        """Run analyze + visualize and return summary + report path."""
        pcap_path = raw_args.strip() if raw_args else ""
        if not pcap_path:
            return "Usage: /netscope <path/to/capture.pcap>"

        # Run analyze
        analyze_result_str = handle_analyze(pcap_path)
        import json
        try:
            res = json.loads(analyze_result_str)
        except Exception:
            return f"Analysis failed: {analyze_result_str}"

        if not res.get('ok'):
            return f"Error: {res.get('error', 'Unknown error')}"

        analysis_id = res['analysis_id']

        # Run visualize
        vis_result_str = handle_visualize(analysis_id)
        try:
            vis_res = json.loads(vis_result_str)
            report_path = vis_res.get('report_path', 'unknown')
        except Exception:
            report_path = "failed to generate"

        # Format output
        dur = res.get('capture_duration_sec', 0)
        pkts = res.get('total_packets', 0)
        nbytes = res.get('total_bytes', 0)
        hosts = res.get('host_count', 0)
        flows = res.get('flow_count', 0)
        findings = res.get('findings_summary', [])

        lines = [
            f"⬡ netScope Analysis: {pcap_path}",
            f"• Packets: {pkts:,} | Bytes: {nbytes:,} | Duration: {dur:.1f}s",
            f"• Hosts: {hosts} | Flows: {flows}",
        ]

        if findings:
            lines.append(f"\nFindings ({len(findings)}):")
            for f in findings:
                kind = f['kind'].replace('_', ' ').title()
                lines.append(f"  ⚠ [{f['severity'].upper()}] {kind}: {f['why'][:120]}…")
        else:
            lines.append("\nNo anomaly heuristics triggered.")

        lines.append(f"\n📊 Interactive Report: {report_path}")
        lines.append("Open this file in your browser to explore the network graph, replay traffic, and inspect findings.")
        lines.append("\nNote: Findings are heuristic observations, not definitive security verdicts.")

        return "\n".join(lines)

    ctx.register_command(
        name="netscope",
        handler=handle_netscope_cmd,
        description="Analyze a pcap/pcapng capture and generate an interactive report: /netscope <path>"
    )

    # 3. Register bundled skill
    skill_file = Path(__file__).parent / "skills" / "netscope" / "SKILL.md"
    if skill_file.exists():
        ctx.register_skill(name="netscope", path=skill_file)
    else:
        root_skill = Path(__file__).parent / "SKILL.md"
        if root_skill.exists():
            ctx.register_skill(name="netscope", path=root_skill)
        else:
            logger.warning("netscope SKILL.md not found")

    logger.info("netscope plugin registered successfully (3 tools, 1 command, 1 skill)")
