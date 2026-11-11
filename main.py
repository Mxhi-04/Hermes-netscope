"""
main.py — Hermes Agent plugin entry point for netscope.

Registers tools, slash command, and bundled skill.
No hooks or middleware registered (minimal capability footprint).
"""

import logging
import shlex
from pathlib import Path

if __package__:
    from .tools import handle_analyze, handle_query, handle_visualize
    from .schemas import ANALYZE_SCHEMA, QUERY_SCHEMA, VISUALIZE_SCHEMA
else:
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
    def analyze_tool(*args, **kwargs) -> str:
        """Parse and analyze a pcap/pcapng capture file."""
        import json
        params = {}
        if args and isinstance(args[0], dict):
            params.update(args[0])
        elif args:
            if len(args) >= 1:
                params["pcap_path"] = args[0]
            if len(args) >= 2:
                params["max_packets"] = args[1]
        params.update(kwargs)
        pcap_path = params.get("pcap_path")
        if not pcap_path:
            return json.dumps({"ok": False, "error": "Missing required argument: pcap_path"})
        return handle_analyze(pcap_path, params.get("max_packets"))

    def query_tool(*args, **kwargs) -> str:
        """Query an analyzed capture by analysis_id."""
        import json
        params = {}
        if args and isinstance(args[0], dict):
            params.update(args[0])
        elif args:
            if len(args) >= 1:
                params["analysis_id"] = args[0]
            if len(args) >= 2:
                params["query"] = args[1]
        params.update(kwargs)
        aid = params.get("analysis_id")
        q = params.get("query")
        if not aid or not q:
            return json.dumps({"ok": False, "error": "Missing required arguments: analysis_id and query"})
        call_kwargs = {}
        for k in ("ip", "n", "by", "start", "end"):
            if k in params:
                call_kwargs[k] = params[k]
        return handle_query(aid, q, **call_kwargs)

    def visualize_tool(*args, **kwargs) -> str:
        """Generate a self-contained interactive HTML report."""
        import json
        params = {}
        if args and isinstance(args[0], dict):
            params.update(args[0])
        elif args:
            if len(args) >= 1:
                params["analysis_id"] = args[0]
        params.update(kwargs)
        aid = params.get("analysis_id")
        if not aid:
            return json.dumps({"ok": False, "error": "Missing required argument: analysis_id"})
        return handle_visualize(
            aid,
            focus_host=params.get("focus_host"),
            protocol=params.get("protocol"),
            start=params.get("start"),
            end=params.get("end"),
        )

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
        if pcap_path[0:1] in ('"', "'"):
            try:
                parts = shlex.split(pcap_path)
                if len(parts) != 1:
                    return 'Usage: /netscope <path/to/capture.pcap>'
                pcap_path = parts[0]
            except ValueError as exc:
                return f'Invalid quoted path: {exc}'

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
            report_path = vis_res.get('report_path') if vis_res.get('ok') else None
            report_error = vis_res.get('error', 'Unknown visualization error')
        except Exception:
            report_path = None
            report_error = 'Invalid visualization response'

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

        if report_path:
            lines.append(f"\n📊 Interactive Report: {report_path}")
            lines.append("Open this file in your browser to explore the network graph, replay traffic, and inspect findings.")
        else:
            lines.append(f'\nReport generation failed: {report_error}')
        if res.get('truncated'):
            lines.append(f"\nPartial capture: {res.get('truncation_reason')}")
        for error in res.get('errors', [])[:3]:
            lines.append(f'Capture warning: {error}')
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
