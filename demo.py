"""Run the plugin's actual tool handlers without a Hermes installation."""
import argparse
import json

if __package__:
    from .tools import handle_analyze, handle_visualize
else:
    from tools import handle_analyze, handle_visualize


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pcap_path', help='Local .pcap or .pcapng file')
    parser.add_argument('--max-packets', type=int, default=None)
    parser.add_argument('--report', action='store_true', help='Also write the interactive HTML report')
    args = parser.parse_args()
    result = json.loads(handle_analyze(args.pcap_path, args.max_packets))
    print(json.dumps(result, indent=2))
    if not result['ok']:
        return 1
    if args.report:
        report = json.loads(handle_visualize(result['analysis_id']))
        print(json.dumps(report, indent=2))
        return 0 if report['ok'] else 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
