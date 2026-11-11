# Hackathon handoff

The local plugin audit and demo are prepared. Nothing has been committed, pushed, posted to X, or submitted to a form by this work.

## Before opening the catalog PR

1. Review the source diff and [audit](AUDIT.md), then publish the intended plugin commit in `Mxhi-04/Hermes-netscope`.
2. Run `hermes plugins doctor . --ci` and `hermes plugins validate .` on a checkout of that exact published commit. Current local evidence is stored beside this document.
3. Add a catalog entry in `NousResearch/hermes-agent/plugin-catalog/netscope.yaml`, using the **full reviewed 40-character commit SHA**. The template below deliberately has no fabricated SHA.

```yaml
name: netscope
repo: https://github.com/Mxhi-04/Hermes-netscope
sha: REPLACE_WITH_FULL_REVIEWED_40_CHARACTER_COMMIT_SHA
description: Offline packet capture analysis, explainable traffic findings, and interactive reports for Hermes.
maintainer: Mxhi-04
tier: community
category: tools
requires_hermes: ">=0.23.0"
version: "0.1.0"
readme: true
```

Follow the [canonical catalog schema and admission rules](https://github.com/NousResearch/hermes-agent/blob/main/plugin-catalog/README.md). The community tier is intentional. Add pinned raw GitHub URLs for the hero and report screenshots after the final commit exists.

Suggested PR description:

> netScope adds three native tools, a `/netscope` command, and a bundled investigation skill for local pcap/pcapng analysis. It returns structured host, flow, protocol and time summaries, explainable heuristic observations, and a standalone interactive HTML report.
>
> Disclosures: reads user-supplied local captures and writes local HTML reports; no network calls, credentials, runtime third-party packages, core overrides, hooks, or middleware. Limited DNS/SNI/HTTP Host/SSH metadata is extracted; packet bodies are not retained in the report or aggregate cache. Capture metadata returned to Hermes can enter the configured model conversation. Parsing is resource-limited but memory scales with capture size; findings are heuristic observations, not security verdicts. The five-entry cache is process-local. Nous artwork is attributed separately from the code license.
>
> Validation: pytest regression suite, Chromium desktop/mobile checks, current upstream Plugin Doctor and catalog validator, and real Hermes registry dispatch. See the repository audit for exact results and limits.

## Demo and social copy

Use `assets/netscope-demo.mp4`: approximately 69.2 seconds, 1920×1080 at 30 fps, female Sarvam narration, actual synthetic-capture results and report footage. Upload the original MP4 directly to X; a repository file link is not an X video upload. Include captions from `assets/demo-captions.srt` if supported.

Suggested post:

> Meet netScope — an independent community plugin for @NousResearch's Hermes Agent.
>
> Turn a local packet capture into a conversation: inspect hosts and flows, investigate explainable traffic patterns, and explore an offline interactive report.
>
> 3 native tools. Python stdlib runtime. No capture uploads by the plugin.
>
> Code: https://github.com/Mxhi-04/Hermes-netscope
>
> #HermesAgent

Then submit the catalog PR URL and the published X demo URL through the event form supplied by the organizer. According to the deadline provided in the chat, **November 11 at 5 PM EST corresponds to November 12 at 3:30 AM IST**. This handoff does not independently verify the event deadline or form availability.
