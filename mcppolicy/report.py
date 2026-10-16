"""Terminal + JSON renderers."""

from __future__ import annotations

import json

SEV_ORDER = {"high": 0, "medium": 1, "low": 2}
SEV_TAG = {"high": "[HIGH]", "medium": "[MED ]", "low": "[LOW ]"}


def render_audit(result: dict) -> str:
    lines = []
    lines.append("mcp-policy audit: %s" % result["config"])
    lines.append("servers: %d (%s)" % (
        result["summary"]["servers"], ", ".join(result["servers"]) or "none"))
    s = result["summary"]
    lines.append("findings: %d (high=%d medium=%d low=%d)" % (
        s["findings"], s["high"], s["medium"], s["low"]))
    lines.append("")
    findings = sorted(result["findings"],
                      key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["server"]))
    if not findings:
        lines.append("No risk signals found.")
    for f in findings:
        lines.append("%s %s — %s" % (
            SEV_TAG.get(f["severity"], "[????]"), f["server"], f["check"]))
        lines.append("       %s" % f["message"])
        lines.append("       fix: %s" % f["remediation"])
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_harden(result: dict) -> str:
    lines = []
    lines.append("mcp-policy harden")
    lines.append("input:  %s" % result["input"])
    lines.append("policy: %s" % result["policy"])
    lines.append("output: %s (original untouched)" % result["output"])
    for w in result["warnings"]:
        lines.append("warning: %s" % w)
    s = result["summary"]
    lines.append("")
    lines.append("kept %d/%d servers, dropped %d, scrubbed %d env var(s)" % (
        s["servers_kept"], s["servers_in"],
        s["servers_dropped"], s["env_vars_scrubbed"]))
    if result["dropped_servers"]:
        lines.append("")
        lines.append("dropped servers:")
        for d in result["dropped_servers"]:
            lines.append("  - %s (%s)" % (d["server"], d["reason"]))
    if result["scrubbed_env"]:
        lines.append("")
        lines.append("scrubbed env vars (values never shown):")
        for e in result["scrubbed_env"]:
            lines.append("  - %s on %s" % (e["var"], e["server"]))
    if result["kept"]:
        lines.append("")
        lines.append("kept: %s" % ", ".join(result["kept"]))
    return "\n".join(lines) + "\n"


def to_json(obj: dict) -> str:
    return json.dumps(obj, indent=2) + "\n"
