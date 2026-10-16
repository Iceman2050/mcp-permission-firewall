#!/usr/bin/env python3
"""mcppolicy — audit and harden MCP server configs.

v0.1 is a policy AUDITOR + config HARDENER. It reads config files and
writes hardened copies. It does NOT sandbox, proxy, or otherwise control
running MCP servers (see README "What this is NOT").
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcppolicy import __version__  # noqa: E402
from mcppolicy.audit import ConfigError, audit_config  # noqa: E402
from mcppolicy.harden import harden_config  # noqa: E402
from mcppolicy.policy import EXAMPLE_POLICY, PolicyError  # noqa: E402
from mcppolicy.report import render_audit, render_harden, to_json  # noqa: E402

SEV_RANK = {"low": 0, "medium": 1, "high": 2}


def cmd_audit(args) -> int:
    try:
        result = audit_config(args.config)
    except ConfigError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    if args.json:
        print(to_json(result), end="")
    else:
        print(render_audit(result), end="")
    if args.fail_on:
        threshold = SEV_RANK[args.fail_on]
        if any(SEV_RANK.get(f["severity"], 0) >= threshold
               for f in result["findings"]):
            return 1
    return 0


def cmd_harden(args) -> int:
    try:
        result = harden_config(args.config, args.policy, args.output)
    except (ConfigError, PolicyError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    if args.json:
        print(to_json(result), end="")
    else:
        print(render_harden(result), end="")
    return 0


def cmd_policy_init(args) -> int:
    path = args.output or "mcp-policy.yaml"
    if os.path.exists(path) and not args.force:
        print("error: %s exists (use --force to overwrite)" % path,
              file=sys.stderr)
        return 2
    with open(path, "w", encoding="utf-8") as f:
        f.write(EXAMPLE_POLICY)
    print("wrote example policy to %s" % path)
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="mcppolicy",
        description="Audit and harden MCP server configs (v0.1: auditor, "
                    "not a live proxy).")
    ap.add_argument("--version", action="version", version="%(prog)s " + __version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("audit", help="audit a config file for risk signals")
    a.add_argument("--config", required=True, help="MCP config JSON file")
    a.add_argument("--json", action="store_true", help="machine-readable output")
    a.add_argument("--fail-on", choices=("low", "medium", "high"),
                   help="exit 1 if any finding at/above this severity")
    a.set_defaults(func=cmd_audit)

    h = sub.add_parser("harden", help="write a policy-hardened copy of a config")
    h.add_argument("--config", required=True)
    h.add_argument("--policy", required=True, help="policy YAML file")
    h.add_argument("--output", help="output path (default: <config>.hardened.json)")
    h.add_argument("--json", action="store_true")
    h.set_defaults(func=cmd_harden)

    p = sub.add_parser("policy-init", help="write an annotated example policy")
    p.add_argument("--output", help="output path (default: mcp-policy.yaml)")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_policy_init)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
