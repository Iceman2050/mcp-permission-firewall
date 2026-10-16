"""Apply a policy to an MCP config: drop/scrub violations, write hardened copy."""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path

from .audit import ConfigError, load_servers
from .policy import PolicyError, parse_policy

KNOWN_POLICY_KEYS = {
    "require_allowlist", "allow_servers", "deny_servers",
    "deny_env_patterns", "deny_commands",
}


def load_policy(path: str | Path) -> tuple[dict, list[str]]:
    """Parse a policy file. Returns (policy, warnings)."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise PolicyError("policy file not found: %s" % p)
    policy = parse_policy(text)
    warnings = []
    for key in policy:
        if key not in KNOWN_POLICY_KEYS:
            warnings.append("unknown policy key %r ignored" % key)
    # Normalize shapes.
    for key in ("allow_servers", "deny_servers",
                "deny_env_patterns", "deny_commands"):
        v = policy.get(key, [])
        if not isinstance(v, list):
            raise PolicyError(
                "policy key %r must be a list" % key)
        policy[key] = [str(x) for x in v]
    if "require_allowlist" not in policy:
        policy["require_allowlist"] = False
    if not isinstance(policy["require_allowlist"], bool):
        raise PolicyError("require_allowlist must be true or false")
    # Validate env regexes eagerly so bad patterns fail fast at load time.
    _compile_env_patterns(policy["deny_env_patterns"])
    return policy, warnings


def _compile_env_patterns(patterns: list[str]) -> list[re.Pattern]:
    compiled = []
    for pat in patterns:
        try:
            compiled.append(re.compile(pat, re.IGNORECASE))
        except re.error as e:
            raise PolicyError("bad deny_env_patterns regex %r: %s" % (pat, e))
    return compiled


def harden_config(config_path: str | Path, policy_path: str | Path,
                  out_path: str | Path | None = None) -> dict:
    """Apply policy; write hardened config. Never touches the original.

    Returns a result dict with the diff summary.
    """
    servers, wrapped = load_servers(config_path)
    policy, warnings = load_policy(policy_path)
    env_res = _compile_env_patterns(policy["deny_env_patterns"])
    deny_cmds = [d.lower() for d in policy["deny_commands"]]
    allow = set(policy["allow_servers"])
    deny = set(policy["deny_servers"])
    require_allow = policy["require_allowlist"]

    kept: dict = {}
    dropped_servers: list[dict] = []
    scrubbed_env: list[dict] = []

    for name, cfg in servers.items():
        cfg = copy.deepcopy(cfg) if isinstance(cfg, dict) else cfg
        reason = None
        if name in deny:
            reason = "deny_servers"
        elif require_allow and name not in allow:
            reason = "not in allow_servers (require_allowlist)"
        else:
            cmd = cfg.get("command", "") if isinstance(cfg, dict) else ""
            args = cfg.get("args", []) if isinstance(cfg, dict) else []
            joined = " ".join([str(cmd)] + [str(a) for a in args]).lower()
            hit = next((d for d in deny_cmds if d and d in joined), None)
            if hit:
                reason = "deny_commands matched %r" % hit
        if reason:
            dropped_servers.append({"server": name, "reason": reason})
            continue
        if isinstance(cfg, dict) and isinstance(cfg.get("env"), dict):
            for var in list(cfg["env"]):
                if any(rx.search(str(var)) for rx in env_res):
                    del cfg["env"][var]
                    scrubbed_env.append({"server": name, "var": var})
        kept[name] = cfg

    if out_path is None:
        out_path = str(config_path) + ".hardened.json"
    out_doc = {"mcpServers": kept} if wrapped else kept
    Path(out_path).write_text(
        json.dumps(out_doc, indent=2) + "\n", encoding="utf-8")

    return {
        "input": str(config_path),
        "policy": str(policy_path),
        "output": str(out_path),
        "warnings": warnings,
        "kept": sorted(kept),
        "dropped_servers": dropped_servers,
        "scrubbed_env": scrubbed_env,
        "summary": {
            "servers_in": len(servers),
            "servers_kept": len(kept),
            "servers_dropped": len(dropped_servers),
            "env_vars_scrubbed": len(scrubbed_env),
        },
    }
