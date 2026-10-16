"""Audit MCP server configs for permission risk signals."""

from __future__ import annotations

import json
import re
from pathlib import Path


class ConfigError(Exception):
    pass


# Env var NAME fragments that strongly suggest an embedded secret.
SECRET_NAME_RES = [
    re.compile(p, re.IGNORECASE) for p in (
        r"key", r"token", r"secret", r"password", r"passwd",
        r"credential", r"private_key", r"api[_-]?key", r"auth",
    )
]

SHELL_WRAPPERS = {"sh", "bash", "zsh", "fish", "cmd", "cmd.exe",
                  "powershell", "powershell.exe", "pwsh"}

# Bare-name runtimes we recognize. Anything else bare is "unknown".
KNOWN_RUNTIMES = {"node", "npx", "uvx", "uv", "python", "python3",
                  "deno", "bun", "docker", "podman", "java"}

NETWORK_HINTS = ("0.0.0.0", "--host", "--port", "http://", "https://",
                 "--listen", "--bind")


def _looks_like_url(s: str) -> bool:
    return bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", s))


def load_servers(path: str | Path) -> tuple[dict, bool]:
    """Load an MCP config file.

    Returns (servers_dict, wrapped) where wrapped is True when the file used
    the {"mcpServers": {...}} envelope (so harden can preserve the shape).
    Supports Claude Code ~/.claude.json and generic {mcpServers:{...}} files,
    plus bare {name: {...}} maps.
    """
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError("config file not found: %s" % p)
    except json.JSONDecodeError as e:
        raise ConfigError("invalid JSON in %s: %s" % (p, e))
    if not isinstance(data, dict):
        raise ConfigError("top-level JSON must be an object in %s" % p)
    if isinstance(data.get("mcpServers"), dict):
        return data["mcpServers"], True
    # Bare map? Every value must be an object with a "command".
    if data and all(isinstance(v, dict) and "command" in v
                    for v in data.values()):
        return data, False
    raise ConfigError(
        "no MCP servers found in %s: expected {\"mcpServers\": {...}} "
        "or a bare {name: {command: ...}} map" % p)


def _finding(server, check, severity, message, remediation):
    return {
        "server": server,
        "check": check,
        "severity": severity,
        "message": message,
        "remediation": remediation,
    }


def audit_server(name: str, cfg: dict) -> list[dict]:
    """Audit one server entry. Returns a list of findings."""
    findings: list[dict] = []
    if not isinstance(cfg, dict):
        return [_finding(name, "malformed-entry", "high",
                         "server entry is not an object; cannot evaluate it.",
                         "Replace it with {\"command\": ..., \"args\": [...], "
                         "\"env\": {...}}.")]
    command = cfg.get("command", "")
    args = cfg.get("args", []) or []
    env = cfg.get("env", {}) or {}
    if not isinstance(args, list):
        args = [args]
    cmd_base = Path(str(command)).name.lower() if command else ""
    joined = " ".join([str(command)] + [str(a) for a in args])

    # 1. Secrets embedded in env (by NAME — values are never echoed).
    if isinstance(env, dict):
        for var in env:
            if any(rx.search(str(var)) for rx in SECRET_NAME_RES):
                findings.append(_finding(
                    name, "secret-in-env", "high",
                    "env var %r looks like an embedded secret "
                    "(matched by name; value not shown)." % var,
                    "Remove the literal value: use ${%s} passthrough from "
                    "your shell environment or a secrets manager, and keep "
                    "secrets out of the config file." % var))

    # 2. Shell wrappers — arbitrary command execution by construction.
    if cmd_base in SHELL_WRAPPERS or (
            args and str(args[0]).strip() in ("-c", "/c")):
        findings.append(_finding(
            name, "shell-wrapper", "high",
            "server runs through a shell (%r); the shell string can do "
            "anything the user can." % command,
            "Replace the wrapper with the real executable and an explicit "
            "args list, or pin down exactly what the shell string may do."))

    # 3. Network exposure hints in args.
    lowered = joined.lower()
    if any(h in lowered for h in NETWORK_HINTS) or any(
            _looks_like_url(str(a)) for a in args):
        findings.append(_finding(
            name, "network-exposed", "medium",
            "command/args suggest the server binds to or contacts the "
            "network (%r)." % _truncate(joined, 80),
            "Bind to 127.0.0.1 only, drop unneeded --host/--port flags, and "
            "document why this server needs network access."))

    # 4. Executable provenance.
    if command:
        cmd_str = str(command)
        if ("/" in cmd_str or "\\" in cmd_str) and not Path(cmd_str).is_absolute():
            findings.append(_finding(
                name, "relative-executable", "low",
                "command uses a relative path (%r); resolution depends on "
                "the working directory." % cmd_str,
                "Use an absolute path so the binary cannot be shadowed by "
                "CWD contents."))
        elif "/" not in cmd_str and "\\" not in cmd_str \
                and cmd_base not in KNOWN_RUNTIMES \
                and cmd_base not in SHELL_WRAPPERS:
            # Shells are already covered by the shell-wrapper check above;
            # don't double-flag them here.
            findings.append(_finding(
                name, "unknown-executable", "medium",
                "command %r is a bare name that is not a recognized "
                "runtime; it resolves via PATH." % cmd_str,
                "Use an absolute path, or confirm the PATH entry is "
                "controlled by you."))
        # npx/uvx remote packages should be version-pinned.
        if cmd_base in ("npx", "uvx"):
            pkgs = [str(a) for a in args
                    if a and not str(a).startswith("-") and "@" not in str(a)
                    and not str(a).startswith(".") and "/" not in str(a)]
            if pkgs:
                findings.append(_finding(
                    name, "unpinned-remote-package", "medium",
                    "npx/uvx fetches remote package(s) without a version pin: "
                    "%s. A future publish can change what runs." % ", ".join(pkgs),
                    "Pin the version (pkg@x.y.z) or vendor the package "
                    "locally."))
    else:
        findings.append(_finding(
            name, "missing-command", "high",
            "server entry has no \"command\"; it cannot run as configured.",
            "Add an explicit \"command\" (absolute path preferred)."))

    return findings


def _truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


def audit_config(path: str | Path) -> dict:
    """Audit a whole config file. Returns {servers, findings, summary}."""
    servers, wrapped = load_servers(path)
    all_findings: list[dict] = []
    for name, cfg in servers.items():
        all_findings.extend(audit_server(name, cfg))
    by_sev = {"high": 0, "medium": 0, "low": 0}
    for f in all_findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    return {
        "config": str(path),
        "servers": sorted(servers),
        "wrapped": wrapped,
        "findings": all_findings,
        "summary": {
            "servers": len(servers),
            "findings": len(all_findings),
            **by_sev,
        },
    }
