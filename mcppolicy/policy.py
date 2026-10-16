"""Minimal YAML-subset parser for mcp-policy files.

The policy format is deliberately tiny so it needs no third-party YAML
library. Supported:

    # comments and blank lines are ignored
    require_allowlist: true        # scalar: true/false or plain string
    allow_servers:                 # list: indented "- item" lines
      - filesystem
      - github
    deny_servers:
      - evil-server
    deny_env_patterns:             # regexes, matched against env var NAMES
      - ".*KEY.*"
    deny_commands:                 # substrings, matched against command+args
      - "sh -c"

Anything else (nested maps, flow syntax, anchors, multi-line strings)
raises PolicyError with a line number. Quoted scalars may use single or
double quotes; surrounding quotes are stripped.
"""

from __future__ import annotations


class PolicyError(Exception):
    pass


def _unquote(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        return s[1:-1]
    return s


def _scalar(s: str):
    s = s.strip()
    low = s.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    return _unquote(s)


def parse_policy(text: str) -> dict:
    """Parse the policy YAML subset. Returns a dict. Raises PolicyError."""
    policy: dict = {}
    current_list_key = None
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip("\n")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("- ") or stripped == "-":
            if current_list_key is None:
                raise PolicyError(
                    "line %d: list item outside of a list key" % lineno)
            item = stripped[1:].strip()
            # strip inline comments not inside quotes (best effort)
            policy[current_list_key].append(_unquote(_strip_inline_comment(item)))
            continue
        if ":" not in stripped:
            raise PolicyError(
                "line %d: expected 'key: value' or '- item', got %r"
                % (lineno, stripped))
        key, _, value = stripped.partition(":")
        key = key.strip()
        if not key or " " in key:
            raise PolicyError("line %d: invalid key %r" % (lineno, key))
        value = value.strip()
        current_list_key = None
        if value == "":
            policy[key] = []
            current_list_key = key
        else:
            policy[key] = _scalar(_strip_inline_comment(value))
    return policy


def _strip_inline_comment(s: str) -> str:
    """Remove a ' #...' comment unless inside quotes (best effort)."""
    in_s = in_d = False
    for i, ch in enumerate(s):
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        elif ch == "#" and not in_s and not in_d and i > 0 and s[i - 1] == " ":
            return s[:i].rstrip()
    return s


EXAMPLE_POLICY = """\
# mcp-policy example — annotated. Written by `mcppolicy policy-init`.
#
# This file is read by `mcppolicy harden`. Unknown keys are ignored with a
# warning; missing keys mean "no constraint".

# If true, ONLY servers listed in allow_servers may run. Everything else
# is dropped from the hardened config.
require_allowlist: true

# Servers allowed to run (by their config key name).
allow_servers:
  - filesystem
  - github

# Servers that are always dropped, even if allowlisted.
deny_servers:
  - legacy-internal-tool

# Regexes matched (case-insensitive) against environment variable NAMES.
# Matching vars are scrubbed from the hardened config — their values are
# never printed. Prefer ${VAR} passthrough or a secrets manager instead of
# embedding secrets in the config file.
deny_env_patterns:
  - ".*KEY.*"
  - ".*TOKEN.*"
  - ".*SECRET.*"
  - ".*PASSWORD.*"

# Substrings matched (case-insensitive) against "command + args" joined.
# A server matching any pattern is dropped.
deny_commands:
  - "sh -c"
  - "bash -c"
"""
