# mcp-permission-firewall

Audit and harden MCP (Model Context Protocol) server configs. Zero dependencies — Python 3.10+ stdlib only.

## The MCP permission problem, in plain words

AI coding agents (Claude Code, Cursor, and friends) run **MCP servers**: little programs listed in a JSON config file that get launched with whatever command, arguments, and environment variables the config says. There is no permission layer. A config entry can:

- run an arbitrary shell command (`"command": "sh", "args": ["-c", "..."]`),
- embed live API keys and tokens in plain text (`"env": {"API_KEY": "sk-..."}`),
- fetch and execute remote code on every launch (`"command": "npx", "args": ["some-package"]` with no version pin),
- bind to the network (`--host 0.0.0.0`).

If you paste a "recommended MCP config" from a blog post, a skill, or a chat message into your setup, you are granting all of that. `mcppolicy` audits the config *before* you trust it, and can write you a hardened copy with an allowlist policy applied.

## Install

No dependencies. Clone and run:

```sh
git clone https://github.com/Iceman2050/mcp-permission-firewall
cd mcp-permission-firewall
python3 mcppolicy.py --version
```

## Usage

**Audit a config** (Claude Code `~/.claude.json` format and generic `{mcpServers: {...}}` both work; bare `{name: {...}}` maps too):

```sh
python3 mcppolicy.py audit --config ~/.claude.json
python3 mcppolicy.py audit --config mcp.json --json            # machine-readable
python3 mcppolicy.py audit --config mcp.json --fail-on high    # exit 1 on high findings (CI gate)
```

**Harden a config** with a policy (writes `<config>.hardened.json`; the original is never modified):

```sh
python3 mcppolicy.py policy-init                       # write annotated mcp-policy.yaml
python3 mcppolicy.py harden --config mcp.json --policy mcp-policy.yaml
```

Example audit output:

```
mcp-policy audit: mcp.json
servers: 3 (evil-server, filesystem, shelltool)
findings: 4 (high=3 medium=1 low=0)

[HIGH] evil-server — secret-in-env
       env var 'BACKDOOR_KEY' looks like an embedded secret (matched by name; value not shown).
       fix: Remove the literal value: use ${BACKDOOR_KEY} passthrough ...
```

## Policy format reference (`mcp-policy.yaml`)

Simple YAML subset (no library needed — the parser is built in):

```yaml
require_allowlist: true   # only allow_servers may run; everything else dropped

allow_servers:            # permitted server names
  - filesystem
  - github

deny_servers:             # always dropped, even if allowlisted
  - legacy-internal-tool

deny_env_patterns:        # regexes vs env var NAMES (case-insensitive); values never printed
  - ".*KEY.*"
  - ".*TOKEN.*"
  - ".*SECRET.*"

deny_commands:            # substrings vs "command + args" (case-insensitive); server dropped
  - "sh -c"
```

Unknown keys produce a warning, not an error. `deny_env_patterns` regexes are validated when the policy loads.

## What this is NOT

- **Not a sandbox, proxy, or runtime enforcer.** v0.1 audits config *files* and writes hardened *copies*. It does not intercept, filter, or control running MCP servers. A live stdio-permission proxy is on the roadmap — it is not claimed here.
- **Not exhaustive.** Detection is heuristic and name-based (e.g. env vars are flagged by name, never by reading values). A clean audit is not a proof of safety.
- **Does not phone home.** Fully offline; the only network use is none.

## Roadmap

- Live stdio proxy mode: per-tool allow/deny with approval prompts.
- `policy-init --strict` preset.
- Editor integrations (surface findings inline).

## Managed follow-up

For teams that want this as a managed control plane — allow/deny policies, approval queues, and kill switches for AI agents — see [Agent Auth Gateway](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway) by Ingenious AI.

## License

MIT — see [LICENSE](LICENSE). Copyright Ingenious AI.

## Built by Ingenious AI

This project is part of the **Ingenious AI** platform suite — defensive security tooling for the AI era. Our platforms are currently in early access (full launch Nov 1) — request access to any of them on WhatsApp:

- [DisclosureGuard](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DisclosureGuard)
- [ModelMinder](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ModelMinder)
- [TermsWatch](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20TermsWatch)
- [Vibe-Code Audit](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Vibe-Code%20Audit)
- [Rogue-Agent Defense](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Rogue-Agent%20Defense)
- [BreachHunter](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20BreachHunter)
- [ChatBreaker](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ChatBreaker)
- [Agent Flight Recorder](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Flight%20Recorder)
- [Agent Auth Gateway](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway)
- [DomainGuard](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DomainGuard)
- [ContentCraft AI](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ContentCraft%20AI)
