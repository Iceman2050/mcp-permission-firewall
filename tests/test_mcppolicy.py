"""Tests for mcp-policy. Run: python3 -m unittest discover -s tests -v"""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcppolicy.audit import ConfigError, audit_config
from mcppolicy.harden import harden_config, load_policy
from mcppolicy.policy import EXAMPLE_POLICY, PolicyError, parse_policy
import mcppolicy as entry_mod  # noqa: F401  (ensures entry imports)
from mcppolicy import __version__

FIX = Path(__file__).resolve().parent / "fixtures"


def findings_for(name):
    return audit_config(str(FIX / name))["findings"]


def checks(findings):
    return {(f["server"], f["check"], f["severity"]) for f in findings}


class TestAudit(unittest.TestCase):
    def test_clean_config_no_findings(self):
        r = audit_config(str(FIX / "clean.json"))
        self.assertEqual(r["findings"], [])
        self.assertEqual(r["summary"]["servers"], 2)
        self.assertTrue(r["wrapped"])

    def test_secret_in_env_flagged_high_and_value_hidden(self):
        fs = findings_for("secrets.json")
        hit = {(f["server"], f["check"]) for f in fs if f["severity"] == "high"}
        self.assertIn(("github", "secret-in-env"), hit)
        # values must never be echoed in messages
        blob = json.dumps(fs)
        self.assertNotIn("ghp_REALVALUE", blob)
        self.assertNotIn("sk-live-abcdef", blob)

    def test_shell_wrapper_flagged(self):
        self.assertIn(("runner", "shell-wrapper", "high"),
                      checks(findings_for("shell.json")))

    def test_network_exposed_flagged(self):
        self.assertIn(("web", "network-exposed", "medium"),
                      checks(findings_for("network.json")))

    def test_unpinned_remote_package_and_unknown_exe(self):
        c = checks(findings_for("unpinned.json"))
        self.assertIn(("fetch", "unpinned-remote-package", "medium"), c)
        self.assertIn(("mystery", "unknown-executable", "medium"), c)

    def test_bare_map_format(self):
        r = audit_config(str(FIX / "bare.json"))
        self.assertFalse(r["wrapped"])
        self.assertEqual(r["servers"], ["solo"])

    def test_missing_file_raises(self):
        with self.assertRaises(ConfigError):
            audit_config(str(FIX / "nope.json"))

    def test_malformed_json_raises(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                         delete=False) as f:
            f.write("{not json")
            p = f.name
        try:
            with self.assertRaises(ConfigError):
                audit_config(p)
        finally:
            os.unlink(p)

    def test_no_mcp_servers_raises(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                         delete=False) as f:
            json.dump({"hello": "world"}, f)
            p = f.name
        try:
            with self.assertRaises(ConfigError):
                audit_config(p)
        finally:
            os.unlink(p)


class TestPolicy(unittest.TestCase):
    def test_parse_example(self):
        p = parse_policy(EXAMPLE_POLICY)
        self.assertTrue(p["require_allowlist"])
        self.assertIn("filesystem", p["allow_servers"])
        self.assertIsInstance(p["deny_env_patterns"], list)

    def test_list_item_outside_list_raises(self):
        with self.assertRaises(PolicyError):
            parse_policy("- orphan\n")

    def test_bad_line_raises(self):
        with self.assertRaises(PolicyError):
            parse_policy("this is not yaml at all\n")

    def test_load_policy_unknown_key_warns(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml",
                                         delete=False) as f:
            f.write("bogus_key: 1\n")
            p = f.name
        try:
            _, warnings = load_policy(p)
            self.assertTrue(any("bogus_key" in w for w in warnings))
        finally:
            os.unlink(p)

    def test_bad_regex_raises(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml",
                                         delete=False) as f:
            f.write('deny_env_patterns:\n  - "([invalid"\n')
            p = f.name
        try:
            with self.assertRaises(PolicyError):
                load_policy(p)
        finally:
            os.unlink(p)


class TestHarden(unittest.TestCase):
    def test_strict_policy(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "out.json")
            r = harden_config(str(FIX / "denylist.json"),
                              str(FIX / "policy-strict.yaml"), out)
            # evil-server: deny_servers. shelltool: not allowlisted.
            dropped = {x["server"] for x in r["dropped_servers"]}
            self.assertEqual(dropped, {"evil-server", "shelltool"})
            self.assertEqual(r["kept"], ["filesystem"])
            # original untouched
            orig = json.loads((FIX / "denylist.json").read_text())
            self.assertIn("evil-server", orig["mcpServers"])
            # hardened file preserves wrapped shape
            hardened = json.loads(Path(out).read_text())
            self.assertEqual(set(hardened["mcpServers"]), {"filesystem"})

    def test_deny_commands_and_env_scrub(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "out.json")
            r = harden_config(str(FIX / "secrets.json"),
                              str(FIX / "policy-strict.yaml"), out)
            # github not in allowlist -> dropped regardless
            self.assertEqual(r["summary"]["servers_dropped"], 1)
            # now without allowlist: env scrubbed, server kept
            with tempfile.NamedTemporaryFile("w", suffix=".yaml",
                                             delete=False) as f:
                f.write('deny_env_patterns:\n  - ".*TOKEN.*"\n  - ".*KEY.*"\n')
                pol = f.name
            try:
                r2 = harden_config(str(FIX / "secrets.json"), pol, out)
            finally:
                os.unlink(pol)
            self.assertEqual(r2["kept"], ["github"])
            self.assertEqual(r2["summary"]["env_vars_scrubbed"], 2)
            hardened = json.loads(Path(out).read_text())
            self.assertEqual(hardened["mcpServers"]["github"]["env"], {})

    def test_default_output_path(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = os.path.join(d, "c.json")
            pol = os.path.join(d, "p.yaml")
            Path(cfg).write_text((FIX / "clean.json").read_text())
            Path(pol).write_text("require_allowlist: false\n")
            r = harden_config(cfg, pol)
            self.assertEqual(r["output"], cfg + ".hardened.json")
            self.assertTrue(Path(r["output"]).exists())


def _entry_main():
    """Load main() from the mcppolicy.py entry script (the package shadows
    the module name on sys.path, so import by file location)."""
    import importlib.util
    entry = Path(__file__).resolve().parent.parent / "mcppolicy.py"
    spec = importlib.util.spec_from_file_location("mcppolicy_cli", entry)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.main


class TestCLI(unittest.TestCase):
    def run_cli(self, argv):
        main = _entry_main()
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(argv)
        return code, buf.getvalue()

    def test_audit_clean_exit_0(self):
        code, out = self.run_cli(
            ["audit", "--config", str(FIX / "clean.json")])
        self.assertEqual(code, 0)
        self.assertIn("No risk signals", out)

    def test_audit_fail_on_high(self):
        code, _ = self.run_cli(
            ["audit", "--config", str(FIX / "secrets.json"),
             "--fail-on", "high"])
        self.assertEqual(code, 1)

    def test_audit_json_valid(self):
        code, out = self.run_cli(
            ["audit", "--config", str(FIX / "shell.json"), "--json"])
        self.assertEqual(code, 0)
        json.loads(out)

    def test_audit_missing_config_exit_2(self):
        code, _ = self.run_cli(
            ["audit", "--config", str(FIX / "nope.json")])
        self.assertEqual(code, 2)

    def test_policy_init_writes_and_parses(self):
        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, "p.yaml")
            code, _ = self.run_cli(
                ["policy-init", "--output", target])
            self.assertEqual(code, 0)
            parse_policy(Path(target).read_text())

    def test_policy_init_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, "p.yaml")
            Path(target).write_text("x: 1\n")
            code, _ = self.run_cli(["policy-init", "--output", target])
            self.assertEqual(code, 2)

    def test_version(self):
        self.assertRegex(__version__, r"^\d+\.\d+\.\d+$")


if __name__ == "__main__":
    unittest.main()
