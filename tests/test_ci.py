"""Tests for the CI entry point (ci/amygdala_ci.py) and the SARIF exporter.

Runs the entry point the way a pipeline would, on a copy of the eCTF fixture, and checks the gates,
the baseline round trip, the output files, redaction and the exit codes. Standard library only.

    python -m unittest tests.test_ci -v
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CI = os.path.join(ROOT, "ci", "amygdala_ci.py")
SARIF_PY = os.path.join(ROOT, "plugin", "skills", "review", "scripts", "leads_to_sarif.py")
ECTF = os.path.join(ROOT, "evals", "review", "ectf-2025-insecure-example")
EXAMPLE_CONFIG = os.path.join(ROOT, "ci", "amygdala-ci.example.json")
REQUIRED_TOOLS = [t for t in os.environ.get("FW_TEST_REQUIRE_TOOLS", "").split(",") if t.strip()]


def run_ci(*args, expect=None, cwd=None):
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1", FW_REVIEW_OPEN="0", SEMGREP_SEND_METRICS="off")
    env.pop("GITHUB_STEP_SUMMARY", None)
    cp = subprocess.run([sys.executable, CI, *args], capture_output=True, text=True, encoding="utf-8",
                        errors="replace", env=env, cwd=cwd, timeout=1500)
    if expect is not None and cp.returncode != expect:
        raise AssertionError("amygdala_ci.py %s exited %d (expected %d)\nstdout:\n%s\nstderr:\n%s"
                             % (" ".join(args[:1]), cp.returncode, expect, cp.stdout, cp.stderr))
    return cp


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TempDirTest(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory(prefix="amygdala-ci-test-")
        self.tmp = self._td.name

    def tearDown(self):
        self._td.cleanup()

    def fixture_copy(self):
        dst = os.path.join(self.tmp, "repo")
        shutil.copytree(ECTF, dst)
        return dst


class Pipeline(TempDirTest):
    def test_all_then_baseline_then_new_lead(self):
        repo = self.fixture_copy()
        out = os.path.join(self.tmp, "out")
        base = os.path.join(self.tmp, "baseline.json")
        gates_names = {"hotspot-rules", "static-agreement", "static-errors", "functions-over-thresholds",
                       "maintainability-rating", "vulnerabilities", "licence-families"}

        # 1. No baseline: the fixture has a printf inside an ISR, a gated hotspot rule, so the run fails with 1.
        cp = run_ci("all", "--root", repo, "--out-dir", out, "--baseline", base, expect=1)
        for name in ("platform.json", "hotspots.json", "hotspots.md", "static_leads.json", "static_leads.md", "maintainability.json",
                     "osv_plan.json", "components.json", "license_scan.md", "findings.json", "report.html", "report.md",
                     "findings.csv", "junit.xml", "leads.sarif", "gates.json", "summary.md", "ci_steps.json"):
            self.assertTrue(os.path.isfile(os.path.join(out, name)), name + " missing after `all`")
        self.assertFalse(os.path.exists(os.path.join(out, "osv_leads.json")), "nothing may be sent to OSV.dev without osv.send")
        self.assertIn("nothing is sent", cp.stdout)
        gates = {g["name"]: g for g in load(os.path.join(out, "gates.json"))["gates"]}
        self.assertEqual(set(gates), gates_names)
        self.assertEqual(gates["hotspot-rules"]["status"], "fail")
        self.assertTrue(any(it["rule"] == "isr-blocking-in-isr" for it in gates["hotspot-rules"]["items"]))
        self.assertEqual(gates["vulnerabilities"]["status"], "skipped")
        self.assertEqual(gates["licence-families"]["status"], "pass")
        if "lizard" in REQUIRED_TOOLS:
            self.assertEqual(gates["functions-over-thresholds"]["status"], "pass")
            self.assertEqual(gates["maintainability-rating"]["status"], "pass")

        # The report is honest about what it is.
        d = load(os.path.join(out, "findings.json"))
        self.assertEqual(d["report"]["title"], "Automated checks (CI)")
        self.assertTrue(all(c["status"] == "not_reviewed" for c in d["coverage"]))
        self.assertTrue(d["findings"], "failed gates become findings")
        self.assertTrue(all(f["rag"] == "amber" and f["confidence"] == "needs-verification" for f in d["findings"]))
        self.assertIn("not a code review", d["summary"]["overview"])
        self.assertIn("every item counts as new", d["summary"]["overview"])
        html = read(os.path.join(out, "report.html"))
        self.assertIn("AUTOMATED CHECKS FAILED", html)
        self.assertIn("Automated checks (CI)", html)
        self.assertIn("maintainability", d, "maintainability.json is carried into the report even without lizard")
        tool_names = {t["name"] for t in d["tools"]}
        self.assertTrue({"detect_platform.py", "hotspots.py", "OSV.dev dependency lookup", "license_scan.py"} <= tool_names)

        # JUnit: one failure per failed gate; SARIF: valid 2.1.0 with relative paths and fingerprints.
        suite = ET.parse(os.path.join(out, "junit.xml")).getroot().find("testsuite")
        failed = [g for g in gates.values() if g["status"] == "fail"]
        self.assertEqual(int(suite.get("failures")), len(failed))
        self.assertTrue(any(tc.get("name") == "hotspot-rules" and tc.find("failure") is not None for tc in suite.findall("testcase")))
        sarif = load(os.path.join(out, "leads.sarif"))
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertTrue(run["results"])
        rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        for r in run["results"]:
            self.assertIn(r["ruleId"], rule_ids)
            uri = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            self.assertFalse(uri.startswith("/") or "\\" in uri or ":" in uri, "SARIF uri must be repository-relative: " + uri)
            self.assertIn("amygdala/v1", r["partialFingerprints"])
            self.assertIn(r["level"], ("error", "warning", "note"))
        self.assertIn("hotspots/isr-blocking-in-isr", rule_ids)

        # 2. Accept the current state; the same tree now passes with 0.
        run_ci("baseline", "--root", repo, "--out-dir", out, "--baseline", base, expect=0)
        b = load(base)
        self.assertEqual(b["tool"], "amygdala-ci")
        self.assertTrue(b["items"]["hotspot"])
        cp = run_ci("report", "--root", repo, "--out-dir", out, "--baseline", base, expect=0)
        self.assertIn("passed: 0 gate(s) failed", cp.stdout)
        gates = {g["name"]: g for g in load(os.path.join(out, "gates.json"))["gates"]}
        self.assertTrue(all(g["status"] in ("pass", "skipped") for g in gates.values()))
        self.assertEqual(load(os.path.join(out, "findings.json"))["findings"], [])

        # 3. Someone commits a password. Only the new item fails, and its value never reaches an output file.
        planted = "ci-test-not-a-real-value-7731"
        target = os.path.join(repo, "files", "2025-ectf-insecure-example", "decoder", "src", "decoder.c")
        with open(target, "a", encoding="utf-8") as f:
            f.write('\n#define WIFI_PASSWORD "%s"\n' % planted)
        run_ci("hotspots", "--root", repo, "--out-dir", out, "--baseline", base, expect=0)
        cp = run_ci("report", "--root", repo, "--out-dir", out, "--baseline", base, expect=1)
        gates = {g["name"]: g for g in load(os.path.join(out, "gates.json"))["gates"]}
        self.assertEqual(gates["hotspot-rules"]["status"], "fail")
        self.assertEqual([it["rule"] for it in gates["hotspot-rules"]["items"]], ["hardcoded-password"])
        for name in ("gates.json", "findings.json", "report.html", "report.md", "findings.csv", "junit.xml", "leads.sarif", "summary.md"):
            self.assertNotIn(planted, read(os.path.join(out, name)), name + " leaks the credential value")
        self.assertNotIn(planted, cp.stdout + cp.stderr)
        self.assertNotIn(planted, read(base))

    def test_steps_run_individually_and_gates_skip_what_did_not_run(self):
        repo = self.fixture_copy()
        out = os.path.join(self.tmp, "out")
        run_ci("platform", "--root", repo, "--out-dir", out, "--baseline", os.path.join(self.tmp, "none.json"), expect=0)
        run_ci("hotspots", "--root", repo, "--out-dir", out, "--baseline", os.path.join(self.tmp, "none.json"), expect=0)
        run_ci("report", "--root", repo, "--out-dir", out, "--baseline", os.path.join(self.tmp, "none.json"), expect=1)
        gates = {g["name"]: g for g in load(os.path.join(out, "gates.json"))["gates"]}
        self.assertEqual(gates["hotspot-rules"]["status"], "fail")
        for name in ("static-agreement", "static-errors", "functions-over-thresholds", "maintainability-rating", "vulnerabilities", "licence-families"):
            self.assertEqual(gates[name]["status"], "skipped", name)
        self.assertFalse(os.path.exists(os.path.join(out, "leads.sarif")) and not load(os.path.join(out, "leads.sarif"))["runs"][0]["results"])

    def test_maintainability_gate_is_absolute(self):
        out = os.path.join(self.tmp, "out")
        os.makedirs(out)
        with open(os.path.join(out, "ci_steps.json"), "w", encoding="utf-8") as f:
            json.dump({"static": {"status": "ran", "notes": "", "at": ""}}, f)
        with open(os.path.join(out, "maintainability.json"), "w", encoding="utf-8") as f:
            json.dump({"tool": "lizard", "status": "ran", "notes": "", "rating": "poor",
                       "rating_basis": "9 of 20 functions (45%) are over the thresholds; worst complexity 71",
                       "totals": {"files": 2, "functions": 20, "nloc": 900, "avg_complexity": 12.0, "max_complexity": 71, "avg_nloc": 45.0,
                                  "over_threshold": 9, "pct_over": 45.0},
                       "by_directory": [], "worst_functions": [{"name": "parse", "file": "src/parse.c", "line": 10, "nloc": 300, "complexity": 71,
                                                                "params": 2, "over": ["complexity", "length"]}],
                       "layering": {"status": "not_inferable", "lower_files": 0, "upper_files": 0, "basis": [],
                                    "upward_includes": 0, "upward_calls": 0, "register_access_in_app": 0, "samples": []}}, f)
        run_ci("report", "--root", ECTF, "--out-dir", out, "--baseline", os.path.join(self.tmp, "none.json"), expect=1)
        gates = {g["name"]: g for g in load(os.path.join(out, "gates.json"))["gates"]}
        self.assertEqual(gates["maintainability-rating"]["status"], "fail")
        d = load(os.path.join(out, "findings.json"))
        self.assertTrue(any(f["title"] == "Maintainability rated poor" for f in d["findings"]))
        self.assertEqual(d["maintainability"]["rating"], "poor")
        self.assertIn("Maintainability", read(os.path.join(out, "report.html")))


class Config(TempDirTest):
    def test_example_config_loads_and_check_prints_json(self):
        repo = self.fixture_copy()
        shutil.copy(EXAMPLE_CONFIG, os.path.join(repo, "amygdala-ci.json"))
        cp = run_ci("check", "--root", repo, expect=0)
        body = cp.stdout[cp.stdout.index("{"):]
        info = json.loads(body)
        self.assertEqual(info["gates"]["static_min_tools"], 2)
        self.assertFalse(info["osv_send"])
        self.assertFalse(info["baseline_present"])
        self.assertIn("cppcheck", info["static_tools"])

    def test_unknown_key_is_a_usage_error(self):
        cfg = os.path.join(self.tmp, "cfg.json")
        with open(cfg, "w", encoding="utf-8") as f:
            json.dump({"gates": {"hotspot_rulez": []}}, f)
        cp = run_ci("check", "--root", ECTF, "--config", cfg, expect=2)
        self.assertIn("unknown config key 'gates.hotspot_rulez'", cp.stdout)
        with open(cfg, "w", encoding="utf-8") as f:
            json.dump({"gates": {"maintainability_rating": "excellent"}}, f)
        cp = run_ci("check", "--root", ECTF, "--config", cfg, expect=2)
        self.assertIn("maintainability_rating", cp.stdout)

    def test_required_tool_missing_fails_check(self):
        cfg = os.path.join(self.tmp, "cfg.json")
        with open(cfg, "w", encoding="utf-8") as f:
            json.dump({"gates": {"required_tools": ["cppcheck", "lizard"]}}, f)
        cp = run_ci("check", "--root", ECTF, "--config", cfg, expect=None)
        info = json.loads(cp.stdout[cp.stdout.index("{"):cp.stdout.rindex("}") + 1])
        installed = {t for t, v in info["static_tools"].items() if v["installed"]}
        self.assertEqual(cp.returncode, 0 if {"cppcheck", "lizard"} <= installed else 1)
        if "lizard" in REQUIRED_TOOLS:
            self.assertIn("lizard", installed)

    def test_bad_root_and_missing_config(self):
        self.assertEqual(run_ci("check", "--root", os.path.join(self.tmp, "nope")).returncode, 2)
        self.assertEqual(run_ci("check", "--root", ECTF, "--config", os.path.join(self.tmp, "nope.json")).returncode, 2)


class Sarif(unittest.TestCase):
    def setUp(self):
        self.mod = load_module(SARIF_PY, "leads_to_sarif_under_test")

    def test_redaction_blanks_secret_values_only(self):
        r = self.mod.redact
        self.assertNotIn("hunter2", r('#define WIFI_PASSWORD "hunter2xyz"'))
        self.assertIn("WIFI_PASSWORD", r('#define WIFI_PASSWORD "hunter2xyz"'))
        self.assertEqual(r('printf("hello world");'), 'printf("hello world");')
        key = "static const uint8_t aes_key[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};"
        self.assertNotIn("0x05", r(key))
        self.assertIn("aes_key", r(key))
        self.assertEqual(r(""), "")
        self.assertEqual(r(None), "")

    def test_fingerprint_ignores_line_numbers_and_whitespace(self):
        fp = self.mod.fingerprint
        a = fp("hotspot", "unbounded-string", "src/a.c", "  strcpy(dst, src);", 10)
        b = fp("hotspot", "unbounded-string", "src/a.c", "strcpy(dst,  src);", 99)
        self.assertEqual(a, b)
        self.assertNotEqual(a, fp("hotspot", "unbounded-string", "src/b.c", "strcpy(dst, src);", 10))
        self.assertNotEqual(a, fp("hotspot", "strncpy", "src/a.c", "strcpy(dst, src);", 10))
        self.assertEqual(fp("static", "x", "src\\a.c", "", 7), fp("static", "x", "src/a.c", "", 7), "path separators do not matter")
        self.assertEqual(len(a), 20)

    def test_levels(self):
        lv = self.mod.level_for
        self.assertEqual(lv("cppcheck", "uninitvar", "error"), "error")
        self.assertEqual(lv("cppcheck", "variableScope", "style"), "note")
        self.assertEqual(lv("flawfinder", "sprintf", "level 4"), "warning")
        self.assertEqual(lv("flawfinder", "memcpy", "level 2"), "note")
        self.assertEqual(lv("hotspots", "private-key", None), "warning")
        self.assertEqual(lv("hotspots", "volatile", None), "note")
        self.assertEqual(lv("lizard", "function-complexity", "metric"), "note")

    def test_cli_needs_an_input(self):
        cp = subprocess.run([sys.executable, SARIF_PY, "--out", os.path.join(tempfile.gettempdir(), "x.sarif")],
                            capture_output=True, text=True, encoding="utf-8", errors="replace")
        self.assertNotEqual(cp.returncode, 0)
        self.assertIn("--static", cp.stderr)


if __name__ == "__main__":
    unittest.main()
