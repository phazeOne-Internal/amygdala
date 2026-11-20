"""Cross-platform tests for the firmware plugin's scripts.

Runs every bundled script the way the skills run it, on the eval fixtures and on two small
findings.json fixtures, and checks the outputs. Standard library only; Python 3.8 or later.

    python -m unittest discover -s tests -v

Set FW_TEST_REQUIRE_TOOLS=cppcheck,flawfinder (comma separated) to assert that those static
analysers are installed and actually ran; without it their absence is tolerated.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGIN = os.path.join(ROOT, "plugin")
SKILLS = os.path.join(PLUGIN, "skills")
REVIEW = os.path.join(SKILLS, "review", "scripts")
OSS = os.path.join(SKILLS, "oss", "scripts")
FIX = os.path.join(SKILLS, "fix", "scripts")
FIXTURES = os.path.join(ROOT, "tests", "fixtures")
PSOC6 = os.path.join(SKILLS, "review", "evals", "psoc6-mqtt-sensor-release", "files", "psoc6-mqtt-sensor")
ACME = os.path.join(SKILLS, "oss", "evals", "acme-hub-multi-product", "files", "acme-hub")

REQUIRED_TOOLS = [t for t in os.environ.get("FW_TEST_REQUIRE_TOOLS", "").split(",") if t.strip()]


def run(script, *args, env=None, expect=0, cwd=None):
    """Run a bundled script with this interpreter and return the CompletedProcess."""
    e = dict(os.environ)
    e.update({"PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"})
    # Never launch a browser from the tests, whatever the host environment says.
    e["FW_REVIEW_OPEN"] = "0"
    if env:
        e.update(env)
    cp = subprocess.run([sys.executable, script, *args], capture_output=True, text=True,
                        encoding="utf-8", errors="replace", env=e, cwd=cwd, timeout=600)
    if expect is not None and cp.returncode != expect:
        raise AssertionError("%s exited %d (expected %d)\nstdout:\n%s\nstderr:\n%s"
                             % (os.path.basename(script), cp.returncode, expect, cp.stdout, cp.stderr))
    return cp


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


class TempDirTest(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory(prefix="fwplugin-test-")
        self.tmp = self._td.name

    def tearDown(self):
        self._td.cleanup()

    def path(self, *parts):
        return os.path.join(self.tmp, *parts)


class PluginLayout(unittest.TestCase):
    def test_manifests_agree(self):
        plugin = load(os.path.join(PLUGIN, ".claude-plugin", "plugin.json"))
        market = load(os.path.join(ROOT, ".claude-plugin", "marketplace.json"))
        self.assertEqual(plugin["name"], "firmware")
        self.assertRegex(plugin["version"], r"^\d+\.\d+\.\d+$")
        entries = {p["name"]: p for p in market["plugins"]}
        self.assertIn("firmware", entries)
        self.assertEqual(entries["firmware"]["source"], "./plugin")

    def test_skill_names_match_folders(self):
        names = sorted(os.listdir(SKILLS))
        self.assertEqual(names, ["fix", "oss", "review"])
        for name in names:
            skill_md = os.path.join(SKILLS, name, "SKILL.md")
            self.assertTrue(os.path.isfile(skill_md), skill_md)
            head = read(skill_md).split("---", 2)
            self.assertGreaterEqual(len(head), 3, "no YAML frontmatter in " + skill_md)
            front = head[1]
            m = re.search(r"^name:\s*(\S+)\s*$", front, re.M)
            self.assertIsNotNone(m, "no name in " + skill_md)
            self.assertEqual(m.group(1), name)
            self.assertIsNotNone(re.search(r"^description:\s*\S", front, re.M), "no description in " + skill_md)

    def test_scripts_compile_and_guard_python_version(self):
        import py_compile
        scripts = []
        for d in (REVIEW, OSS, FIX):
            scripts += [os.path.join(d, f) for f in os.listdir(d) if f.endswith(".py")]
        self.assertGreaterEqual(len(scripts), 9)
        for s in scripts:
            py_compile.compile(s, doraise=True, cfile=os.path.join(tempfile.gettempdir(), "fwplugin-compile.pyc"))
            self.assertIn("sys.version_info < (3, 8)", read(s), "missing Python 3.8 guard: " + s)

    def test_no_stale_skill_paths(self):
        """Nothing in the plugin may point at the old .claude/skills/<old-name> layout except the
        fix tracker's documented fallbacks."""
        for base, _, files in os.walk(SKILLS):
            if "evals" in base.split(os.sep):
                continue
            for f in files:
                if not f.endswith((".md", ".py", ".yml")):
                    continue
                p = os.path.join(base, f)
                if f == "fix_tracker.py":
                    continue
                self.assertNotIn(".claude/skills/", read(p), p)


class ReviewScripts(TempDirTest):
    def test_detect_platform(self):
        out = self.path("platform.json")
        run(os.path.join(REVIEW, "detect_platform.py"), PSOC6, "--out", out)
        d = load(out)
        self.assertEqual(d["detection_confidence"], "high")
        self.assertIn("PSoC 6", d["platforms"][0]["platform"])
        self.assertTrue(any("mtb_shared" in v for v in d.get("vendored_dirs", []) or [])
                        or "vendored" in json.dumps(d), "vendored directories not reported")

    def test_hotspots(self):
        out = self.path("hotspots.md")
        run(os.path.join(REVIEW, "hotspots.py"), PSOC6, "--exclude", "mtb_shared", "--out", out)
        text = read(out)
        self.assertIn("Hotspot leads", text)
        self.assertIn("leads to read in context, not findings", text)
        self.assertGreater(len(text.splitlines()), 20)

    def test_static_tools_check(self):
        cp = run(os.path.join(REVIEW, "run_static_tools.py"), PSOC6, "--check")
        d = json.loads(cp.stdout)
        self.assertIn(d["os"], ("macos", "linux", "windows"))
        for tool in ("cppcheck", "clang-tidy", "flawfinder", "semgrep"):
            self.assertIn(tool, d["tools"])
            self.assertIn("install_commands", d["tools"][tool])
        for tool in REQUIRED_TOOLS:
            self.assertTrue(d["tools"][tool]["installed"], tool + " should be installed on this runner")

    def test_static_tools_run(self):
        out = self.path("static")
        run(os.path.join(REVIEW, "run_static_tools.py"), PSOC6, "--out-dir", out, "--exclude", "mtb_shared")
        self.assertTrue(os.path.isfile(os.path.join(out, "static_leads.md")))
        d = load(os.path.join(out, "static_leads.json"))
        status = {t["name"]: t["status"] for t in d["tools"]}
        self.assertEqual(set(status), {"cppcheck", "clang-tidy", "flawfinder", "semgrep"})
        for s in status.values():
            self.assertIn(s, ("ran", "not_available", "failed", "skipped"))
        for tool in REQUIRED_TOOLS:
            self.assertEqual(status[tool], "ran", tool + ": " + json.dumps(d["tools"]))
            self.assertGreater(sum(t["leads"] for t in d["tools"] if t["name"] == tool), 0,
                               tool + " found no leads in a fixture full of planted defects")

    def test_osv_plan_mode_sends_nothing(self):
        out = self.path("osv")
        cp = run(os.path.join(REVIEW, "osv_check.py"), PSOC6,
                 "--dep", "https://github.com/madler/zlib@v1.2.11", "--out-dir", out)
        self.assertIn("nothing was sent", cp.stdout.lower())
        self.assertTrue(os.path.isfile(os.path.join(out, "osv_plan.json")))
        self.assertFalse(os.path.exists(os.path.join(out, "osv_leads.json")), "plan mode must not write leads")
        plan = json.dumps(load(os.path.join(out, "osv_plan.json")))
        self.assertIn("madler/zlib", plan)
        self.assertIn("api.osv.dev", cp.stdout + plan)


class Renderer(TempDirTest):
    def render(self, fixture, extra_env=None, *flags):
        src = os.path.join(FIXTURES, fixture)
        dst = self.path("findings.json")
        shutil.copy(src, dst)
        cp = run(os.path.join(REVIEW, "render_report.py"), dst, "--out-dir", self.tmp, "--open", *flags, env=extra_env)
        for f in ("report.html", "report.md", "findings.csv"):
            self.assertTrue(os.path.isfile(self.path(f)), f + " not written")
        return cp

    def test_firmware_report(self):
        cp = self.render("findings_firmware.json")
        html, md, csv = read(self.path("report.html")), read(self.path("report.md")), read(self.path("findings.csv"))
        self.assertIn("NOT READY FOR FIELD RELEASE", html)
        self.assertIn("Must fix before release", html)
        self.assertIn("https://www.phazeone.com/contact", html)
        self.assertIn("Get in touch", html)
        self.assertIn("Third-party component", html)
        self.assertIn("NOT ASSESSED", html)
        self.assertIn("Acknowledgements", html)
        self.assertIn("Cppcheck", html)
        self.assertRegex(html, r"Generated.*UTC", "generated stamp with time zone missing")
        self.assertIn("2026-11-20 10:00", html)
        self.assertIn("**Origin:** Third-party component", md)
        self.assertIn("Origin", csv.splitlines()[0])
        self.assertIn("not opening a browser", cp.stdout)
        self.assertNotIn("Prepared by", html)

    def test_secret_values_are_redacted(self):
        cp = self.render("findings_firmware.json")
        self.assertIn("redacted", cp.stdout.lower())
        for f in ("report.html", "report.md", "findings.csv"):
            text = read(self.path(f))
            self.assertNotIn("hunter2-SECRET-VALUE-9f8e7d", text, f)
            self.assertNotIn("sk_live_SECRET_KEY_0123456789", text, f)
        # the finding itself must survive, with the value shortened rather than dropped
        self.assertIn("MQTT_PASSWORD", read(self.path("report.md")))

    def test_licence_profile(self):
        self.render("findings_licence.json")
        html = read(self.path("report.html"))
        self.assertIn("NOT CLEARED FOR DISTRIBUTION", html)
        self.assertIn("Must resolve before distribution", html)
        self.assertIn("Strong copyleft (GPL family)", html)
        self.assertIn("ScanCode Toolkit", html)
        self.assertNotIn("NOT READY FOR FIELD RELEASE", html)
        self.assertNotIn("Must fix before release", html)

    def test_oss_renderer_is_identical(self):
        self.assertEqual(read(os.path.join(REVIEW, "render_report.py")), read(os.path.join(OSS, "render_report.py")),
                         "plugin/skills/oss/scripts/render_report.py must be a byte-identical copy of the review one")

    def test_ci_environment_skips_browser(self):
        env = {"CI": "true", "GITHUB_ACTIONS": "true"}
        src = os.path.join(FIXTURES, "findings_firmware.json")
        dst = self.path("findings.json")
        shutil.copy(src, dst)
        e = dict(os.environ); e.update(env); e.pop("FW_REVIEW_OPEN", None)
        e.update({"PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"})
        cp = subprocess.run([sys.executable, os.path.join(REVIEW, "render_report.py"), dst, "--out-dir", self.tmp, "--open"],
                            capture_output=True, text=True, encoding="utf-8", errors="replace", env=e, timeout=300)
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertIn("not opening a browser", cp.stdout)
        self.assertIn("file://", cp.stdout)

    def test_invalid_findings_rejected(self):
        bad = self.path("bad.json")
        with open(bad, "w", encoding="utf-8") as f:
            json.dump({"project": {"name": "x"}, "findings": [{"id": "FW-001", "rag": "purple"}]}, f)
        cp = run(os.path.join(REVIEW, "render_report.py"), bad, "--out-dir", self.tmp, expect=None)
        self.assertNotEqual(cp.returncode, 0, "renderer accepted an invalid findings.json")
        self.assertFalse(os.path.exists(self.path("report.html")))


class OssScripts(TempDirTest):
    def test_license_scan_check(self):
        cp = run(os.path.join(OSS, "license_scan.py"), ACME, "--check")
        d = json.loads(cp.stdout)
        self.assertIn(d["os"], ("macos", "linux", "windows"))
        self.assertIn("install_commands", d["scancode"])

    def test_license_scan_inventory(self):
        out = self.path("lic")
        run(os.path.join(OSS, "license_scan.py"), ACME, "--out-dir", out)
        comps = load(os.path.join(out, "components.json"))
        items = comps["components"] if isinstance(comps, dict) else comps
        self.assertGreaterEqual(len(items), 5)
        blob = json.dumps(comps)
        self.assertIn("GPL", blob)
        self.assertTrue(os.path.isfile(os.path.join(out, "license_scan.md")))

    def test_make_outputs(self):
        confirmed = self.path("confirmed_components.json")
        with open(confirmed, "w", encoding="utf-8") as f:
            json.dump({
                "product": {"name": "CI Hub", "version": "1.0.0", "supplier": "Acme Ltd"},
                "components": [
                    {"name": "zlib", "version": "1.2.11", "path": "firmware/zlib", "license": "Zlib",
                     "shipped_in": ["mcu-firmware"], "distribution": "linked", "supplier": "Mark Adler",
                     "purl": "pkg:github/madler/zlib@v1.2.11", "license_file": "", "modified": False, "notes": ""},
                    {"name": "cmake", "version": "3.28", "path": "", "license": "BSD-3-Clause",
                     "shipped_in": [], "distribution": "build-tool", "supplier": "Kitware",
                     "purl": "", "license_file": "", "modified": False, "notes": ""}]}, f)
        out = self.path("out")
        run(os.path.join(OSS, "make_outputs.py"), ACME, "--confirmed", confirmed, "--out-dir", out)
        notices = read(os.path.join(out, "THIRD_PARTY_NOTICES.md"))
        self.assertIn("zlib", notices)
        self.assertNotIn("cmake", notices, "build tools must not appear in the notices")
        sbom = load(os.path.join(out, "sbom.cdx.json"))
        self.assertEqual(sbom["bomFormat"], "CycloneDX")
        names = {c["name"] for c in sbom["components"]}
        self.assertEqual(names, {"zlib", "cmake"})

    def test_install_scancode_dry_run_installs_nothing(self):
        cp = run(os.path.join(OSS, "install_scancode.py"), "--dry-run")
        d = json.loads(cp.stdout)
        self.assertIn(d["status"], ("already_installed", "dry_run", "would_install"))


class FixTracker(TempDirTest):
    def setUp(self):
        super().setUp()
        self.findings = self.path("findings.json")
        shutil.copy(os.path.join(FIXTURES, "findings_firmware.json"), self.findings)
        self.script = os.path.join(FIX, "fix_tracker.py")

    def test_plan_orders_red_first(self):
        cp = run(self.script, self.findings, "plan")
        plan = json.loads(cp.stdout)
        items = plan["plan"]
        self.assertEqual(items[0]["id"], "FW-001")
        self.assertEqual([i["id"] for i in items], ["FW-001", "FW-002", "FW-003"])

    def test_set_summary_and_render(self):
        run(self.script, self.findings, "set", "FW-001", "fixed", "--note", "rotated credential", "--commit", "abc1234")
        run(self.script, self.findings, "set", "FW-003", "wont_fix", "--note", "agreed with lead: cosmetic")
        d = load(self.findings)
        by_id = {f["id"]: f for f in d["findings"]}
        self.assertEqual(by_id["FW-001"]["fix"]["status"] if "fix" in by_id["FW-001"] else by_id["FW-001"].get("status"), "fixed")
        self.assertTrue(os.path.isfile(self.findings + ".bak"), "first set should keep a backup")
        cp = run(self.script, self.findings, "summary")
        self.assertIn("fixed", cp.stdout.lower())
        run(self.script, self.findings, "render")
        html = read(self.path("report.html"))
        self.assertIn("FW-001", html)
        self.assertIn("abc1234", html)

    def test_wont_fix_requires_note(self):
        cp = run(self.script, self.findings, "set", "FW-003", "wont_fix", expect=None)
        self.assertNotEqual(cp.returncode, 0)


if __name__ == "__main__":
    unittest.main()
