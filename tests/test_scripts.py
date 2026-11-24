"""Cross-platform tests for the amygdala plugin's scripts.

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
EVALS = os.path.join(ROOT, "evals")
PSOC6 = os.path.join(EVALS, "review", "psoc6-mqtt-sensor-release", "files", "psoc6-mqtt-sensor")
ACME = os.path.join(EVALS, "oss", "acme-hub-multi-product", "files", "acme-hub")

REQUIRED_TOOLS = [t for t in os.environ.get("FW_TEST_REQUIRE_TOOLS", "").split(",") if t.strip()]
REQUIRE_SCANCODE = os.environ.get("FW_TEST_REQUIRE_SCANCODE") == "1"


def run(script, *args, env=None, expect=0, cwd=None, timeout=600):
    """Run a bundled script with this interpreter and return the CompletedProcess."""
    e = dict(os.environ)
    e.update({"PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"})
    # Never launch a browser from the tests, whatever the host environment says.
    e["FW_REVIEW_OPEN"] = "0"
    if env:
        e.update(env)
    cp = subprocess.run([sys.executable, script, *args], capture_output=True, text=True,
                        encoding="utf-8", errors="replace", env=e, cwd=cwd, timeout=timeout)
    if expect is not None and cp.returncode != expect:
        raise AssertionError("%s exited %d (expected %d)\nstdout:\n%s\nstderr:\n%s"
                             % (os.path.basename(script), cp.returncode, expect, cp.stdout, cp.stderr))
    return cp


def glob_one(pattern):
    import glob
    matches = sorted(p for p in glob.glob(pattern) if os.path.isdir(p))
    assert matches, "no directory matches " + pattern
    return matches[0]


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def write(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


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
        self.assertEqual(plugin["name"], "amygdala")
        self.assertRegex(plugin["version"], r"^\d+\.\d+\.\d+$")
        entries = {p["name"]: p for p in market["plugins"]}
        self.assertIn("amygdala", entries)
        self.assertEqual(entries["amygdala"]["source"], "./plugin")

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

    def test_no_evals_or_fixtures_inside_plugin(self):
        """Eval fixtures carry planted secrets and deliberately bad code; they live in evals/ at the repo root
        so an installed plugin never ships them."""
        for base, dirs, files in os.walk(PLUGIN):
            self.assertNotIn("evals", dirs, base)
            for f in files:
                p = os.path.join(base, f)
                if f.endswith((".c", ".h", ".py", ".yml", ".json", ".txt", ".pem", ".key", ".der", ".crt")):
                    self.assertNotRegex(read(p), r"BEGIN (RSA |EC )?PRIVATE KEY-----\s*\n\s*[A-Za-z0-9+/=]{20,}", p)

    def test_no_stale_skill_paths(self):
        """Nothing in the plugin may point at the old .claude/skills/<old-name> layout except the
        fix tracker's documented fallbacks."""
        for base, _, files in os.walk(SKILLS):
            for f in files:
                if not f.endswith((".md", ".py", ".yml")):
                    continue
                p = os.path.join(base, f)
                if f == "fix_tracker.py":
                    continue
                self.assertNotIn(".claude/skills/", read(p), p)

    def test_every_skill_checks_for_python_first(self):
        """Claude Code cannot check for Python at plugin install time, so each skill must check
        before its first script runs, show per-OS install commands, and ask before installing."""
        for name in os.listdir(SKILLS):
            text = read(os.path.join(SKILLS, name, "SKILL.md"))
            check = text.find("## Before anything else: make sure Python 3 is available")
            self.assertGreater(check, 0, name)
            first_script = text.find("<skill-dir>/scripts/")
            self.assertLess(check, first_script, "%s: Python check must come before the first script" % name)
            section = text[check:check + 2500]
            for needle in ("python3 --version", "py -3 --version", "winget install --id Python.Python.3.12",
                           "xcode-select --install", "apt install python3", "ask before running it",
                           "Never install without a yes", "new terminal"):
                self.assertIn(needle, section, "%s: %s" % (name, needle))


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

    def test_hotspots_flags_calls_inside_interrupt_handlers(self):
        """A blocking call inside a function that is an interrupt handler, by name or by registration, is
        reported under its own rule with the handler named; one level of indirection is followed."""
        ectf = os.path.join(EVALS, "review", "ectf-2025-insecure-example", "files", "2025-ectf-insecure-example")
        cp = run(os.path.join(REVIEW, "hotspots.py"), ectf, "--json")
        d = json.loads(cp.stdout)
        self.assertIn({"file": "decoder/src/simple_flash.c", "line": 29, "name": "flash_simple_irq"}, d["interrupt_handlers"],
                      "handler registered via MXC_NVIC_SetVector not recognised")
        hits = d["hits"]["isr-blocking-in-isr"]["samples"]
        self.assertTrue(any(h["file"] == "decoder/src/simple_flash.c" and h["line"] == 39 and h["isr"] == "flash_simple_irq"
                            for h in hits), hits)
        plug = glob_one(os.path.join(EVALS, "review", "psoc6-subtle-defects", "files", "*"))
        d = json.loads(run(os.path.join(REVIEW, "hotspots.py"), plug, "--exclude", "mtb_shared", "--json").stdout)
        hits = d["hits"]["isr-blocking-in-isr"]["samples"]
        self.assertTrue(any(h["isr"] == "zero_cross_isr" and h.get("via") == "relay_apply" for h in hits),
                        "indirect blocking call from zero_cross_isr via relay_apply not reported: " + json.dumps(hits))
        lock = glob_one(os.path.join(EVALS, "review", "zephyr-ble-lock-audit", "files", "*"))
        d = json.loads(run(os.path.join(REVIEW, "hotspots.py"), lock, "--json").stdout)
        hits = d["hits"]["isr-blocking-in-isr"]["samples"]
        self.assertTrue(any(h["isr"] == "door_changed" and h.get("via") == "motor_lock" for h in hits),
                        "two-level indirect blocking call from door_changed via motor_lock not reported: " + json.dumps(hits))
        md = run(os.path.join(REVIEW, "hotspots.py"), ectf, "--out", self.path("h.md"))
        text = read(self.path("h.md"))
        self.assertIn("## Interrupt handlers found", text)
        self.assertIn("INSIDE an interrupt handler", text)
        self.assertIn("(in handler `flash_simple_irq`)", text)

    def test_check_marks_semgrep_unavailable_on_windows_arm(self):
        """On Windows on ARM pip cannot build semgrep's dependencies (seen on the Windows VM test), so --check
        must report it unavailable with a WSL note and no install command instead of a doomed pip command."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("rst", os.path.join(REVIEW, "run_static_tools.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.OS, mod.ARCH = "windows", "arm64"
        mod.find_tool = lambda name: None
        d = mod.check(PSOC6)
        self.assertEqual(d["arch"], "arm64")
        sg = d["tools"]["semgrep"]
        self.assertTrue(sg["unavailable_on_this_platform"])
        self.assertEqual(sg["install_commands"], [])
        self.assertIn("WSL", sg["install_note"])
        cc = d["tools"]["cppcheck"]
        self.assertFalse(cc["unavailable_on_this_platform"])
        self.assertTrue(cc["install_commands"])
        mod.ARCH = "x64"
        self.assertFalse(mod.check(PSOC6)["tools"]["semgrep"]["unavailable_on_this_platform"])

    def test_hotspots_layering(self):
        """Layering leads fire on the smart-plug fixture (drivers/relay.c includes app.h and calls app functions),
        stay silent where no layers are visible, and honour --layer overrides and the register-write rule."""
        plug = glob_one(os.path.join(EVALS, "review", "psoc6-subtle-defects", "files", "*"))
        d = json.loads(run(os.path.join(REVIEW, "hotspots.py"), plug, "--json").stdout)
        self.assertEqual(d["layers"]["lower"], ["source/drivers/relay.c"])
        self.assertIn("source/app/main.c", d["layers"]["upper"])
        inc = d["hits"]["layer-upward-include"]["samples"]
        self.assertTrue(any(h["file"] == "source/drivers/relay.c" and h["header"] == "source/app/app.h" for h in inc), inc)
        calls = {h["callee"] for h in d["hits"]["layer-upward-call"]["samples"]}
        self.assertEqual(calls, {"config_load", "wdt_checkin"})
        md = run(os.path.join(REVIEW, "hotspots.py"), plug).stdout
        self.assertIn("## Layering", md)
        self.assertIn("`config_load` is defined in `source/app/config_store.c`", md)
        # no layers visible -> explicit note, no layer-* hits
        d2 = json.loads(run(os.path.join(REVIEW, "hotspots.py"), PSOC6, "--json").stdout)
        self.assertIn("not inferable", d2["layers"]["note"])
        self.assertFalse([r for r in d2["hits"] if r.startswith("layer-")])
        # overrides + direct register write in application code
        root = os.path.join(self.tmp, "flat")
        os.makedirs(os.path.join(root, "lowlevel_stuff")); os.makedirs(os.path.join(root, "logic_stuff"))
        write(os.path.join(root, "lowlevel_stuff", "uart.c"), '#include "cloud.h"\nvoid uart_rx(void) { cloud_publish(1); }\n')
        write(os.path.join(root, "logic_stuff", "cloud.h"), "void cloud_publish(int x);\n")
        write(os.path.join(root, "logic_stuff", "cloud.c"), "void cloud_publish(int x) { GPIO_PRT9->OUT |= 1u; *(volatile uint32_t *)0x40320000 = x; }\n")
        d3 = json.loads(run(os.path.join(REVIEW, "hotspots.py"), root, "--json",
                            "--layer", "lower=lowlevel_stuff", "--layer", "upper=logic_stuff").stdout)
        self.assertEqual(d3["layers"]["basis"], ["override"])
        self.assertEqual(d3["hits"]["layer-upward-call"]["samples"][0]["callee"], "cloud_publish")
        self.assertEqual(d3["hits"]["layer-upward-include"]["count"], 1)
        self.assertEqual(d3["hits"]["layer-register-access-in-app"]["count"], 2)

    def test_static_tools_check(self):
        cp = run(os.path.join(REVIEW, "run_static_tools.py"), PSOC6, "--check")
        d = json.loads(cp.stdout)
        self.assertIn(d["os"], ("macos", "linux", "windows"))
        for tool in ("cppcheck", "clang-tidy", "flawfinder", "semgrep", "lizard"):
            self.assertIn(tool, d["tools"])
            self.assertIn("install_commands", d["tools"][tool])
        for tool in REQUIRED_TOOLS:
            self.assertTrue(d["tools"][tool]["installed"], tool + " should be installed on this runner")

    def test_install_advice_is_plain_commands(self):
        """Every install command the skills print must be runnable as-is; caveats go in install_note."""
        cp = run(os.path.join(REVIEW, "run_static_tools.py"), PSOC6, "--check")
        for name, t in json.loads(cp.stdout)["tools"].items():
            self.assertIn("install_note", t)
            for cmd in t["install_commands"]:
                self.assertNotRegex(cmd, r"[()]|\s{2,}", name + ": not a plain command: " + cmd)
        cp = run(os.path.join(OSS, "license_scan.py"), ACME, "--check")
        sc = json.loads(cp.stdout)["scancode"]
        self.assertIn("install_note", sc)
        for cmd in sc["install_commands"]:
            self.assertNotRegex(cmd, r"[()]|\s{2,}", "scancode: not a plain command: " + cmd)

    def test_static_tools_run(self):
        out = self.path("static")
        run(os.path.join(REVIEW, "run_static_tools.py"), PSOC6, "--out-dir", out, "--exclude", "mtb_shared")
        self.assertTrue(os.path.isfile(os.path.join(out, "static_leads.md")))
        d = load(os.path.join(out, "static_leads.json"))
        status = {t["name"]: t["status"] for t in d["tools"]}
        self.assertEqual(set(status), {"cppcheck", "clang-tidy", "flawfinder", "semgrep", "lizard"})
        for s in status.values():
            self.assertIn(s, ("ran", "not_available", "failed", "skipped"))
        for tool in REQUIRED_TOOLS:
            self.assertEqual(status[tool], "ran", tool + ": " + json.dumps(d["tools"]))
            if tool != "lizard":   # lizard's leads are metrics over thresholds; a fixture may legitimately have none
                self.assertGreater(sum(t["leads"] for t in d["tools"] if t["name"] == tool), 0,
                                   tool + " found no leads in a fixture full of planted defects: " + json.dumps(d["tools"]))
        # maintainability.json is always written, with the layering result even when lizard is missing
        h = load(os.path.join(out, "maintainability.json"))
        self.assertEqual(h, d["maintainability"])
        self.assertIn(h["rating"], ("good", "fair", "poor", "unknown"))
        self.assertIn(h["layering"]["status"], ("checked", "not_inferable"))
        if status["lizard"] == "ran":
            self.assertGreater(h["totals"]["functions"], 0)
            self.assertTrue(h["by_directory"] and h["worst_functions"])
            self.assertNotEqual(h["rating"], "unknown")
        else:
            self.assertEqual(h["rating"], "unknown")

    def test_lizard_metrics_and_maintainability_band(self):
        """The lizard runner parses the CSV, flags functions over the thresholds as leads, and the
        summary bands the tree good / fair / poor from the share of functions over thresholds."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("rst2", os.path.join(REVIEW, "run_static_tools.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        root = self.path("tree")
        os.makedirs(os.path.join(root, "src", "app"))
        os.makedirs(os.path.join(root, "src", "drivers"))
        write(os.path.join(root, "src", "app", "parser.c"), "int parse(void) { return 0; }\n")
        write(os.path.join(root, "src", "drivers", "uart.c"), "void uart_init(void) { }\n")
        srcs = [os.path.join(root, "src", "app", "parser.c"), os.path.join(root, "src", "drivers", "uart.c")]
        csv_out = (
            '340,48,2100,7,360,"parse@10-370@src/app/parser.c","src/app/parser.c","parse","parse(a,b,c,d,e,f,g)",10,370\n'
            '12,3,80,1,12,"helper@400-412@src/app/parser.c","src/app/parser.c","helper","helper(x)",400,412\n'
            '4,1,20,0,4,"uart_init@1-4@src/drivers/uart.c","src/drivers/uart.c","uart_init","uart_init()",1,4\n'
            '9,2,60,2,9,"vendor@1-9@mtb_shared/x.c","mtb_shared/x.c","vendor","vendor(a,b)",1,9\n')
        mod.run = lambda cmd, timeout, cwd=None: (0, csv_out, "", None)
        args = type("A", (), {"timeout": 10, "excludes_all": mod.DEFAULT_EXCLUDES})()
        leads, status, note = mod.run_lizard("lizard", root, srcs, [], args)
        self.assertEqual(status, "ran")
        self.assertEqual([l["file"] for l in leads], ["src/app/parser.c"])
        self.assertEqual(leads[0]["rule"], "function-complexity")
        self.assertIn("complexity 48, 340 lines, 7 parameter", leads[0]["message"])
        funcs = mod.EXTRA["lizard"]
        self.assertEqual(len(funcs), 3, "the vendored row must be dropped")
        h = mod.maintainability_metrics(funcs)
        self.assertEqual(h["totals"]["functions"], 3)
        self.assertEqual(h["totals"]["max_ccn"], 48)
        self.assertEqual(h["by_directory"][0]["path"], "src/app")
        self.assertEqual(h["by_directory"][0]["over_threshold"], 1)
        self.assertEqual(h["worst_functions"][0]["name"], "parse")
        self.assertEqual(h["worst_functions"][0]["over"], ["complexity", "length", "parameters"])
        self.assertEqual(h["rating"], "poor")   # 1 of 3 over, and complexity 48 over the fair ceiling? no: 33% over
        self.assertEqual(mod.maintainability_band(100, 2, 20)[0], "good")
        self.assertEqual(mod.maintainability_band(100, 2, 45)[0], "fair")
        self.assertEqual(mod.maintainability_band(100, 10, 20)[0], "fair")
        self.assertEqual(mod.maintainability_band(100, 20, 20)[0], "poor")
        self.assertEqual(mod.maintainability_band(100, 1, 80)[0], "poor")
        self.assertEqual(mod.maintainability_band(0, 0, 0)[0], "unknown")
        # layering summary over the same tree: directories name the layers, nothing crosses
        lay = mod.layering_summary(root, srcs, [], [])
        self.assertEqual(lay["status"], "checked")
        self.assertEqual((lay["lower_files"], lay["upper_files"]), (1, 1))
        self.assertEqual(lay["upward_calls"] + lay["upward_includes"] + lay["register_access_in_app"], 0)

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

    def test_maintainability_section(self):
        """findings.json may carry maintainability.json from run_static_tools.py; both outputs get a
        Maintainability section, and a bad block is rejected by validation."""
        src = load(os.path.join(FIXTURES, "findings_firmware.json"))
        src["maintainability"] = {
            "tool": "lizard", "status": "ran", "notes": "1.17.10; 40 functions measured; 3 over thresholds",
            "thresholds": {"ccn": 15, "nloc": 100, "params": 5},
            "totals": {"files": 6, "functions": 40, "nloc": 1800, "avg_ccn": 6.2, "max_ccn": 41, "avg_nloc": 45.0,
                       "over_threshold": 3, "pct_over": 7.5},
            "by_directory": [{"path": "source/app", "files": 4, "functions": 30, "nloc": 1500, "avg_ccn": 7.1, "max_ccn": 41, "over_threshold": 3},
                             {"path": "source/drivers", "files": 2, "functions": 10, "nloc": 300, "avg_ccn": 3.0, "max_ccn": 8, "over_threshold": 0}],
            "worst_functions": [{"name": "mqtt_handle", "file": "source/app/mqtt.c", "line": 88, "nloc": 240, "ccn": 41, "params": 2,
                                 "over": ["complexity", "length"]}],
            "rating": "fair", "rating_basis": "3 of 40 functions (8%) are over the size / complexity thresholds; worst complexity 41",
            "layering": {"status": "checked", "lower_files": 2, "upper_files": 4, "basis": ["directory"],
                         "upward_includes": 1, "upward_calls": 0, "register_access_in_app": 0,
                         "samples": {"layer-upward-include": [{"file": "source/drivers/relay.c", "line": 7,
                                                              "code": "#include \"app.h\"", "header": "source/app/app.h"}]}},
        }
        dst = self.path("findings.json")
        with open(dst, "w", encoding="utf-8") as fh:
            json.dump(src, fh)
        run(os.path.join(REVIEW, "render_report.py"), dst, "--out-dir", self.tmp, env={"FW_REVIEW_OPEN": "0"})
        html, md = read(self.path("report.html")), read(self.path("report.md"))
        for text in (html, md):
            self.assertIn("Maintainability (code health)", text)
            self.assertIn("mqtt_handle", text)
            self.assertIn("source/drivers/relay.c", text)
            self.assertIn("FAIR", text)
            self.assertIn("Lizard", text)   # acknowledged
        self.assertIn("href='#maintainability'", html)
        src["maintainability"]["rating"] = "excellent"
        with open(dst, "w", encoding="utf-8") as fh:
            json.dump(src, fh)
        cp = run(os.path.join(REVIEW, "render_report.py"), dst, "--out-dir", self.tmp, env={"FW_REVIEW_OPEN": "0"}, expect=1)
        self.assertIn("maintainability.rating", cp.stdout + cp.stderr)

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

    def test_scancode_unavailable_on_windows_arm(self):
        """Seen on the Windows VM test: pip cannot build pyicu on Windows ARM64. Both the checker and the installer
        must say so up front instead of running a doomed install."""
        import importlib.util
        def load_module(name):
            spec = importlib.util.spec_from_file_location(name, os.path.join(OSS, name + ".py"))
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
        ls = load_module("license_scan")
        ls.OS, ls.ARCH = "windows", "arm64"
        ls.find_scancode = lambda: None
        d = ls.check()
        self.assertTrue(d["scancode"]["unavailable_on_this_platform"])
        self.assertEqual(d["scancode"]["install_commands"], [])
        self.assertIn("WSL", d["scancode"]["install_note"])
        ls.ARCH = "x64"
        self.assertFalse(ls.check()["scancode"]["unavailable_on_this_platform"])
        inst = load_module("install_scancode")
        inst.OS, inst.ARCH = "windows", "arm64"
        self.assertIn("WSL", inst.unsupported_platform())
        inst.ARCH = "x64"
        self.assertIsNone(inst.unsupported_platform())

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

    @unittest.skipUnless(REQUIRE_SCANCODE, "set FW_TEST_REQUIRE_SCANCODE=1 on a runner where ScanCode is installed")
    def test_scancode_runs_and_merges(self):
        out = self.path("lic-sc")
        cp = run(os.path.join(OSS, "license_scan.py"), ACME, "--out-dir", out, "--run-scancode",
                 "--scancode-timeout", "1500", timeout=1800)
        comps = load(os.path.join(out, "components.json"))
        blob = json.dumps(comps)
        self.assertIn("ScanCode completed", blob, cp.stderr[-2000:])
        self.assertIn("(scancode)", blob, "no ScanCode-detected licence expressions were merged")
        self.assertTrue(os.path.isfile(os.path.join(out, "scancode.json")))

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
