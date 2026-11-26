#!/usr/bin/env python3
"""Amygdala in a CI/CD pipeline: the deterministic checks, without the model.

    python3 ci/amygdala_ci.py all        --root <repo> [--out-dir DIR] [--config amygdala-ci.json]
    python3 ci/amygdala_ci.py <step>     --root <repo> ...        one step at a time, for one job per step
    python3 ci/amygdala_ci.py baseline   --root <repo> ...        accept the current leads as the baseline
    python3 ci/amygdala_ci.py check      --root <repo>            which tools are installed; validates the config

Steps (each writes into the output directory; later steps read what earlier ones wrote):

    platform         platform.json                     MCU / SDK / RTOS / library inventory
    hotspots         hotspots.json, hotspots.md        pattern leads over first-party code
    static           static_leads.json/.md,            cppcheck, clang-tidy, flawfinder, semgrep, lizard
                     maintainability.json              function metrics, maintainability band, layering
    maintainability  the lizard part of `static` alone
    vulns            osv_plan.json | osv_leads.json    OSV.dev lookup: PLAN ONLY unless osv.send is true
    licences         components.json, license_scan.md  open-source component and licence inventory
    sbom             sbom.cdx.json, THIRD_PARTY_NOTICES.md   from a reviewer-confirmed component list
    report           findings.json, report.html/.md,   gates, JUnit, SARIF, GitHub step summary, exit code
                     findings.csv, junit.xml, leads.sarif, gates.json

Exit codes: 0 all gates passed; 1 a gate failed; 2 usage or configuration error; 3 a step's script failed.

What this is and is not. The scripts find LEADS (pattern hits, analyser warnings, metrics, licence files)
and measure code health. Nobody reads the code, so nothing here is a verified finding and the report
says so on every page. The gates fail the build on NEW items only, compared with a committed baseline,
so an existing backlog never blocks a pipeline but new risk does. amygdala:review, run interactively or
on a pull request, is what turns leads into findings.

Nothing leaves the runner. The one exception is the OSV.dev dependency lookup, which is off unless the
config sets "osv": {"send": true}; it then sends the public repository URLs and tags of third-party
components, nothing else (see plugin/skills/review/scripts/osv_check.py and SECURITY.md).

Standard library only; Python 3.8 or later; GitHub Actions, GitLab CI, Azure DevOps, Jenkins or a shell.
"""
import argparse
import datetime
import importlib.util
import json
import os
import platform as _platform
import re
import subprocess
import sys
from xml.sax.saxutils import escape as xml_escape

if sys.version_info < (3, 8):
    sys.exit("This script needs Python 3.8 or later (any interpreter on PATH is fine); found " + sys.version.split()[0])

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
REVIEW = os.path.join(REPO, "plugin", "skills", "review", "scripts")
OSS = os.path.join(REPO, "plugin", "skills", "oss", "scripts")
EXIT_OK, EXIT_GATE, EXIT_USAGE, EXIT_STEP = 0, 1, 2, 3
STEPS = ["platform", "hotspots", "static", "maintainability", "vulns", "licences", "sbom", "report"]
ALL_STEPS = ["platform", "hotspots", "static", "vulns", "licences", "sbom", "report"]

DEFAULT_CONFIG = {
    "project": {"name": None, "version": None},
    "exclude": [],                 # extra vendored / generated directory names to skip
    "layers": {"lower": [], "upper": []},   # path prefixes for the layering check (driver vs application)
    "compile_db": None,            # compile_commands.json for clang-tidy
    "tools": None,                 # static tools to run; null = everything installed
    "timeout": 1800,               # seconds per script
    "osv": {"send": False, "deps": []},     # send=true is the ONLY setting that lets data leave the runner
    "licences": {"run_scancode": False, "maps": [], "confirmed_components": None},
    "baseline": "amygdala-ci-baseline.json",   # relative to the repository root; null = no baseline
    "gates": {
        "required_tools": [],      # tool names that must report "ran" (e.g. ["lizard", "cppcheck"])
        "hotspot_rules": ["private-key", "hardcoded-password", "tls-verify-off", "ota-validate-off",
                          "sample-signing-key", "isr-blocking-in-isr"],
        "static_min_tools": 2,     # a NEW line flagged by this many static tools fails (0 disables)
        "static_errors": True,     # a NEW analyser lead with severity "error" fails
        "new_functions_over_thresholds": True,   # a NEW function over lizard's size/complexity thresholds fails
        "maintainability_rating": "poor",        # fail at this band or worse: "poor", "fair", or null
        "vulnerabilities": True,   # a NEW published advisory for a third-party component fails (osv.send only)
        "licence_families": ["strong", "network", "nc"],   # a NEW component whose most restrictive licence family is listed fails
    },
}
BAND_RANK = {"good": 0, "fair": 1, "poor": 2, "unknown": -1}
CATEGORIES = ["memory-safety", "security", "secure-boot-ota", "robustness", "concurrency", "hardware-power",
              "dependencies", "field-readiness", "regulatory", "code-quality"]
ENV = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1", FW_REVIEW_OPEN="0", SEMGREP_SEND_METRICS="off")


class Usage(Exception):
    pass


class StepFailed(Exception):
    pass


# ---------------------------------------------------------------- helpers
def log(msg):
    print(msg, flush=True)


def read_json(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except OSError:
        return default
    except ValueError as ex:
        raise Usage(f"{path} is not valid JSON: {ex}")


def write_json(path, data):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1)


def write_text(path, text):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


SARIF = load_module(os.path.join(REVIEW, "leads_to_sarif.py"), "amygdala_leads_to_sarif")


def merge(base, over, path=""):
    """Deep-merge a user config over the defaults; unknown keys are an error so typos cannot silently disable a gate."""
    if not isinstance(over, dict):
        raise Usage(f"config{path or ''} must be an object")
    out = dict(base)
    for k, v in over.items():
        if k.startswith("_"):      # "_comment" style notes, as in amygdala-ci.example.json
            continue
        if k not in base:
            raise Usage(f"unknown config key '{path}.{k}'".replace("'.", "'") if path else f"unknown config key '{k}'")
        if isinstance(base[k], dict):
            out[k] = merge(base[k], v, f"{path}.{k}")
        else:
            out[k] = v
    return out


def validate_config(cfg):
    g = cfg["gates"]
    if g["maintainability_rating"] not in (None, "fair", "poor"):
        raise Usage("gates.maintainability_rating must be \"fair\", \"poor\" or null")
    for key in ("exclude", "required_tools", "hotspot_rules", "licence_families"):
        val = cfg[key] if key == "exclude" else g[key]
        if not isinstance(val, list) or not all(isinstance(x, str) for x in val):
            raise Usage(f"{'gates.' if key != 'exclude' else ''}{key} must be a list of strings")
    if not isinstance(g["static_min_tools"], int) or g["static_min_tools"] < 0:
        raise Usage("gates.static_min_tools must be a non-negative integer")
    for k in ("lower", "upper"):
        if not isinstance(cfg["layers"][k], list):
            raise Usage(f"layers.{k} must be a list of path prefixes")
    if cfg["tools"] is not None and not isinstance(cfg["tools"], list):
        raise Usage("tools must be a list of tool names or null")
    if not isinstance(cfg["osv"]["send"], bool):
        raise Usage("osv.send must be true or false")
    return cfg


def load_config(args):
    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        raise Usage(f"--root {args.root} is not a directory")
    path = args.config or os.path.join(root, "amygdala-ci.json")
    user = {}
    if os.path.isfile(path):
        user = read_json(path)
        log(f"config: {path}")
    elif args.config:
        raise Usage(f"--config {args.config} not found")
    cfg = validate_config(merge(DEFAULT_CONFIG, user))
    cfg["_root"] = root
    cfg["_out"] = os.path.abspath(args.out_dir or os.path.join(root, "amygdala-ci"))
    cfg["_config_path"] = path if os.path.isfile(path) else None
    if getattr(args, "exclude", None):
        cfg["exclude"] = list(cfg["exclude"]) + list(args.exclude)
    if getattr(args, "send", False):
        cfg["osv"]["send"] = True
    if getattr(args, "baseline", None):
        cfg["baseline"] = args.baseline
    return cfg


def exclude_args(cfg):
    names = list(cfg["exclude"])
    out = cfg["_out"]
    try:
        rel = os.path.relpath(out, cfg["_root"])
    except ValueError:
        rel = None
    if rel and rel != "." and not rel.startswith(".."):
        names.append(rel.split(os.sep)[0])   # the scripts exclude by directory name; never scan our own output
    args = []
    for n in names:
        args += ["--exclude", n]
    return args


def layer_args(cfg):
    args = []
    for side in ("lower", "upper"):
        for prefix in cfg["layers"][side]:
            args += ["--layer", f"{side}={prefix}"]
    return args


def run_script(cfg, script, *args, allow_fail=False, quiet=False):
    cmd = [sys.executable, script, *[str(a) for a in args]]
    log("$ " + " ".join(os.path.basename(c) if i < 2 else c for i, c in enumerate(cmd)))
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                            env=ENV, timeout=cfg["timeout"])
    except subprocess.TimeoutExpired:
        raise StepFailed(f"{os.path.basename(script)} exceeded the {cfg['timeout']}s timeout")
    tail = "\n".join((cp.stdout + "\n" + cp.stderr).strip().splitlines()[-12:])
    if tail and not quiet:
        log("  " + tail.replace("\n", "\n  "))
    if cp.returncode != 0 and not allow_fail:
        raise StepFailed(f"{os.path.basename(script)} exited {cp.returncode}")
    return cp


def record_step(cfg, name, status, notes=""):
    path = os.path.join(cfg["_out"], "ci_steps.json")
    steps = read_json(path, {}) or {}
    steps[name] = {"status": status, "notes": notes, "at": now_stamp()}
    write_json(path, steps)


def now_stamp():
    return datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")


def git(root, *args):
    try:
        cp = subprocess.run(["git", "-C", root, *args], capture_output=True, text=True, encoding="utf-8",
                            errors="replace", timeout=30)
        return cp.stdout.strip() if cp.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


# ---------------------------------------------------------------- steps
def step_platform(cfg):
    run_script(cfg, os.path.join(REVIEW, "detect_platform.py"), cfg["_root"], "--out", os.path.join(cfg["_out"], "platform.json"))
    record_step(cfg, "platform", "ran")


def step_hotspots(cfg):
    out = cfg["_out"]
    run_script(cfg, os.path.join(REVIEW, "hotspots.py"), cfg["_root"], "--json", "--out", os.path.join(out, "hotspots.json"),
               *exclude_args(cfg), *layer_args(cfg))
    run_script(cfg, os.path.join(REVIEW, "hotspots.py"), cfg["_root"], "--out", os.path.join(out, "hotspots.md"),
               *exclude_args(cfg), *layer_args(cfg))
    hot = read_json(os.path.join(out, "hotspots.json"), {})
    n = sum(v.get("count", 0) for v in hot.get("hits", {}).values())
    record_step(cfg, "hotspots", "ran", f"{n} pattern hit(s) across {len(hot.get('hits', {}))} rule(s)")


def step_static(cfg, step="static", tools=None):
    args = [cfg["_root"], "--out-dir", cfg["_out"], "--timeout", str(cfg["timeout"])] + exclude_args(cfg) + layer_args(cfg)
    tools = tools if tools is not None else cfg["tools"]
    if tools:
        args += ["--tools", ",".join(tools)]
    if cfg["compile_db"]:
        args += ["--compile-db", os.path.join(cfg["_root"], cfg["compile_db"]) if not os.path.isabs(cfg["compile_db"]) else cfg["compile_db"]]
    run_script(cfg, os.path.join(REVIEW, "run_static_tools.py"), *args)
    st = read_json(os.path.join(cfg["_out"], "static_leads.json"), {})
    ran = [t["name"] for t in st.get("tools", []) if t.get("status") == "ran"]
    record_step(cfg, step, "ran", f"{len(st.get('leads', []))} merged location(s); ran: {', '.join(ran) or 'none'}")


def step_vulns(cfg):
    out = cfg["_out"]
    args = [cfg["_root"], "--out-dir", out]
    confirmed = confirmed_components_path(cfg)
    if confirmed:
        args += ["--components", confirmed]
    for d in cfg["osv"]["deps"]:
        args += ["--dep", d]
    if cfg["osv"]["send"]:
        log("osv.send is true: public repository URLs and tags of third-party components WILL be sent to api.osv.dev")
        args.append("--send")
    else:
        log("osv.send is false: planning only, nothing is sent (set \"osv\": {\"send\": true} to query OSV.dev)")
    run_script(cfg, os.path.join(REVIEW, "osv_check.py"), *args)
    if cfg["osv"]["send"]:
        res = read_json(os.path.join(out, "osv_leads.json"), {})
        hits = sum(r.get("count", 0) for r in res.get("results", []))
        record_step(cfg, "vulns", "ran", f"sent; {hits} advisory match(es) across {len(res.get('results', []))} component(s)")
    else:
        plan = read_json(os.path.join(out, "osv_plan.json"), {})
        record_step(cfg, "vulns", "skipped", f"plan only ({len(plan.get('queries', []))} query(ies) would be sent); osv.send is false")


def confirmed_components_path(cfg):
    p = cfg["licences"]["confirmed_components"]
    if not p:
        return None
    full = p if os.path.isabs(p) else os.path.join(cfg["_root"], p)
    return full if os.path.isfile(full) else None


def step_licences(cfg):
    args = [cfg["_root"], "--out-dir", cfg["_out"]] + exclude_args(cfg)
    for m in cfg["licences"]["maps"]:
        args += ["--map", m if os.path.isabs(m) else os.path.join(cfg["_root"], m)]
    if cfg["licences"]["run_scancode"]:
        args += ["--run-scancode", "--scancode-timeout", str(cfg["timeout"])]
    run_script(cfg, os.path.join(OSS, "license_scan.py"), *args)
    comp = read_json(os.path.join(cfg["_out"], "components.json"), {})
    record_step(cfg, "licences", "ran", f"{len(comp.get('components', []))} component(s); scancode {comp.get('scancode_status', 'not run')}")


def step_sbom(cfg):
    confirmed = confirmed_components_path(cfg)
    if not confirmed:
        why = ("no reviewer-confirmed component list: set licences.confirmed_components to the confirmed_components.json "
               "written by an amygdala:oss run (the SBOM and notices are generated from confirmed facts, never guessed)")
        log("sbom: skipped, " + why)
        record_step(cfg, "sbom", "skipped", why)
        return
    run_script(cfg, os.path.join(OSS, "make_outputs.py"), cfg["_root"], "--confirmed", confirmed, "--out-dir", cfg["_out"])
    record_step(cfg, "sbom", "ran", f"from {os.path.relpath(confirmed, cfg['_root'])}")


# ---------------------------------------------------------------- baseline and gates
def current_items(cfg):
    """Everything the gates can look at, keyed by kind, each with a stable fingerprint."""
    out = cfg["_out"]
    src = SARIF.SourceLines(cfg["_root"])
    items = {"hotspot": [], "static": [], "function": [], "vuln": [], "component": []}
    hot = read_json(os.path.join(out, "hotspots.json"))
    if hot:
        for r in SARIF.results_from_hotspots(hot, src):
            items["hotspot"].append({"fp": r["fingerprint"], "rule": r["rule"], "category": r["category"],
                                     "file": r["file"], "line": r["line"], "code": r["code"], "text": r["message"]})
    st = read_json(os.path.join(out, "static_leads.json"))
    if st:
        for lead in st.get("leads", []):
            rel, line = lead.get("file", ""), lead.get("line")
            code = src.line(rel, line)
            hits = lead.get("hits", [])
            tools = sorted({h.get("tool", "") for h in hits if h.get("tool") != "lizard"})
            errors = [h for h in hits if (h.get("severity") or "").lower() in ("error", "fatal")]
            if tools:
                items["static"].append({"fp": SARIF.fingerprint("static-location", "", rel, code, line), "file": rel, "line": line,
                                        "code": code, "tools": tools, "errors": [f"{h['tool']}/{h.get('rule')}" for h in errors],
                                        "text": "; ".join(f"{h.get('tool')}: {h.get('message')}" for h in hits if h.get("tool") != "lizard"),
                                        "cwes": sorted({str(h["cwe"]) for h in hits if h.get("cwe")})})
            for h in hits:
                if h.get("tool") == "lizard":
                    items["function"].append({"fp": SARIF.fingerprint("function", "over-thresholds", rel, code, line), "file": rel,
                                              "line": line, "code": code, "text": h.get("message", "")})
    osv = read_json(os.path.join(out, "osv_leads.json"))
    if osv and osv.get("mode") == "sent":
        for r in osv.get("results", []):
            for v in r.get("vulns", []):
                items["vuln"].append({"fp": SARIF.fingerprint("vuln", v.get("id", ""), r.get("dependency", ""), ""),
                                      "dependency": r.get("dependency"), "id": v.get("id"), "severity": v.get("severity"),
                                      "text": f"{r.get('dependency')} {r.get('queried', '')}: {v.get('id')} {v.get('summary', '')}".strip(),
                                      "url": v.get("url")})
    comp = read_json(os.path.join(out, "components.json"))
    if comp:
        for c in comp.get("components", []):
            if c.get("first_party"):
                continue
            fam = c.get("most_restrictive_family") or "unknown"
            items["component"].append({"fp": SARIF.fingerprint("component", fam, c.get("path", ""), c.get("component", "")),
                                       "component": c.get("component"), "path": c.get("path"), "family": fam,
                                       "licences": sorted((c.get("detected_licenses") or {}).keys()) or c.get("declared_licenses", []),
                                       "text": f"{c.get('component')} ({c.get('path')}): {fam}; "
                                               f"{', '.join(sorted((c.get('detected_licenses') or {}).keys())) or 'no licence detected'}"})
    return items


def baseline_path(cfg):
    b = cfg["baseline"]
    if not b:
        return None
    return b if os.path.isabs(b) else os.path.join(cfg["_root"], b)


def load_baseline(cfg):
    p = baseline_path(cfg)
    if not p or not os.path.isfile(p):
        return None
    data = read_json(p, {})
    if not isinstance(data, dict) or "items" not in data:
        raise Usage(f"baseline {p} is not an amygdala-ci baseline (expected an object with 'items')")
    return data


def cmd_baseline(cfg):
    p = baseline_path(cfg)
    if not p:
        raise Usage("config sets baseline to null; give --baseline PATH to write one")
    items = current_items(cfg)
    if not any(items.values()) and not os.path.isfile(os.path.join(cfg["_out"], "ci_steps.json")):
        raise Usage(f"nothing to baseline in {cfg['_out']}: run `all` (or the individual steps) first")
    data = {"tool": "amygdala-ci", "generated": now_stamp(), "root": os.path.basename(cfg["_root"]),
            "commit": git(cfg["_root"], "rev-parse", "--short", "HEAD") or None,
            "note": "Fingerprints of leads accepted as the baseline. Gates fail on items NOT listed here. "
                    "Regenerate with `amygdala_ci.py baseline` after deliberately accepting new items.",
            "items": {k: sorted(x["fp"] for x in v) for k, v in items.items()}}
    write_json(p, data)
    log(f"baseline: {sum(len(v) for v in data['items'].values())} item(s) -> {p}")


def tool_status(cfg):
    st = read_json(os.path.join(cfg["_out"], "static_leads.json"), {}) or {}
    return {t["name"]: t for t in st.get("tools", [])}


def evaluate_gates(cfg):
    """Returns (gates, items, baseline). Each gate: name, status pass|fail|skipped, items (new ones), note."""
    g = cfg["gates"]
    items = current_items(cfg)
    baseline = load_baseline(cfg)
    known = {k: set(v) for k, v in (baseline or {}).get("items", {}).items()}

    def new(kind):
        return [x for x in items[kind] if x["fp"] not in known.get(kind, set())]

    steps = read_json(os.path.join(cfg["_out"], "ci_steps.json"), {}) or {}
    gates = []

    def gate(name, status, found=None, note=""):
        gates.append({"name": name, "status": status, "items": found or [], "note": note})

    # required tools
    tools = tool_status(cfg)
    if g["required_tools"]:
        if "static" not in steps and "maintainability" not in steps:
            gate("required-tools", "skipped", note="static step did not run")
        else:
            missing = [t for t in g["required_tools"] if tools.get(t, {}).get("status") != "ran"]
            gate("required-tools", "fail" if missing else "pass",
                 [{"text": f"{t}: {tools.get(t, {}).get('status', 'unknown')} ({tools.get(t, {}).get('notes', '')})", "tool": t} for t in missing],
                 note="all required tools ran" if not missing else f"{len(missing)} required tool(s) did not run")

    # hotspot rules
    if "hotspots" not in steps:
        gate("hotspot-rules", "skipped", note="hotspots step did not run")
    elif g["hotspot_rules"]:
        found = [x for x in new("hotspot") if x["rule"] in set(g["hotspot_rules"])]
        gate("hotspot-rules", "fail" if found else "pass", found,
             note=f"rules: {', '.join(g['hotspot_rules'])}")

    # static: agreement and errors
    if "static" not in steps:
        gate("static-agreement", "skipped", note="static step did not run")
        gate("static-errors", "skipped", note="static step did not run")
    else:
        if g["static_min_tools"] > 0:
            found = [x for x in new("static") if len(x["tools"]) >= g["static_min_tools"]]
            gate("static-agreement", "fail" if found else "pass", found,
                 note=f"new lines flagged by at least {g['static_min_tools']} analysers")
        if g["static_errors"]:
            found = [x for x in new("static") if x["errors"]]
            gate("static-errors", "fail" if found else "pass", found, note="new analyser leads with severity error")

    # functions over thresholds
    if g["new_functions_over_thresholds"]:
        if "static" not in steps and "maintainability" not in steps:
            gate("functions-over-thresholds", "skipped", note="static step did not run")
        elif tools.get("lizard", {}).get("status") != "ran":
            gate("functions-over-thresholds", "skipped", note=f"lizard {tools.get('lizard', {}).get('status', 'not run')}: {tools.get('lizard', {}).get('notes', '')}")
        else:
            found = new("function")
            gate("functions-over-thresholds", "fail" if found else "pass", found, note="new functions over lizard's size / complexity thresholds")

    # maintainability band (absolute, not baseline-relative)
    mt = read_json(os.path.join(cfg["_out"], "maintainability.json"), {}) or {}
    if g["maintainability_rating"]:
        rating = mt.get("rating", "unknown")
        if not mt or rating == "unknown":
            gate("maintainability-rating", "skipped", note=f"no rating ({mt.get('notes', 'maintainability.json missing')})")
        else:
            bad = BAND_RANK[rating] >= BAND_RANK[g["maintainability_rating"]]
            worst = (mt.get("worst_functions") or [{}])[0]
            gate("maintainability-rating", "fail" if bad else "pass",
                 [{"text": f"maintainability rated {rating}: {mt.get('rating_basis', '')}", "rule": rating,
                   "file": worst.get("file"), "line": worst.get("line"), "code": ""}] if bad else [],
                 note=f"rated {rating}; fails at {g['maintainability_rating']} or worse")

    # vulnerabilities
    if g["vulnerabilities"]:
        osv = read_json(os.path.join(cfg["_out"], "osv_leads.json"))
        if "vulns" not in steps:
            gate("vulnerabilities", "skipped", note="vulns step did not run")
        elif not cfg["osv"]["send"] or not osv or osv.get("mode") != "sent":
            gate("vulnerabilities", "skipped", note="OSV.dev lookup not sent (osv.send is false)")
        else:
            found = new("vuln")
            gate("vulnerabilities", "fail" if found else "pass", found, note="new published advisories for third-party components")

    # licence families
    if g["licence_families"]:
        if "licences" not in steps:
            gate("licence-families", "skipped", note="licences step did not run")
        else:
            fams = set(g["licence_families"])
            found = [x for x in new("component") if x["family"] in fams]
            gate("licence-families", "fail" if found else "pass", found, note=f"new components in families: {', '.join(sorted(fams))}")

    return gates, items, baseline


# ---------------------------------------------------------------- report
CI_PROFILE = {
    "title": "Automated checks (CI)",
    "must_fix_heading": "New items that need a developer's verdict",
    "verdict": {
        "red": "AUTOMATED CHECKS FAILED",
        "amber": "AUTOMATED CHECKS FAILED — NEW ITEMS TO VERIFY",
        "green": "AUTOMATED CHECKS PASSED — THIS IS NOT A CODE REVIEW",
    },
    "verdict_sub": {
        "red": "{n} gate(s) failed.",
        "amber": "{n} gate(s) failed on items that are new since the baseline. Each is a lead from a tool, not a verified finding: a developer must confirm it is a defect, fix it, or accept it into the baseline.",
        "green": "No new items crossed the configured gates. Nothing here was read by a reviewer; run amygdala:review for verified findings.",
        "green_tracking": "No open gate failures.",
    },
    "rag_meaning": {"red": "Gate failed", "amber": "Gate failed: verify, fix or accept", "green": "Informational"},
    "legend": {
        "red": "Not used by the automated checks.",
        "amber": "A configured gate failed on something new since the baseline. The tools cannot tell a real defect from a false positive; a developer must look.",
        "green": "Not used by the automated checks.",
    },
    "disclaimer": "Automated output from pattern scanning, static analysers, function metrics and licence-file detection. "
                  "No code was read and nothing here is a verified finding. Gates compare against the committed baseline and fail only on new items.",
}
GATE_META = {   # gate -> (category, origin, title template, recommendation)
    "required-tools": ("code-quality", "first-party", "{n} required analyser(s) did not run",
                       "Install the tool on the runner (the install command is in the item text) or remove it from gates.required_tools."),
    "hotspot-rules": ("security", "first-party", "{n} new pattern hit(s) for gated rule '{rule}'",
                      "Read each location. If it is a real defect, fix it and re-run. If it is acceptable, accept it into the baseline with `amygdala_ci.py baseline` and commit the file."),
    "static-agreement": ("memory-safety", "first-party", "{n} new line(s) flagged by several analysers",
                         "Lines that two or more independent analysers flag are the ones most worth reading first. Fix, or accept into the baseline with a reason in the commit message."),
    "static-errors": ("memory-safety", "first-party", "{n} new analyser error(s)",
                      "An analyser rated these as errors, not warnings. Fix, or accept into the baseline with a reason in the commit message."),
    "functions-over-thresholds": ("code-quality", "first-party", "{n} new function(s) over the size / complexity thresholds",
                                  "Split the function or reduce its branching before it grows further; see the Maintainability section for the numbers."),
    "maintainability-rating": ("code-quality", "first-party", "Maintainability rated {rule}",
                               "Work through the worst functions in the Maintainability section; the band is recomputed on every run."),
    "vulnerabilities": ("dependencies", "third-party", "{n} new published advisory(ies) for third-party components",
                        "Check whether the affected feature is compiled in and reachable; update the component or record the risk acceptance. These are third-party records, not defects in this code."),
    "licence-families": ("dependencies", "third-party", "{n} new component(s) with a {rule} licence family",
                         "Confirm the licence and how the component is distributed (linked, separate, build-only); run amygdala:oss for the obligations."),
}
HOTSPOT_CATEGORY_DEFAULT = "security"


def item_line(it):
    """One line per gated item for evidence blocks and JUnit bodies: where, what the line says, what the tool said."""
    where = it.get("file") or it.get("path") or it.get("dependency") or ""
    if it.get("line"):
        where += f":{it['line']}"
    code = (it.get("code") or "").strip()
    return "  ".join(x for x in (where, code, it.get("text", "")) if x)


def gate_findings(gates):
    findings, n = [], 0
    for gt in gates:
        if gt["status"] != "fail":
            continue
        cat, origin, title, rec = GATE_META[gt["name"]]
        groups = {}
        for it in gt["items"]:
            key = it.get("rule") or it.get("family") or ""
            groups.setdefault(key, []).append(it)
        for key, its in sorted(groups.items()):
            n += 1
            first = its[0]
            category = first.get("category") or cat
            if category not in CATEGORIES:
                category = cat
            locs = [{"file": x.get("file") or x.get("path") or "(repository)", "line": x.get("line") if isinstance(x.get("line"), int) else None} for x in its]
            evidence = "\n".join(item_line(x) for x in its[:12])
            refs = sorted({c if c.upper().startswith("CWE") else f"CWE-{c}" for x in its for c in x.get("cwes", [])})
            findings.append({
                "id": f"CI-{n:03d}", "title": title.format(n=len(its), rule=key or "n/a"),
                "rag": "amber", "category": category, "confidence": "needs-verification",
                "location": locs[0], "other_locations": locs[1:],
                "evidence": evidence,
                "description": f"Gate '{gt['name']}' ({gt['note']}). " + "; ".join(x.get("text", "")[:200] for x in its[:5]) + (" ..." if len(its) > 5 else ""),
                "impact": "Not assessed. The automated checks cannot tell a reachable defect from a false positive; this item is new since the baseline and needs a developer's verdict.",
                "recommendation": rec,
                "origin": origin, "references": refs,
            })
    return findings


def build_findings(cfg, gates, items, baseline):
    out = cfg["_out"]
    root = cfg["_root"]
    plat = read_json(os.path.join(out, "platform.json"), {}) or {}
    st = read_json(os.path.join(out, "static_leads.json"), {}) or {}
    mt = read_json(os.path.join(out, "maintainability.json"))
    hot = read_json(os.path.join(out, "hotspots.json"), {}) or {}
    comp = read_json(os.path.join(out, "components.json"), {}) or {}
    osv = read_json(os.path.join(out, "osv_leads.json")) or read_json(os.path.join(out, "osv_plan.json"))
    steps = read_json(os.path.join(out, "ci_steps.json"), {}) or {}
    failed = [g for g in gates if g["status"] == "fail"]
    passed = [g for g in gates if g["status"] == "pass"]
    skipped = [g for g in gates if g["status"] == "skipped"]
    name = cfg["project"]["name"] or os.path.basename(root)
    version = cfg["project"]["version"] or git(root, "describe", "--tags", "--always", "--dirty") or None
    commit = git(root, "rev-parse", "--short", "HEAD")

    tools = [{"name": "detect_platform.py", "status": "ran" if plat else "not_available",
              "notes": (plat.get("detection_confidence", "") + " confidence; platforms: " + ", ".join(p.get("platform", p.get("name", "?")) if isinstance(p, dict) else str(p) for p in plat.get("platforms", [])[:4])) if plat else "step did not run"},
             {"name": "hotspots.py", "status": "ran" if hot else "not_available",
              "notes": f"{sum(v.get('count', 0) for v in hot.get('hits', {}).values())} pattern hit(s) across {len(hot.get('hits', {}))} rule(s); {len(hot.get('absent_presence_checks', []))} absence check(s)" if hot else "step did not run"}]
    tools += [{"name": t["name"], "status": t["status"], "notes": f"{t.get('notes', '')}; {t.get('leads', 0)} lead(s)"} for t in st.get("tools", [])]
    if osv and osv.get("mode") == "sent":
        tools.append(osv.get("tools_entry") or {"name": "OSV.dev dependency lookup", "status": "ran", "notes": ""})
    else:
        tools.append({"name": "OSV.dev dependency lookup", "status": "skipped",
                      "notes": (f"plan only, nothing sent: {len(osv.get('queries', []))} query(ies) would go to api.osv.dev if osv.send were true" if osv else "step did not run")})
    tools.append({"name": "license_scan.py", "status": "ran" if comp else "not_available",
                  "notes": f"{len(comp.get('components', []))} component(s); ScanCode {comp.get('scancode_status', 'not run')}" if comp else "step did not run"})
    if "sbom" in steps:
        tools.append({"name": "make_outputs.py (SBOM, notices)", "status": "ran" if steps["sbom"]["status"] == "ran" else "skipped", "notes": steps["sbom"]["notes"]})

    counts = {k: len(v) for k, v in items.items()}
    overview = (f"Automated checks on {name}" + (f" at {commit}" if commit else "") + f", run {now_stamp()}. "
                f"The tools produced {counts['hotspot']} pattern hit(s), {counts['static']} analyser location(s), {counts['function']} function(s) over the size / complexity thresholds"
                + (f", {counts['vuln']} published advisory match(es)" if osv and osv.get("mode") == "sent" else "")
                + f" and {counts['component']} third-party component(s). "
                + (f"Compared with the baseline of {sum(len(v) for v in baseline.get('items', {}).values())} accepted item(s) from {baseline.get('generated', '?')}"
                   + (f" (commit {baseline['commit']})" if baseline.get("commit") else "") + ", "
                   if baseline else "No baseline file was found, so every item counts as new; accept the current state with `amygdala_ci.py baseline`. ")
                + (f"{len(failed)} gate(s) failed: {', '.join(g['name'] for g in failed)}." if failed else f"all {len(passed)} evaluated gate(s) passed.")
                + (f" {len(skipped)} gate(s) could not be evaluated: {', '.join(g['name'] for g in skipped)}." if skipped else "")
                + " No code was read: this is not a code review and the scorecard shows every area as not assessed on purpose.")
    key_risks = [f"{g['name']}: {len(g['items'])} new item(s). {g['note']}" for g in failed]
    strengths = []
    if mt and mt.get("rating") in ("good", "fair"):
        strengths.append(f"Maintainability rated {mt['rating']}: {mt.get('rating_basis', '')}")
    ran = [t["name"] for t in tools if t["status"] == "ran"]
    if ran:
        strengths.append("Ran: " + ", ".join(ran))

    d = {
        "report": CI_PROFILE,
        "project": {"name": name, "repo_path": os.path.basename(root), "version": version,
                    "review_date": now_stamp(), "reviewer": "./phazeOne Amygdala CI (automated checks, no reviewer)",
                    "platform": {"summary": "; ".join(str(p.get("platform", p)) if isinstance(p, dict) else str(p) for p in plat.get("platforms", [])) or "not detected"}},
        "summary": {"overview": overview, "key_risks": key_risks, "strengths": strengths},
        "coverage": [{"area": c, "status": "not_reviewed", "notes": "Automated checks only; no code was read."} for c in CATEGORIES],
        "tools": tools,
        "findings": gate_findings(gates),
        "next_steps": [
            "Treat every item above as a lead: open the file, decide, fix or accept. Nothing here has been verified by a person.",
            "Run amygdala:review (interactively, or on the pull request) to turn leads into verified, RAG-rated findings with field impact.",
            "After deliberately accepting items, regenerate the baseline with `amygdala_ci.py baseline` and commit it with the reason.",
        ] + (["Enable the OSV.dev lookup (osv.send: true) once the team has agreed that component URLs and tags may leave the runner."]
             if not cfg["osv"]["send"] else []),
    }
    if mt:
        d["maintainability"] = mt
    return d


def write_junit(path, gates, tools):
    cases = []
    for g in gates:
        name = xml_escape(g["name"])
        if g["status"] == "fail":
            body = xml_escape("\n".join(item_line(x) for x in g["items"][:50]))
            cases.append(f'  <testcase classname="amygdala.gates" name="{name}"><failure message="{xml_escape(str(len(g["items"])) + " new item(s): " + g["note"])}">{body}</failure></testcase>')
        elif g["status"] == "skipped":
            cases.append(f'  <testcase classname="amygdala.gates" name="{name}"><skipped message="{xml_escape(g["note"])}"/></testcase>')
        else:
            cases.append(f'  <testcase classname="amygdala.gates" name="{name}"/>')
    for t in tools:
        name = xml_escape(t["name"])
        if t["status"] == "ran":
            cases.append(f'  <testcase classname="amygdala.tools" name="{name}"><system-out>{xml_escape(t.get("notes", ""))}</system-out></testcase>')
        else:
            cases.append(f'  <testcase classname="amygdala.tools" name="{name}"><skipped message="{xml_escape(t["status"] + ": " + t.get("notes", ""))}"/></testcase>')
    failures = sum(1 for g in gates if g["status"] == "fail")
    skipped = sum(1 for g in gates if g["status"] == "skipped") + sum(1 for t in tools if t["status"] != "ran")
    xml = ('<?xml version="1.0" encoding="UTF-8"?>\n'
           f'<testsuites tests="{len(cases)}" failures="{failures}">\n'
           f'<testsuite name="amygdala-ci" tests="{len(cases)}" failures="{failures}" errors="0" skipped="{skipped}">\n'
           + "\n".join(cases) + "\n</testsuite>\n</testsuites>\n")
    write_text(path, xml)


def step_summary_md(d, gates, out):
    lines = [f"## Amygdala automated checks: {'FAILED' if any(g['status'] == 'fail' for g in gates) else 'passed'}", "",
             d["summary"]["overview"], "", "| Gate | Result | New items | Note |", "|---|---|---:|---|"]
    for g in gates:
        lines.append(f"| {g['name']} | {g['status']} | {len(g['items'])} | {g['note']} |")
    lines += ["", "| Tool | Status | Notes |", "|---|---|---|"]
    for t in d["tools"]:
        lines.append(f"| {t['name']} | {t['status']} | {t.get('notes', '')} |")
    lines += ["", f"Report files: `{out}` (report.html, report.md, findings.csv, leads.sarif, junit.xml). Leads, not findings."]
    return "\n".join(lines) + "\n"


def step_report(cfg):
    out = cfg["_out"]
    gates, items, baseline = evaluate_gates(cfg)
    d = build_findings(cfg, gates, items, baseline)
    write_json(os.path.join(out, "findings.json"), d)
    run_script(cfg, os.path.join(REVIEW, "render_report.py"), os.path.join(out, "findings.json"), "--out-dir", out)
    sarif_args = ["--root", cfg["_root"], "--out", os.path.join(out, "leads.sarif")]
    if os.path.isfile(os.path.join(out, "static_leads.json")):
        sarif_args += ["--static", os.path.join(out, "static_leads.json")]
    if os.path.isfile(os.path.join(out, "hotspots.json")):
        sarif_args += ["--hotspots", os.path.join(out, "hotspots.json")]
    if "--static" in sarif_args or "--hotspots" in sarif_args:
        run_script(cfg, os.path.join(REVIEW, "leads_to_sarif.py"), *sarif_args)
    write_junit(os.path.join(out, "junit.xml"), gates, d["tools"])
    write_json(os.path.join(out, "gates.json"), {"generated": now_stamp(), "baseline": baseline_path(cfg) if baseline else None,
                                                 "exit_code": EXIT_GATE if any(g["status"] == "fail" for g in gates) else EXIT_OK,
                                                 "gates": gates})
    md = step_summary_md(d, gates, out)
    write_text(os.path.join(out, "summary.md"), md)
    gh = os.environ.get("GITHUB_STEP_SUMMARY")
    if gh:
        try:
            with open(gh, "a", encoding="utf-8") as f:
                f.write(md)
        except OSError:
            pass
    log("")
    for g in gates:
        log(f"gate {g['name']:<28} {g['status']:<8} {len(g['items']):>4} new   {g['note']}")
    failed = [g for g in gates if g["status"] == "fail"]
    log("")
    log(f"{'FAILED' if failed else 'passed'}: {len(failed)} gate(s) failed; report in {out}")
    record_step(cfg, "report", "ran", f"{len(failed)} gate(s) failed")
    return EXIT_GATE if failed else EXIT_OK


# ---------------------------------------------------------------- check
def cmd_check(cfg):
    st = run_script(cfg, os.path.join(REVIEW, "run_static_tools.py"), cfg["_root"], "--check", allow_fail=True, quiet=True)
    lic = run_script(cfg, os.path.join(OSS, "license_scan.py"), cfg["_root"], "--check", allow_fail=True, quiet=True)
    try:
        static = json.loads(st.stdout)
        licence = json.loads(lic.stdout)
    except ValueError:
        raise StepFailed("--check output was not JSON")
    missing_required = [t for t in cfg["gates"]["required_tools"] if not static.get("tools", {}).get(t, {}).get("installed")]
    result = {"python": sys.version.split()[0], "os": _platform.system(), "config": cfg["_config_path"] or "(defaults)",
              "root": cfg["_root"], "out_dir": cfg["_out"], "baseline": baseline_path(cfg),
              "baseline_present": bool(baseline_path(cfg) and os.path.isfile(baseline_path(cfg))),
              "osv_send": cfg["osv"]["send"],
              "static_tools": {k: {"installed": v.get("installed"), "version": v.get("version"), "install": v.get("install_commands")}
                               for k, v in static.get("tools", {}).items()},
              "scancode": licence.get("scancode"), "missing_required_tools": missing_required,
              "gates": cfg["gates"]}
    print(json.dumps(result, indent=1))
    if missing_required:
        log(f"required tools missing: {', '.join(missing_required)}")
        return EXIT_GATE
    return EXIT_OK


# ---------------------------------------------------------------- main
def main(argv=None):
    ap = argparse.ArgumentParser(prog="amygdala_ci.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=STEPS + ["all", "baseline", "check"])
    ap.add_argument("--root", default=".", help="repository to check (default: current directory)")
    ap.add_argument("--out-dir", help="where outputs go (default: <root>/amygdala-ci; excluded from the scan)")
    ap.add_argument("--config", help="amygdala-ci.json (default: <root>/amygdala-ci.json if it exists)")
    ap.add_argument("--exclude", action="append", default=[], help="extra directory name to skip; repeatable")
    ap.add_argument("--baseline", help="baseline file to compare with / write (overrides the config)")
    ap.add_argument("--send", action="store_true", help="vulns/all: send the OSV.dev queries (same as osv.send: true)")
    args = ap.parse_args(argv)
    try:
        cfg = load_config(args)
        os.makedirs(cfg["_out"], exist_ok=True)
        if args.command == "check":
            return cmd_check(cfg)
        if args.command == "baseline":
            cmd_baseline(cfg)
            return EXIT_OK
        if args.command == "all":
            if os.path.isfile(os.path.join(cfg["_out"], "ci_steps.json")):
                os.remove(os.path.join(cfg["_out"], "ci_steps.json"))
            for step in ALL_STEPS:
                log(f"\n== {step}")
                code = RUN[step](cfg)
                if step == "report":
                    return code
            return EXIT_OK
        return RUN[args.command](cfg) or EXIT_OK
    except Usage as ex:
        log(f"amygdala_ci: {ex}")
        return EXIT_USAGE
    except StepFailed as ex:
        log(f"amygdala_ci: step failed: {ex}")
        return EXIT_STEP


RUN = {
    "platform": step_platform, "hotspots": step_hotspots, "static": step_static,
    "maintainability": lambda cfg: step_static(cfg, step="maintainability", tools=["lizard"]),
    "vulns": step_vulns, "licences": step_licences, "sbom": step_sbom, "report": step_report,
}

if __name__ == "__main__":
    sys.exit(main())
