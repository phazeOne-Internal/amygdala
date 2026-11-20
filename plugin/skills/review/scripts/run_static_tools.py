#!/usr/bin/env python3
"""Detect, and run, static analysis tools over first-party firmware code. Cross-platform (Windows/macOS/Linux).

Two modes:

  --check                 Report which tools are installed and, for missing ones, the install
                          command for THIS operating system. Prints JSON. Installs nothing.
                          Use the output to ask the user what (if anything) to install.

  (default: run)          Run the available tools and merge their output into one de-duplicated
                          set of leads: static_leads.md (to read) and static_leads.json (tools
                          status + leads, to copy into findings.json "tools").

Usage:
  python run_static_tools.py <repo-root> --check
  python run_static_tools.py <repo-root> --out-dir DIR [--tools cppcheck,clang-tidy,flawfinder,semgrep]
         [--exclude DIR ...] [--compile-db PATH] [--misra] [--timeout SECONDS] [--jobs N]

Leads are NOT findings: every one must be read in context before it goes in the report.
Nothing is sent off the machine: semgrep runs with --metrics=off and only the bundled local rules.
"""
import argparse
import csv
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

if sys.version_info < (3, 8):
    sys.exit("This script needs Python 3.8 or later (any interpreter on PATH is fine); found " + sys.version.split()[0])

for _s in (sys.stdout, sys.stderr):  # Windows consoles default to cp1252; code snippets may not be ASCII
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEMGREP_RULES = os.path.join(SKILL_DIR, "assets", "semgrep", "embedded-c.yml")
OS = {"Windows": "windows", "Darwin": "macos"}.get(platform.system(), "linux")
ARCH = {"ARM64": "arm64", "AARCH64": "arm64", "AMD64": "x64", "X86_64": "x64"}.get(platform.machine().upper(), platform.machine().lower() or "unknown")

DEFAULT_EXCLUDES = {
    "mtb_shared", "libs", "deps", "third_party", "thirdparty", "third-party", "vendor", "external",
    "extern", "modules", "zephyr", "nrf", "nrfxlib", "mcuboot", "middlewares", "cmsis",
    "managed_components", ".pio", "bsps", "generatedsource", "build", "out", "node_modules", ".git",
}
SRC_EXT = {".c", ".cpp", ".cc", ".cxx"}
HDR_EXT = {".h", ".hpp"}

TOOLS = {
    "cppcheck": {
        "purpose": "General C/C++ bug finder: buffer overruns, null derefs, leaks, uninitialised data. "
                   "Works without a build setup. Best value for least effort.",
        "exe": ["cppcheck"],
        "extra_paths": {"windows": [r"C:\Program Files\Cppcheck\cppcheck.exe", r"C:\Program Files (x86)\Cppcheck\cppcheck.exe"]},
        "install": {
            "macos": ["brew install cppcheck"],
            "linux": ["sudo apt-get install -y cppcheck", "sudo dnf install -y cppcheck"],
            "windows": ["winget install --id Cppcheck.Cppcheck -e --accept-source-agreements --accept-package-agreements",
                        "choco install cppcheck -y"],
        },
        "size": "small (~20 MB)",
    },
    "clang-tidy": {
        "purpose": "Deep semantic checks (bugprone, CERT, clang static analyzer). Needs compile_commands.json "
                   "from the build; skipped if none is found.",
        "exe": ["clang-tidy"],
        "extra_paths": {
            "macos": ["/opt/homebrew/opt/llvm/bin/clang-tidy", "/usr/local/opt/llvm/bin/clang-tidy"],
            "windows": [r"C:\Program Files\LLVM\bin\clang-tidy.exe"],
        },
        "install": {
            "macos": ["brew install llvm"],
            "linux": ["sudo apt-get install -y clang-tidy", "sudo dnf install -y clang-tools-extra"],
            "windows": ["winget install --id LLVM.LLVM -e --accept-source-agreements --accept-package-agreements",
                        "choco install llvm -y"],
        },
        "size": "large (~1-2 GB with LLVM)",
    },
    "flawfinder": {
        "purpose": "Fast security scanner for risky C functions (CWE-tagged). Noisy but never misses a call site.",
        "exe": ["flawfinder"],
        "extra_paths": {},
        "install": {
            "macos": ["brew install flawfinder", "python3 -m pip install --user flawfinder"],
            "linux": ["python3 -m pip install --user flawfinder", "sudo apt-get install -y flawfinder"],
            "windows": ["py -m pip install --user flawfinder"],
        },
        "size": "tiny (pure Python)",
    },
    "semgrep": {
        "purpose": "Pattern rules; runs the skill's embedded-firmware rules (ISR misuse, assert-as-error-handling, "
                   "TLS verify off, tick wrap...). Runs locally with metrics off.",
        "exe": ["semgrep", "pysemgrep"],
        "extra_paths": {},
        "install": {
            "macos": ["brew install semgrep", "python3 -m pip install --user semgrep"],
            "linux": ["python3 -m pip install --user semgrep"],
            "windows": ["py -m pip install --user semgrep"],
        },
        "install_note": {"windows": "The command names a Python version semgrep has prebuilt wheels for; plain `py` would use "
                                    "your newest Python, which may be too new. Native Windows support in semgrep is recent; "
                                    "if the install or the first run still fails, use WSL."},
        # Platforms where the install is known to fail; --check reports these as unavailable with no install command,
        # so the user is not sent down a pip build that dies after several minutes.
        "unavailable": {("windows", "arm64"): "No prebuilt wheels for Windows on ARM (cryptography, ruamel.yaml.clib), so "
                                             "pip tries to compile them and fails. Run the review under WSL "
                                             "(`wsl --install`, then `pip install semgrep` inside it) or on an x64 machine "
                                             "to get semgrep coverage; the review continues without it."},
        "size": "medium (~200 MB)",
    },
}


def windows_pip():
    """`py -3.X` for the newest installed Python the pip-installed tools have prebuilt wheels for, else `py`.
    Plain `py` runs the newest Python on the machine, which is often newer than semgrep's dependencies support."""
    if OS != "windows" or not shutil.which("py"):
        return "py"
    for v in ("3.13", "3.12", "3.11", "3.10", "3.9"):
        try:
            r = subprocess.run(["py", f"-{v}", "-c", "pass"], capture_output=True, timeout=30)
            if r.returncode == 0:
                return f"py -{v}"
        except (OSError, subprocess.TimeoutExpired):
            continue
    return "py"


def install_commands(t):
    cmds = t["install"].get(OS, [])
    if OS == "windows":
        launcher = windows_pip()
        cmds = [c.replace("py -m pip", f"{launcher} -m pip") for c in cmds]
    return cmds


def user_script_dirs():
    """Folders where `pip install --user` puts console scripts; usually not on PATH on Windows and macOS."""
    import glob
    import sysconfig
    home = os.path.expanduser("~")
    dirs = [os.path.join(home, ".local", "bin")]
    for scheme in ("nt_user", "osx_framework_user", "posix_user"):
        try:
            d = sysconfig.get_path("scripts", scheme)
        except Exception:  # noqa: BLE001  (schemes differ by version and platform; any failure just means "no such folder")
            continue
        if d:
            dirs.append(d)
    if OS == "windows":
        dirs += glob.glob(os.path.join(os.environ.get("APPDATA", ""), "Python", "Python3*", "Scripts"))
    if OS == "macos":
        dirs += glob.glob(os.path.join(home, "Library", "Python", "3.*", "bin"))
    seen, out = set(), []
    for d in dirs:
        if d and d not in seen and os.path.isdir(d):
            seen.add(d)
            out.append(d)
    return out


def cppcheck_works(path):
    """Strawberry Perl and some SDKs put a cppcheck on PATH that cannot run a scan (no cfg files); a
    one-file trial run tells a working install from a stub."""
    d = tempfile.mkdtemp(prefix="cppcheck-probe-")
    try:
        with open(os.path.join(d, "probe.c"), "w", encoding="utf-8") as f:
            f.write("int main(void) { return 0; }\n")
        rc, out, err, fail = run([path, "--xml", "--quiet", "--enable=warning", d], 120)
        return fail is None and rc == 0 and "<results" in err
    finally:
        shutil.rmtree(d, ignore_errors=True)


WORKS = {"cppcheck": cppcheck_works}
_FOUND = {}


def tool_candidates(name):
    t = TOOLS[name]
    cands = []
    # every PATH entry, not just the first hit: the first one may be a stub (see cppcheck_works)
    for d in os.environ.get("PATH", "").split(os.pathsep):
        for exe in t["exe"]:
            p = shutil.which(exe, path=d) if d else None
            if p:
                cands.append(p)
    cands += [p for p in t["extra_paths"].get(OS, []) if os.path.isfile(p)]
    for d in user_script_dirs():
        for exe in t["exe"]:
            p = shutil.which(exe, path=d)
            if p:
                cands.append(p)
    seen, out = set(), []
    for c in cands:
        k = os.path.normcase(os.path.abspath(c))
        if k not in seen:
            seen.add(k)
            out.append(c)
    return out


def find_tool(name):
    if name in _FOUND:
        return _FOUND[name]
    works = WORKS.get(name)
    found = None
    for p in tool_candidates(name):
        if works is None or works(p):
            found = p
            break
    _FOUND[name] = found
    return found


def tool_version(path):
    try:
        out = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=60, env=tool_env(path))
        line = (out.stdout or out.stderr).strip().splitlines()
        return line[0][:120] if line else ""
    except Exception as ex:  # noqa: BLE001
        return f"(version check failed: {ex})"


def find_compile_db(root, explicit=None):
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules"}]
        if "compile_commands.json" in filenames:
            return os.path.join(dirpath, "compile_commands.json")
        if dirpath.count(os.sep) - root.count(os.sep) > 4:
            dirnames[:] = []
    return None


def compile_db_hint(root):
    if os.path.exists(os.path.join(root, "Makefile")) and any(
            f.endswith(".mtb") for _, _, fs in os.walk(root) for f in fs):
        return ("ModusToolbox: build once (`make build`) and look for compile_commands.json under build/; "
                "recent ModusToolbox versions generate it. Otherwise use `bear -- make build`.")
    if os.path.exists(os.path.join(root, "west.yml")) or any(
            os.path.exists(os.path.join(root, d, "prj.conf")) for d in ("", "app")):
        return "Zephyr: `west build` writes build/compile_commands.json."
    if os.path.exists(os.path.join(root, "platformio.ini")):
        return "PlatformIO: `pio run -t compiledb`."
    if any(os.path.exists(os.path.join(root, f)) for f in ("sdkconfig", "sdkconfig.defaults")):
        return "ESP-IDF: `idf.py build` writes build/compile_commands.json."
    return "CMake: configure with -DCMAKE_EXPORT_COMPILE_COMMANDS=ON. Make: `bear -- make`."


def first_party(root, excludes):
    srcs, inc_dirs = [], set()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d.lower() not in excludes and not d.startswith(".")]
        for f in filenames:
            ext = os.path.splitext(f)[1]
            full = os.path.join(dirpath, f)
            if ext in SRC_EXT:
                srcs.append(full)
            if ext in HDR_EXT:
                inc_dirs.add(dirpath)
    return sorted(srcs), sorted(inc_dirs)


def rel(root, p):
    try:
        r = os.path.relpath(os.path.abspath(p), root)
        return (os.path.abspath(p) if r.startswith("..") else r).replace(os.sep, "/")
    except ValueError:  # different drive on Windows
        return p.replace(os.sep, "/")


def tool_env(exe):
    """Environment for running a tool: its own folder goes first on PATH, because wrappers such as
    semgrep.exe exec a sibling (pysemgrep.exe) by name, and pip --user folders are rarely on PATH."""
    env = dict(os.environ)
    d = os.path.dirname(exe) if exe and os.path.isabs(exe) else ""
    if d:
        env["PATH"] = d + os.pathsep + env.get("PATH", "")
    return env


def run(cmd, timeout, cwd=None):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd,
                           encoding="utf-8", errors="replace", env=tool_env(cmd[0]))
        return r.returncode, r.stdout, r.stderr, None
    except subprocess.TimeoutExpired:
        return None, "", "", f"timed out after {timeout}s"
    except OSError as ex:
        return None, "", "", str(ex)


# ------------------------------------------------------------------ tool runners

def run_cppcheck(path, root, srcs, incs, args):
    if not srcs:
        return [], "skipped", "no first-party C/C++ source files"
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as fl:
        fl.write("\n".join(srcs))
        listfile = fl.name
    cmd = [path, "--xml", "--xml-version=2", "--enable=warning,style,performance,portability",
           "--inconclusive", "--std=c11", "--platform=unix32", "--inline-suppr", "--quiet",
           "--suppress=missingIncludeSystem", "--suppress=missingInclude", "--suppress=unusedFunction",
           "--suppress=checkersReport",
           f"-j{args.jobs}", f"--file-list={listfile}",
           # common embedded / vendor macros cppcheck otherwise chokes on
           "-D__GNUC__", "-D__arm__", "-D__ARM_ARCH_7EM__", "-D__WEAK="]
    cmd += [f"-I{i}" for i in incs]
    if args.misra:
        cmd += ["--addon=misra"]
    rc, out, err, fail = run(cmd, args.timeout, cwd=root)
    os.unlink(listfile)
    if fail:
        return [], "failed", fail
    leads = []
    try:
        xroot = ET.fromstring(err[err.find("<?xml"):] if "<?xml" in err else err)
    except ET.ParseError as ex:
        detail = " ".join((err or out or "").split())[:300]
        return [], "failed", f"cppcheck exit {rc}, no usable XML ({ex}); output: {detail or '(none)'}"
    for e in xroot.iter("error"):
        loc = e.find("location")
        if loc is None:
            continue
        leads.append({"tool": "cppcheck", "rule": e.get("id"), "severity": e.get("severity"),
                      "cwe": e.get("cwe"), "file": rel(root, loc.get("file")), "line": int(loc.get("line", 0)),
                      "message": e.get("msg")})
    return leads, "ran", f"{len(srcs)} files" + (" with MISRA addon" if args.misra else "")


CLANG_TIDY_CHECKS = ("-*,bugprone-*,cert-*,clang-analyzer-*,misc-redundant-expression,misc-misplaced-const,"
                     "-bugprone-easily-swappable-parameters,-bugprone-reserved-identifier,-cert-dcl37-c,-cert-dcl51-cpp,"
                     "-bugprone-assignment-in-if-condition")


def run_clang_tidy(path, root, srcs, incs, args):
    db = find_compile_db(root, args.compile_db)
    if not db:
        return [], "skipped", "no compile_commands.json found. " + compile_db_hint(root)
    try:
        entries = json.load(open(db, encoding="utf-8"))
    except (OSError, ValueError) as ex:
        return [], "failed", f"unreadable compile_commands.json: {ex}"
    fp = {os.path.normcase(os.path.abspath(s)) for s in srcs}
    files = []
    for ent in entries:
        f = ent.get("file", "")
        f = f if os.path.isabs(f) else os.path.join(ent.get("directory", ""), f)
        if os.path.normcase(os.path.abspath(f)) in fp:
            files.append(os.path.abspath(f))
    files = sorted(set(files))
    if not files:
        return [], "skipped", f"compile_commands.json at {rel(root, db)} lists no first-party sources"
    dbdir = os.path.dirname(db)
    rx = re.compile(r"^(.*?):(\d+):(\d+): (warning|error): (.*?) \[([\w.,-]+)\]\s*$")

    def one(f):
        rc, out, err, fail = run([path, "-p", dbdir, f"-checks={CLANG_TIDY_CHECKS}", "--quiet", f], args.timeout)
        return out, fail

    leads, failures = [], 0
    with ThreadPoolExecutor(max_workers=args.jobs) as ex:
        for out, fail in ex.map(one, files):
            if fail:
                failures += 1
                continue
            for line in out.splitlines():
                m = rx.match(line)
                if not m or m.group(6).startswith("clang-diagnostic"):
                    continue  # compiler parse errors (ARM headers etc.) are noise here
                leads.append({"tool": "clang-tidy", "rule": m.group(6), "severity": m.group(4),
                              "file": rel(root, m.group(1)), "line": int(m.group(2)), "message": m.group(5)})
    note = f"{len(files)} files via {rel(root, db)}" + (f"; {failures} file(s) failed/timed out" if failures else "")
    return leads, "ran", note


FLAWFINDER_NOISE = {"char", "wchar_t", "TCHAR"}  # "statically-sized array" — flags every buffer declaration


def run_flawfinder(path, root, srcs, incs, args):
    if not srcs:
        return [], "skipped", "no first-party C/C++ source files"
    targets = sorted({os.path.dirname(s) for s in srcs} | set(incs))
    rc, out, err, fail = run([path, "--csv", "--minlevel=2", "--quiet", "--dataonly"] + targets, args.timeout, cwd=root)
    if fail:
        return [], "failed", fail
    leads, seen = [], set()
    for row in csv.DictReader(io.StringIO(out)):
        key = (row.get("File"), row.get("Line"), row.get("Name"))
        if key in seen or row.get("Name") in FLAWFINDER_NOISE:
            continue
        seen.add(key)
        leads.append({"tool": "flawfinder", "rule": row.get("Name"), "severity": f"level {row.get('Level')}",
                      "cwe": row.get("CWEs"), "file": rel(root, row.get("File", "")),
                      "line": int(row.get("Line") or 0), "message": row.get("Warning")})
    return leads, "ran", f"min level 2 over {len(targets)} dirs"


def run_semgrep(path, root, srcs, incs, args):
    if not os.path.isfile(SEMGREP_RULES):
        return [], "failed", f"bundled rules not found at {SEMGREP_RULES}"
    targets = sorted({os.path.dirname(s) for s in srcs} | set(incs))
    if not targets:
        return [], "skipped", "no first-party C/C++ files"
    env_cmd = [path, "scan", "--config", SEMGREP_RULES, "--metrics=off", "--json", "--quiet",
               "--disable-version-check", "--timeout", "30"] + targets
    rc, out, err, fail = run(env_cmd, args.timeout, cwd=root)
    if fail:
        return [], "failed", fail
    try:
        data = json.loads(out)
    except ValueError:
        return [], "failed", f"semgrep output not JSON (exit {rc}): {err[:300]}"
    leads = []
    for r in data.get("results", []):
        leads.append({"tool": "semgrep", "rule": r.get("check_id", "").split(".")[-1],
                      "severity": r.get("extra", {}).get("severity", "").lower(),
                      "file": rel(root, r.get("path", "")), "line": r.get("start", {}).get("line", 0),
                      "message": r.get("extra", {}).get("message", "").strip()})
    errors = data.get("errors", [])
    fatal = [e for e in errors if e.get("level") == "error"]
    scanned = (data.get("paths") or {}).get("scanned")
    if fatal and not leads and not scanned:
        # The engine died (semgrep reports "the engine was killed" this way); zero leads would be a lie.
        msg = " ".join(str(fatal[0].get("message", "")).split())[:200]
        return [], "failed", f"semgrep engine error, nothing scanned: {msg}"
    return leads, "ran", "bundled embedded-c rules, local only" + (f"; {len(errors)} parse error(s)" if errors else "")


RUNNERS = {"cppcheck": run_cppcheck, "clang-tidy": run_clang_tidy, "flawfinder": run_flawfinder, "semgrep": run_semgrep}


def check(root):
    tools = {}
    for name, t in TOOLS.items():
        p = find_tool(name)
        unavailable = t.get("unavailable", {}).get((OS, ARCH))
        tools[name] = {
            "installed": bool(p), "path": p, "version": tool_version(p) if p else None,
            "purpose": t["purpose"], "size": t["size"],
            "install_commands": [] if unavailable else install_commands(t),
            "install_note": unavailable or t.get("install_note", {}).get(OS),
            "unavailable_on_this_platform": bool(unavailable),
        }
    db = find_compile_db(root)
    return {
        "os": OS, "arch": ARCH, "python": sys.executable,
        "tools": tools,
        "missing": [n for n, v in tools.items() if not v["installed"]],
        "compile_commands_json": rel(root, db) if db else None,
        "compile_db_hint": None if db else compile_db_hint(root),
        "notes": [
            "Ask the user before installing anything. Windows installs via winget/choco may need an "
            "elevated (Administrator) terminal; pip --user installs do not.",
            "After installing on Windows, open a new terminal (or pass the full path) so PATH updates are picked up.",
        ],
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--out-dir")
    ap.add_argument("--tools", help="comma list; default: all installed")
    ap.add_argument("--exclude", action="append", default=[])
    ap.add_argument("--compile-db")
    ap.add_argument("--misra", action="store_true", help="also run cppcheck's MISRA addon (style guidance, noisy)")
    ap.add_argument("--timeout", type=int, default=900, help="per-tool (clang-tidy: per-file) timeout, seconds")
    ap.add_argument("--jobs", type=int, default=max(1, min(8, (os.cpu_count() or 2))))
    args = ap.parse_args()
    root = os.path.abspath(args.root)

    if args.check:
        json.dump(check(root), sys.stdout, indent=2)
        print()
        return

    out_dir = os.path.abspath(args.out_dir or os.path.join(root, "firmware-review"))
    os.makedirs(out_dir, exist_ok=True)
    excludes = DEFAULT_EXCLUDES | {e.strip("/\\").lower() for e in args.exclude}
    srcs, incs = first_party(root, excludes)
    wanted = [t.strip() for t in args.tools.split(",")] if args.tools else list(TOOLS)

    status, all_leads = [], []

    def go(name):
        p = find_tool(name)
        if not p:
            return name, [], "not_available", "not installed: " + " | ".join(TOOLS[name]["install"].get(OS, []))
        leads, st, note = RUNNERS[name](p, root, srcs, incs, args)
        return name, leads, st, f"{tool_version(p)}; {note}"

    with ThreadPoolExecutor(max_workers=len(wanted)) as ex:
        for name, leads, st, note in ex.map(go, wanted):
            status.append({"name": name, "status": st, "notes": note, "leads": len(leads)})
            all_leads.extend(leads)

    # Merge by file:line so the same defect flagged by three tools is read once.
    merged = {}
    for l in all_leads:
        k = (l["file"], l["line"])
        m = merged.setdefault(k, {"file": l["file"], "line": l["line"], "hits": []})
        m["hits"].append({x: l.get(x) for x in ("tool", "rule", "severity", "cwe", "message")})
    ordered = sorted(merged.values(), key=lambda m: (-len({h["tool"] for h in m["hits"]}), m["file"], m["line"]))

    with open(os.path.join(out_dir, "static_leads.json"), "w", encoding="utf-8") as fh:
        json.dump({"tools": status, "first_party_sources": len(srcs), "leads": ordered}, fh, indent=2)
    with open(os.path.join(out_dir, "static_leads.md"), "w", encoding="utf-8") as fh:
        fh.write(f"# Static analysis leads\n\n{len(srcs)} first-party source files. "
                 "**Leads, not findings — read each in context.** Lines flagged by several tools are listed first.\n\n")
        fh.write("| Tool | Status | Leads | Notes |\n|---|---|---|---|\n")
        for s in status:
            fh.write(f"| {s['name']} | {s['status']} | {s['leads']} | {s['notes'].replace('|', '/')} |\n")
        fh.write("\n")
        for m in ordered:
            tools = sorted({h["tool"] for h in m["hits"]})
            fh.write(f"- `{m['file']}:{m['line']}` ({', '.join(tools)})\n")
            for h in m["hits"]:
                cwe = f" CWE-{h['cwe']}" if h.get("cwe") and str(h["cwe"]).isdigit() else (f" {h['cwe']}" if h.get("cwe") else "")
                fh.write(f"  - {h['tool']} `{h['rule']}` [{h['severity']}{cwe}] {h['message']}\n")
    for s in status:
        print(f"{s['name']:<11} {s['status']:<14} {s['leads']:>4} leads  {s['notes'][:140]}")
    print(f"{len(ordered)} merged locations -> {os.path.join(out_dir, 'static_leads.md')}")


if __name__ == "__main__":
    main()
