"""Install the optional analysers the way the skills tell users to, then prove they are found.

Used by CI only. It never installs anything on a developer's machine unless run by hand.

    python ci/install_tools.py static cppcheck flawfinder semgrep
    python ci/install_tools.py scancode

`static` reads the install commands for this operating system from
`run_static_tools.py --check` (so the advice the skill gives users is what gets tested), runs them
in order until the tool is detected, and fails if any requested tool is still missing afterwards.
`scancode` runs `install_scancode.py --yes` and then `license_scan.py --check`.
"""
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # repository root; this file lives in ci/
REVIEW = os.path.join(ROOT, "plugin", "skills", "review", "scripts")
OSS = os.path.join(ROOT, "plugin", "skills", "oss", "scripts")
ENV = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")


def script_json(script, *args):
    cp = subprocess.run([sys.executable, script, *args], capture_output=True, text=True,
                        encoding="utf-8", errors="replace", env=ENV, timeout=1800)
    if cp.returncode != 0 and not cp.stdout.strip().startswith("{"):
        sys.exit("%s failed (%d):\n%s\n%s" % (os.path.basename(script), cp.returncode, cp.stdout, cp.stderr))
    return json.loads(cp.stdout), cp


def shell(cmd):
    print("$ " + cmd, flush=True)
    cp = subprocess.run(cmd, shell=True, text=True, encoding="utf-8", errors="replace", env=ENV, timeout=1500)
    print("  -> exit %d" % cp.returncode, flush=True)
    return cp.returncode == 0


def static(tools):
    check, _ = script_json(os.path.join(REVIEW, "run_static_tools.py"), ROOT, "--check")
    print("os: %s  python: %s" % (check["os"], check["python"]))
    for tool in tools:
        info = check["tools"][tool]
        if info["installed"]:
            print("%s: already installed at %s" % (tool, info["path"]))
            continue
        if info.get("install_note"):
            print("%s: note from the skill: %s" % (tool, info["install_note"]))
        for cmd in info["install_commands"]:
            if shell(cmd):
                fresh, _ = script_json(os.path.join(REVIEW, "run_static_tools.py"), ROOT, "--check")
                if fresh["tools"][tool]["installed"]:
                    print("%s: installed via `%s`, found at %s" % (tool, cmd, fresh["tools"][tool]["path"]))
                    break
                print("%s: `%s` succeeded but the skill cannot find the tool afterwards" % (tool, cmd))
        else:
            print("%s: no install command worked" % tool)
    final, _ = script_json(os.path.join(REVIEW, "run_static_tools.py"), ROOT, "--check")
    missing = [t for t in tools if not final["tools"][t]["installed"]]
    print(json.dumps({t: {"installed": v["installed"], "path": v["path"], "version": v["version"]}
                      for t, v in final["tools"].items()}, indent=2))
    if missing:
        sys.exit("still missing after following the skill's install advice: " + ", ".join(missing))


def scancode():
    result, cp = script_json(os.path.join(OSS, "install_scancode.py"), "--yes")
    print(cp.stderr)
    print(json.dumps({k: v for k, v in result.items() if k != "attempts"}, indent=2))
    for a in result.get("attempts", []):
        print("attempt %s: %s -> %s" % (a["method"], a["command"], "ok" if a["ok"] else "failed"))
        if not a["ok"]:
            print(a["tail"])
    if result["status"] not in ("installed", "already_installed", "repaired"):
        sys.exit("ScanCode install failed: " + result["status"])
    check, _ = script_json(os.path.join(OSS, "license_scan.py"), ROOT, "--check")
    print(json.dumps(check["scancode"], indent=2))
    if not check["scancode"]["installed"]:
        sys.exit("install_scancode.py reported success but license_scan.py --check cannot find scancode")


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "static":
        static(sys.argv[2:])
    elif len(sys.argv) == 2 and sys.argv[1] == "scancode":
        scancode()
    else:
        sys.exit(__doc__)
