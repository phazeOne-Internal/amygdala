#!/usr/bin/env python3
"""Install ScanCode Toolkit for the current user, on Windows, macOS or Linux.

  python install_scancode.py --dry-run     # show what would be run, install nothing
  python install_scancode.py --yes         # install (only after the user has agreed)

Method, in order of preference:
  1. pipx install scancode-toolkit          (isolated; recommended)
  2. <python> -m pip install --user scancode-toolkit
No admin rights are needed for either. Prints JSON with the result and the path of the
installed `scancode` executable (which may not be on PATH until a new terminal is opened).
"""
import argparse
import json
import os
import platform
import shutil
import subprocess
import sys

if sys.version_info < (3, 8):
    sys.exit("This script needs Python 3.8 or later (any interpreter on PATH is fine); found " + sys.version.split()[0])

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from license_scan import find_scancode  # noqa: E402

PKG = "scancode-toolkit"
SUPPORTED = ("3.12", "3.11", "3.13", "3.10")   # preferred order; the newest Pythons are often not yet supported
# Known breakage: pluggy >= 1.6 makes ScanCode 32.x fail at start-up ("did not find any 'pre_scan' hooks").
PLUGGY_PIN = "pluggy==1.5.0"
RELEASES = "https://github.com/aboutcode-org/scancode-toolkit/releases"


def base_python():
    """A Python that is not a virtualenv or a tool's private interpreter (PlatformIO, ModusToolbox, ESP-IDF...).
    pip --user is refused inside venvs, and installing into a toolchain's Python could break that toolchain."""
    def tool_owned(path):
        low = path.lower()
        return any(t in low for t in (".platformio", "penv", "venv", ".pio", "modustoolbox", "zephyr-sdk", "espressif",
                                      "windowsapps"))   # WindowsApps = Microsoft Store alias stub, not a real Python

    if sys.prefix == sys.base_prefix and not tool_owned(sys.executable):
        return sys.executable
    if not tool_owned(sys.base_prefix):
        for n in (["python.exe"] if os.name == "nt" else ["bin/python3", "bin/python"]):
            c = os.path.join(sys.base_prefix, n)
            if os.path.isfile(c):
                return c
    for n in (["py"] if os.name == "nt" else []) + ["python3", "python"]:
        w = shutil.which(n)
        if w and not tool_owned(w):
            return w
    for c in ("/opt/homebrew/bin/python3", "/usr/local/bin/python3", "/usr/bin/python3"):
        if os.path.isfile(c):
            return c
    return None


def supported_python():
    """Path of an installed Python in a version ScanCode supports, or None."""
    cands = []
    # The interpreter running this script is the natural first choice when its version is supported;
    # otherwise pipx may silently pick its own (possibly newer, unsupported) Python.
    running = "%d.%d" % sys.version_info[:2]
    if running in SUPPORTED and sys.prefix == sys.base_prefix:
        cands.append(sys.executable)
    for v in SUPPORTED:
        cands += [shutil.which(f"python{v}"), f"/opt/homebrew/opt/python@{v}/bin/python{v}", f"/usr/local/opt/python@{v}/bin/python{v}",
                  f"/usr/bin/python{v}"]
        if os.name == "nt" and shutil.which("py"):
            try:
                r = subprocess.run(["py", f"-{v}", "-c", "import sys;print(sys.executable)"], capture_output=True, text=True, timeout=30)
                if r.returncode == 0:
                    cands.append(r.stdout.strip())
            except Exception:  # noqa: BLE001
                pass
    for c in cands:
        if c and os.path.isfile(c) and not any(t in c.lower() for t in (".platformio", "penv", "windowsapps", "venv")):
            return c
    return None


def scancode_works(path):
    try:
        r = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=900)
    except Exception as ex:  # noqa: BLE001
        return False, str(ex)
    out = (r.stdout + r.stderr)
    return (r.returncode == 0 and "ScanCode version" in out), out.strip()[-600:]


def plan():
    """List of (method, [commands]) to try in order; each method may need several commands."""
    pipx = shutil.which("pipx")
    steps = []
    sp = supported_python()
    pyarg = ["--python", sp] if sp else []
    if pipx:
        steps.append(("pipx", [[pipx, "install", *pyarg, PKG], [pipx, "runpip", PKG, "install", PLUGGY_PIN]]))
    elif platform.system() == "Darwin" and shutil.which("brew"):
        steps.append(("brew pipx + pipx", [["brew", "install", "pipx"], ["pipx", "install", *pyarg, PKG],
                                           ["pipx", "runpip", PKG, "install", PLUGGY_PIN]]))
    py = sp or base_python()
    if py:
        cmd = [py, "-3", "-m", "pip"] if os.path.basename(py).lower() == "py" else [py, "-m", "pip"]
        steps.append(("pip --user", [cmd + ["install", "--user", "--upgrade", PKG]]))
    return steps


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--yes", action="store_true", help="the user has agreed to install ScanCode")
    g.add_argument("--dry-run", action="store_true")
    ap.add_argument("--timeout", type=int, default=1800)
    args = ap.parse_args()

    existing = find_scancode()
    if existing:
        works, out = scancode_works(existing)
        if works:
            print(json.dumps({"status": "already_installed", "path": existing, "version": [l for l in out.splitlines() if "version" in l.lower() and "warn" not in l.lower()]}, indent=2))
            return
        # Installed but broken: the usual cause is the pluggy incompatibility; repair it if pipx manages ScanCode.
        pipx = shutil.which("pipx")
        repair = [pipx, "runpip", PKG, "install", PLUGGY_PIN] if pipx else None
        if args.dry_run or not repair:
            print(json.dumps({"status": "installed_but_broken", "path": existing, "error": out,
                              "repair": " ".join(repair) if repair else
                              f"reinstall with a Python in {SUPPORTED} and `pip install {PLUGGY_PIN}` in ScanCode's environment"}, indent=2))
            return
        subprocess.run(repair, capture_output=True, text=True, timeout=args.timeout)
        works, out = scancode_works(existing)
        print(json.dumps({"status": "repaired" if works else "installed_but_broken", "path": existing, "detail": out}, indent=2))
        if not works:
            sys.exit(1)
        return
    steps = plan()
    info = {"os": platform.system(), "python": sys.version.split()[0],
            "planned": [{"method": m, "commands": [" ".join(c) for c in cmds]} for m, cmds in steps],
            "in_virtualenv": sys.prefix != sys.base_prefix,
            "scancode_python": supported_python() or "none of " + ", ".join(SUPPORTED) + " found; using default",
            "note": "ScanCode supports recent 64-bit Python 3 releases. If pip can't find a matching build for this Python, "
                    f"use the self-contained release archive for this OS from {RELEASES}."}
    if args.dry_run:
        print(json.dumps({"status": "dry_run", **info}, indent=2))
        return

    attempts = []
    for name, cmds in steps:
        ok = True
        for cmd in cmds:
            if cmd[0] == "pipx" and not shutil.which("pipx"):
                cand = shutil.which("pipx") or "/opt/homebrew/bin/pipx"
                cmd = [cand] + cmd[1:]
            print(f"Running: {' '.join(cmd)}  (this can take several minutes)", file=sys.stderr)
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=args.timeout, encoding="utf-8", errors="replace")
                ok = r.returncode == 0
                attempts.append({"method": name, "command": " ".join(cmd), "ok": ok, "tail": (r.stdout + r.stderr)[-1200:]})
            except (OSError, subprocess.TimeoutExpired) as ex:
                attempts.append({"method": name, "command": " ".join(cmd), "ok": False, "tail": str(ex)})
                ok = False
            if not ok:
                break
        if ok:
            path = find_scancode()
            if path:
                # First run unpacks licence data (slow); this also proves the install actually works.
                works, out = scancode_works(path)
                if works:
                    print(json.dumps({"status": "installed", "method": name, "path": path,
                                      "version": [l for l in out.splitlines() if "version" in l.lower() and "warn" not in l.lower()],
                                      "on_path": bool(shutil.which("scancode")),
                                      "hint": None if shutil.which("scancode") else
                                      "Installed but not on PATH in this shell. The skill finds it anyway; "
                                      "open a new terminal (or run `pipx ensurepath`) to use `scancode` directly.",
                                      "attempts": attempts}, indent=2))
                    return
                attempts.append({"method": name, "command": f"{path} --version", "ok": False, "tail": out})
    print(json.dumps({"status": "failed", **info, "attempts": attempts,
                      "next": f"Install manually from {RELEASES} (self-contained archive), then re-run the skill. "
                              "The review can continue with the bundled scanner meanwhile."}, indent=2))
    sys.exit(1)


if __name__ == "__main__":
    main()
