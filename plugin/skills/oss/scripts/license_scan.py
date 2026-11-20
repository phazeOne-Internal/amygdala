#!/usr/bin/env python3
"""Inventory open-source components and licences in a codebase (MCU firmware, embedded Linux, companion apps).

Usage:
  python license_scan.py <repo-root> --out-dir DIR [--map FILE.map ...] [--scancode-json FILE]
                         [--exclude DIR ...] [--max-file-kb 512]
  python license_scan.py <repo-root> --check          # is ScanCode installed? install command for this OS

Writes to DIR:
  components.json   - one entry per component: path, ecosystem, version, declared licence (manifest),
                      detected licences (file text / SPDX tags / ScanCode), licence files, copyleft files,
                      linked-into-binary evidence, flags
  license_scan.md   - human-readable summary to read before rating risk
Leads, not conclusions: the reviewer confirms each component's licence and how it is distributed.
Unlike the firmware code review, vendored and third-party directories are the main target here.
"""
import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict

if sys.version_info < (3, 8):
    sys.exit("This script needs Python 3.8 or later (any interpreter on PATH is fine); found " + sys.version.split()[0])

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

OS = {"Windows": "windows", "Darwin": "macos"}.get(platform.system(), "linux")
SKIP_DIRS = {".git", ".svn", ".hg", ".idea", ".vscode", "__pycache__", ".gradle", "build", "out", "dist",
             "cmake-build-debug", "cmake-build-release", ".pio", "tmp-glibc", "sstate-cache", "downloads"}
LICENSE_FILE_RX = re.compile(r"^(LICEN[CS]E|COPYING|COPYRIGHT|NOTICE|UNLICENSE|EULA|PATENTS)([._-].*)?$", re.I)
TEXT_EXT = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".s", ".S", ".asm", ".py", ".js", ".mjs", ".cjs", ".ts",
            ".tsx", ".jsx", ".java", ".kt", ".kts", ".swift", ".m", ".mm", ".go", ".rs", ".dart", ".cs", ".rb", ".php",
            ".sh", ".bash", ".pl", ".lua", ".cmake", ".mk", ".mak", ".ld", ".txt", ".md", ".rst", ".bb", ".bbappend",
            ".inc", ".bbclass", ".conf", ".json", ".yml", ".yaml", ".toml", ".xml", ".gradle", ".in", ".dts", ".dtsi",
            ".html", ".css", ".vue", ""}
BINARY_EXT = {".a", ".lib", ".so", ".dll", ".dylib", ".bin", ".hex", ".elf", ".o", ".obj", ".jar", ".aar", ".framework",
              ".xcframework", ".clm_blob", ".fw"}

# Directories whose children are separate third-party components.
COMPONENT_PARENTS = {"mtb_shared", "libs", "deps", "third_party", "thirdparty", "third-party", "vendor", "vendors",
                     "external", "extern", "ext", "components", "managed_components", "modules", "node_modules",
                     "pods", "packages", "middlewares", "lib", "site-packages", "dl", "subprojects"}

# (spdx, family, regex) — family: strong | network | weak | permissive | public-domain | proprietary | restricted | nc
TEXT_RULES = [
    ("AGPL-3.0", "network", r"GNU AFFERO GENERAL PUBLIC LICENSE|GNU Affero General Public License"),
    ("SSPL-1.0", "network", r"Server Side Public License"),
    ("LGPL-3.0", "weak", r"GNU LESSER GENERAL PUBLIC LICENSE\s+Version 3|GNU Lesser General Public License[^.\n]{0,60}version 3"),
    ("LGPL-2.1", "weak", r"GNU LESSER GENERAL PUBLIC LICENSE\s+Version 2\.1|GNU Lesser General Public License[^.\n]{0,60}version 2\.1"),
    ("LGPL-2.0", "weak", r"GNU LIBRARY GENERAL PUBLIC LICENSE|GNU Library General Public License"),
    ("GPL-3.0", "strong", r"GNU GENERAL PUBLIC LICENSE\s+Version 3|GNU General Public License[^.\n]{0,80}version 3"),
    ("GPL-2.0", "strong", r"GNU GENERAL PUBLIC LICENSE\s+Version 2|GNU General Public License[^.\n]{0,80}version 2"),
    ("GPL", "strong", r"under the terms of the GNU General Public License|GNU General Public License as published"),
    ("MPL-2.0", "weak", r"Mozilla Public License,?\s+(v\.\s*|Version\s+)2\.0"),
    ("MPL-1.1", "weak", r"Mozilla Public License,?\s+(v\.\s*|Version\s+)1\.1"),
    ("EPL-2.0", "weak", r"Eclipse Public License\s*[-v]*\s*(v\s*)?2\.0"),
    ("EPL-1.0", "weak", r"Eclipse Public License\s*[-v]*\s*(v\s*)?1\.0"),
    ("CDDL-1.0", "weak", r"COMMON DEVELOPMENT AND DISTRIBUTION LICENSE|Common Development and Distribution License"),
    ("EUPL-1.2", "strong", r"European Union Public Licen[cs]e"),
    ("OSL-3.0", "strong", r"Open Software License\s*(\(\"?OSL\"?\))?\s*v?\.?\s*3\.0"),
    ("CC-BY-SA-4.0", "strong", r"Creative Commons Attribution-ShareAlike|CC BY-SA|CC-BY-SA"),
    ("CC-BY-NC", "nc", r"Creative Commons Attribution-NonCommercial|CC BY-NC|CC-BY-NC|NonCommercial|free for non-?commercial|"
                          r"non-?commercial use only|for non-?commercial (use|purposes)|commercial use requires a (paid |separate )?licen[cs]e|"
                          r"evaluation (purposes )?only"),
    ("Apache-2.0", "permissive", r"Apache License,?\s+Version 2\.0|Licensed under the Apache License"),
    ("MIT", "permissive", r"Permission is hereby granted, free of charge, to any person obtaining a copy"),
    ("BSD-3-Clause", "permissive", r"Redistribution and use in source and binary forms[\s\S]{0,900}Neither the name"),
    ("BSD-2-Clause", "permissive", r"Redistribution and use in source and binary forms"),
    ("ISC", "permissive", r"Permission to use, copy, modify, and(/or)? distribute this software for any\s+purpose with or without fee"),
    ("Zlib", "permissive", r"altered source versions must be plainly marked as such"),
    ("BSL-1.0", "permissive", r"Boost Software License"),
    ("Unlicense", "public-domain", r"This is free and unencumbered software released into the public domain"),
    ("LicenseRef-Cypress-EULA", "restricted", r"CYPRESS END USER LICENSE AGREEMENT|Cypress Software License Agreement|licensed under the Cypress"),
    ("LicenseRef-Infineon-EULA", "restricted", r"Infineon Technologies[^.\n]{0,40}End User License Agreement|INFINEON END USER LICENSE"),
    ("LicenseRef-Permissive-Binary-License", "restricted", r"Permissive Binary License"),
    ("LicenseRef-Nordic-5-Clause", "restricted", r"Nordic-5-Clause|for use with a Nordic Semiconductor ASA integrated circuit"),
    ("LicenseRef-Proprietary", "proprietary", r"\bCONFIDENTIAL\b|\bPROPRIETARY\b|[Dd]o not (re)?distribute|All rights reserved\.?\s*(No part|Unauthori[sz]ed)"),
]
TEXT_RULES = [(s, f, re.compile(r, re.I if s.startswith("LicenseRef") or s in ("CC-BY-NC",) else 0)) for s, f, r in TEXT_RULES]
OR_LATER = re.compile(r"or\s*\(at your option\)\s*any later version", re.I)
EXCEPTIONS = re.compile(r"(GCC Runtime Library Exception|Classpath exception|linking exception|Autoconf exception|"
                        r"Bison exception|eCos exception|FreeRTOS exception|special exception|As a special exception)", re.I)
SPDX_RX = re.compile(r"SPDX-License-Identifier:\s*([A-Za-z0-9.\-+ ()]+?)\s*(?:\*/|-->|$)", re.M)
MODULE_LICENSE_RX = re.compile(r'MODULE_LICENSE\(\s*"([^"]+)"\s*\)')
SNIPPET_RX = re.compile(r"(stackoverflow\.com/(?:questions|q|a)/\d+|stackexchange\.com/(?:questions|a)/\d+|"
                        r"(?:copied|taken|borrowed|lifted|adapted|ported) from\s+\S*(?:https?://|github\.com|gitlab\.com)\S*)", re.I)

FAMILY_OF = {}
for s, f, _ in TEXT_RULES:
    FAMILY_OF[s] = f


def spdx_family(expr):
    """Classify an SPDX expression by its most restrictive term."""
    e = expr.upper()
    if re.search(r"\bUNLICENSED\b|\bCLOSED\b|SEE LICEN[CS]E IN", e):
        return "proprietary" if "SEE LICEN" not in e else "unknown"
    e = re.sub(r"\b[AL]GPL", lambda m: m.group(0)[0] + "_GPL", e)   # keep LGPL/AGPL from matching bare GPL
    order = []
    for key, fam in (("A_GPL", "network"), ("SSPL", "network"), ("L_GPL", "weak"), ("GPL", "strong"), ("EUPL", "strong"),
                     ("OSL", "strong"), ("CC-BY-SA", "strong"), ("-NC", "nc"), ("MPL", "weak"), ("EPL", "weak"), ("CDDL", "weak"),
                     ("LICENSEREF-PROPRIETARY", "proprietary"), ("PROPRIETARY", "proprietary"), ("COMMERCIAL", "proprietary"),
                     ("LICENSEREF", "restricted"), ("APACHE", "permissive"), ("MIT", "permissive"), ("BSD", "permissive"),
                     ("ISC", "permissive"), ("ZLIB", "permissive"), ("BSL", "permissive"), ("UNLICENSE", "public-domain"),
                     ("CC0", "public-domain"), ("PUBLIC DOMAIN", "public-domain"), ("PSF", "permissive"), ("PYTHON", "permissive")):
        hit = re.search(r"(?<![A-Z_])GPL", e) if key == "GPL" else (key in e)
        if hit:
            order.append(fam)
    # "A OR B" lets the distributor choose: report the least restrictive alternative; AND/WITH: most restrictive.
    rank = ["network", "strong", "nc", "proprietary", "weak", "restricted", "permissive", "public-domain"]
    if not order:
        return "unknown"
    if " OR " in e and "WITH" not in e:
        return sorted(order, key=rank.index)[-1]
    return sorted(order, key=rank.index)[0]


def normalise_spdx(raw):
    raw = raw.strip().rstrip("*/ ").strip()
    return re.sub(r"\s+", " ", raw)


def read_text(path, limit):
    try:
        with open(path, "rb") as fh:
            data = fh.read(limit)
    except OSError:
        return None
    if b"\x00" in data[:2048]:
        return None
    return data.decode("utf-8", errors="replace")


def detect_text(text, head_only):
    """Return list of (spdx, family, detail). For source files only the leading comment area is examined."""
    t = text[:6000] if head_only else text
    hits = []
    for m in SPDX_RX.finditer(t):
        expr = normalise_spdx(m.group(1))
        hits.append((expr, spdx_family(expr), "SPDX tag"))
    matched = set()
    for spdx, fam, rx in TEXT_RULES:
        if rx.search(t):
            if spdx == "GPL" and any(s.startswith("GPL-") or s.startswith("LGPL") or s.startswith("AGPL") for s in matched):
                continue
            if spdx == "BSD-2-Clause" and "BSD-3-Clause" in matched:
                continue
            if spdx.startswith("GPL") and any(s.startswith(("LGPL", "AGPL")) for s in matched):
                continue
            matched.add(spdx)
            detail = "licence text"
            s = spdx
            if s.startswith(("GPL", "LGPL", "AGPL")) and OR_LATER.search(t):
                s = s + "-or-later"
            ex = EXCEPTIONS.search(t)
            if ex and fam in ("strong", "weak"):
                detail += f" + exception: {ex.group(1)}"
            hits.append((s, fam, detail))
    return hits


# ------------------------------------------------------------------ manifests

def parse_manifests(root, rel, name, text):
    """Return list of dicts: {name, version, declared, ecosystem, source}."""
    out = []
    low = name.lower()
    try:
        if low == "package.json":
            j = json.loads(text)
            lic = j.get("license")
            if isinstance(lic, dict):
                lic = lic.get("type")
            if not lic and isinstance(j.get("licenses"), list) and j["licenses"]:
                first = j["licenses"][0]
                lic = first.get("type") if isinstance(first, dict) else str(first)
            out.append({"name": j.get("name") or os.path.dirname(rel), "version": j.get("version"), "declared": lic,
                        "ecosystem": "npm", "source": rel, "dependencies": sorted((j.get("dependencies") or {}).keys())})
        elif low.endswith(".mtb"):
            m = re.search(r"github\.com/[^/]+/([^/#]+?)(?:\.git)?#([^#]+)#", text)
            if m:
                out.append({"name": m.group(1), "version": m.group(2), "declared": None, "ecosystem": "modustoolbox", "source": rel})
        elif low == "west.yml":
            for m in re.finditer(r"-\s*name:\s*(\S+)[\s\S]*?revision:\s*(\S+)", text):
                out.append({"name": m.group(1), "version": m.group(2), "declared": None, "ecosystem": "west", "source": rel})
        elif low == "idf_component.yml":
            for m in re.finditer(r"^\s{2,}([\w\-/]+):\s*[\"']?([^\"'\n]+)", text, re.M):
                if m.group(1) not in ("version", "dependencies", "description", "url", "license", "idf"):
                    out.append({"name": m.group(1), "version": m.group(2).strip(), "declared": None, "ecosystem": "esp-idf", "source": rel})
            lm = re.search(r"^license:\s*[\"']?([^\"'\n]+)", text, re.M)
            if lm:
                out.append({"name": os.path.basename(os.path.dirname(os.path.join(root, rel))), "version": None,
                            "declared": lm.group(1).strip(), "ecosystem": "esp-idf", "source": rel})
        elif low == "library.json":
            j = json.loads(text)
            out.append({"name": j.get("name"), "version": j.get("version"), "declared": j.get("license"), "ecosystem": "platformio", "source": rel})
        elif low == "cargo.toml":
            n = re.search(r'^name\s*=\s*"([^"]+)"', text, re.M); v = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
            l = re.search(r'^license\s*=\s*"([^"]+)"', text, re.M)
            out.append({"name": n.group(1) if n else rel, "version": v.group(1) if v else None, "declared": l.group(1) if l else None,
                        "ecosystem": "cargo", "source": rel})
        elif low == "pyproject.toml":
            n = re.search(r'^name\s*=\s*"([^"]+)"', text, re.M); l = re.search(r'^license\s*=\s*(?:\{\s*text\s*=\s*)?"([^"]+)"', text, re.M)
            out.append({"name": n.group(1) if n else rel, "version": None, "declared": l.group(1) if l else None, "ecosystem": "pypi", "source": rel})
        elif low == "metadata" and ".dist-info" in rel:
            n = re.search(r"^Name:\s*(.+)$", text, re.M); v = re.search(r"^Version:\s*(.+)$", text, re.M)
            l = re.search(r"^License-Expression:\s*(.+)$", text, re.M) or re.search(r"^License:\s*(.+)$", text, re.M)
            c = re.findall(r"^Classifier:\s*License :: (.+)$", text, re.M)
            out.append({"name": n.group(1).strip() if n else rel, "version": v.group(1).strip() if v else None,
                        "declared": (l.group(1).strip() if l and l.group(1).strip() not in ("UNKNOWN", "") else "; ".join(c) or None),
                        "ecosystem": "pypi", "source": rel})
        elif low in ("requirements.txt",):
            for line in text.splitlines():
                m = re.match(r"^\s*([A-Za-z0-9_.\-]+)\s*(?:==\s*([\w.\-]+))?", line)
                if m and not line.strip().startswith("#"):
                    out.append({"name": m.group(1), "version": m.group(2), "declared": None, "ecosystem": "pypi", "source": rel})
        elif low == "go.mod":
            for m in re.finditer(r"^\s*([\w.\-]+/[\w.\-/]+)\s+(v[\w.\-+]+)", text, re.M):
                out.append({"name": m.group(1), "version": m.group(2), "declared": None, "ecosystem": "go", "source": rel})
        elif low == "pubspec.lock":
            for m in re.finditer(r"^  ([\w\-]+):\n(?:    .*\n)*?    version: \"([^\"]+)\"", text, re.M):
                out.append({"name": m.group(1), "version": m.group(2), "declared": None, "ecosystem": "pub", "source": rel})
        elif low == "podfile.lock":
            for m in re.finditer(r"^  - ([\w\-+/]+) \(([\w.\-]+)\)", text, re.M):
                out.append({"name": m.group(1), "version": m.group(2), "declared": None, "ecosystem": "cocoapods", "source": rel})
        elif low.startswith("build.gradle"):
            for m in re.finditer(r"(?:implementation|api|compile|runtimeOnly)\s*\(?\s*['\"]([\w.\-]+):([\w.\-]+):([\w.\-]+)['\"]", text):
                out.append({"name": f"{m.group(1)}:{m.group(2)}", "version": m.group(3), "declared": None, "ecosystem": "maven", "source": rel})
        elif low.endswith((".bb", ".bbappend")):
            lic = re.search(r'^LICENSE\s*[?:]?=\s*"([^"]+)"', text, re.M)
            base = os.path.basename(rel)
            nm = re.sub(r"(_[\w.+\-]+)?\.bb(append)?$", "", base)
            ver = re.search(r"_([\w.+\-]+)\.bb", base)
            out.append({"name": nm, "version": ver.group(1) if ver else None, "declared": lic.group(1) if lic else None,
                        "ecosystem": "yocto", "source": rel})
        elif low == "license.manifest":
            for blk in text.split("\n\n"):
                n = re.search(r"PACKAGE NAME:\s*(.+)", blk); v = re.search(r"PACKAGE VERSION:\s*(.+)", blk); l = re.search(r"LICENSE:\s*(.+)", blk)
                if n:
                    out.append({"name": n.group(1).strip(), "version": v.group(1).strip() if v else None,
                                "declared": l.group(1).strip() if l else None, "ecosystem": "yocto-image", "source": rel})
        elif low.endswith(".mk") and "_LICENSE" in text:
            for m in re.finditer(r"^([A-Z0-9_]+)_LICENSE\s*=\s*(.+)$", text, re.M):
                pk = m.group(1); v = re.search(rf"^{pk}_VERSION\s*=\s*(\S+)", text, re.M)
                out.append({"name": pk.lower().replace("_", "-"), "version": v.group(1) if v else None, "declared": m.group(2).strip(),
                            "ecosystem": "buildroot", "source": rel})
        elif low == "manifest.csv" and "legal-info" in rel:
            for line in text.splitlines()[1:]:
                cols = [c.strip('"') for c in line.split(",")]
                if len(cols) >= 3:
                    out.append({"name": cols[0], "version": cols[1], "declared": cols[2], "ecosystem": "buildroot-image", "source": rel})
        elif low == ".gitmodules":
            for m in re.finditer(r"path\s*=\s*(\S+)\s*\n\s*url\s*=\s*(\S+)", text):
                out.append({"name": m.group(1), "version": None, "declared": None, "ecosystem": "git-submodule", "source": rel, "url": m.group(2)})
    except (ValueError, AttributeError, IndexError, TypeError):
        pass
    return out


MANIFEST_NAMES = {"package.json", "west.yml", "idf_component.yml", "library.json", "cargo.toml", "pyproject.toml",
                  "requirements.txt", "go.mod", "pubspec.lock", "podfile.lock", "build.gradle", "build.gradle.kts",
                  "license.manifest", ".gitmodules", "manifest.csv"}


def is_manifest(rel, name):
    low = name.lower()
    return (low in MANIFEST_NAMES or low.endswith((".mtb", ".bb", ".bbappend")) or (low == "metadata" and ".dist-info" in rel)
            or (low.endswith(".mk") and "/package/" in "/" + rel))


# ------------------------------------------------------------------ linker map

def map_objects(map_paths):
    objs = set()
    rx = re.compile(r"([A-Za-z]:)?[\w./\\\-+ ]+\.(?:o|obj|a|lib)\b")
    for mp in map_paths:
        try:
            with open(mp, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    for m in rx.finditer(line):
                        objs.add(m.group(0).strip().replace("\\", "/"))
        except OSError:
            print(f"warning: cannot read map {mp}", file=sys.stderr)
    return objs


# ------------------------------------------------------------------ main

def find_scancode():
    """Find the scancode executable even when a fresh install isn't on PATH yet (pipx, pip --user, Windows)."""
    p = shutil.which("scancode")
    if p:
        return p
    home = os.path.expanduser("~")
    cands = [os.path.join(home, ".local", "bin", "scancode"),
             os.path.join(home, ".local", "pipx", "venvs", "scancode-toolkit", "bin", "scancode"),
             "/opt/homebrew/bin/scancode", "/usr/local/bin/scancode"]
    if OS == "macos":
        import glob
        cands += glob.glob(os.path.join(home, "Library", "Python", "3.*", "bin", "scancode"))
    if OS == "windows":
        import glob
        appdata = os.environ.get("APPDATA", "")
        local = os.environ.get("LOCALAPPDATA", "")
        cands += [os.path.join(home, ".local", "bin", "scancode.exe"),
                  os.path.join(home, "scancode-toolkit", "scancode.bat"),            # release archive, common unpack spots
                  os.path.join(local, "scancode-toolkit", "scancode.bat"), r"C:\scancode-toolkit\scancode.bat",
                  os.path.join(home, "pipx", "venvs", "scancode-toolkit", "Scripts", "scancode.exe"),
                  os.path.join(local, "pipx", "pipx", "venvs", "scancode-toolkit", "Scripts", "scancode.exe")]
        cands += glob.glob(os.path.join(appdata, "Python", "Python3*", "Scripts", "scancode.exe"))
        cands += glob.glob(os.path.join(local, "Programs", "Python", "Python3*", "Scripts", "scancode.exe"))
    for c in cands:
        if c and os.path.isfile(c):
            return c
    return None


def run_scancode(path, root, out_dir, excludes, jobs, timeout):
    out = os.path.join(out_dir, "scancode.json")
    cmd = [path, "--license", "--copyright", "--package", "--info", "--strip-root", "--json-pp", out,
           "-n", str(jobs), "--timeout", "120"]
    for e in sorted(excludes):
        cmd += ["--ignore", f"*/{e}/*", "--ignore", f"{e}/*"]
    cmd.append(root)
    print(f"Running ScanCode (can take a long time on large trees): {' '.join(cmd)}", file=sys.stderr)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return None, f"ScanCode timed out after {timeout}s; re-run with a larger --scancode-timeout or on a subtree"
    except OSError as ex:
        return None, f"ScanCode could not start: {ex}"
    if r.returncode not in (0, 1) or not os.path.isfile(out):   # 1 = completed with some per-file errors
        return None, f"ScanCode failed (exit {r.returncode}): {(r.stderr or r.stdout)[-600:]}"
    return out, f"ScanCode completed (exit {r.returncode}{', some files had errors' if r.returncode == 1 else ''})"


def check():
    p = find_scancode()
    ver = None
    if p:
        try:
            ver = subprocess.run([p, "--version"], capture_output=True, text=True, timeout=180).stdout.strip().splitlines()[0]
        except Exception as ex:  # noqa: BLE001
            ver = f"(version check failed: {ex})"
    install = {
        "macos": ["pipx install scancode-toolkit", "python3 -m pip install --user scancode-toolkit"],
        "linux": ["pipx install scancode-toolkit", "python3 -m pip install --user scancode-toolkit"],
        "windows": ["py -m pip install --user scancode-toolkit"],
    }[OS]
    note = {"windows": "If pip cannot build it for this Python, use the self-contained Windows release archive from "
                       "https://github.com/aboutcode-org/scancode-toolkit/releases."}.get(OS)
    return {"os": OS, "scancode": {"installed": bool(p), "path": p, "version": ver,
            "size": "large (several hundred MB with licence data); first run is slow",
            "install_commands": install, "install_note": note,
            "installer": "python <skill-dir>/scripts/install_scancode.py --yes   (only after the user agrees; --dry-run to preview)"},
            "run_hint": "scancode --license --copyright --package --info --strip-root --json-pp <out>/scancode.json "
                        "--ignore '.git/*' -n 4 <repo>  (on big trees add --max-in-memory 0 and expect tens of minutes)"}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--out-dir")
    ap.add_argument("--map", action="append", default=[], help="linker map file(s) proving what is linked into the binary")
    ap.add_argument("--scancode-json", help="merge an existing ScanCode JSON result")
    ap.add_argument("--run-scancode", action="store_true", help="run ScanCode now (if installed) and merge its results")
    ap.add_argument("--scancode-timeout", type=int, default=7200)
    ap.add_argument("--jobs", type=int, default=max(1, min(8, os.cpu_count() or 2)))
    ap.add_argument("--exclude", action="append", default=[])
    ap.add_argument("--max-file-kb", type=int, default=512)
    args = ap.parse_args()
    root = os.path.abspath(args.root)
    if args.check:
        json.dump(check(), sys.stdout, indent=2)
        print()
        return
    out_dir = os.path.abspath(args.out_dir or os.path.join(root, "license-review"))
    os.makedirs(out_dir, exist_ok=True)
    excl = {e.strip("/\\").lower() for e in args.exclude} | SKIP_DIRS
    out_rel = os.path.relpath(out_dir, root).replace(os.sep, "/") if out_dir.startswith(root) else None
    limit = args.max_file_kb * 1024

    files = []
    for dp, dns, fns in os.walk(root):
        rel_dp = os.path.relpath(dp, root).replace(os.sep, "/")
        dns[:] = [d for d in dns if d.lower() not in excl and not (out_rel and (rel_dp + "/" + d).lstrip("./") == out_rel)]
        for f in fns:
            files.append(os.path.relpath(os.path.join(dp, f), root).replace(os.sep, "/"))

    # 1. component roots: dirs with a licence file or manifest, plus children of known component parents
    roots = set()
    for rel in files:
        parts = rel.split("/")
        name = parts[-1]
        d = "/".join(parts[:-1])
        own_manifest = name.lower() in ("package.json", "library.json", "cargo.toml", "pyproject.toml", "idf_component.yml") \
            or name.lower().endswith((".bb", ".bbappend")) or (name.lower() == "metadata" and ".dist-info" in rel)
        if LICENSE_FILE_RX.match(name) or own_manifest:
            roots.add(d)
        for i, p in enumerate(parts[:-1]):
            if p.lower() in COMPONENT_PARENTS and i + 1 < len(parts) - 1:
                roots.add("/".join(parts[: i + 2]))
                # mtb_shared/<lib>/<version>/ — the version dir is the component
                if p.lower() == "mtb_shared" and i + 2 < len(parts) - 1:
                    roots.add("/".join(parts[: i + 3]))
                break
    roots.discard("")

    def comp_of(rel):
        d = rel.rsplit("/", 1)[0] if "/" in rel else ""
        while d:
            if d in roots:
                return d
            d = d.rsplit("/", 1)[0] if "/" in d else ""
        return ""

    comps = defaultdict(lambda: {"path": None, "detected": Counter(), "families": Counter(), "license_files": [],
                                 "copyleft_files": [], "files": 0, "binaries": [], "manifests": [], "exceptions": set(),
                                 "proprietary_kernel_modules": [], "spdx_tagged": 0})
    snippets = []
    for rel in files:
        c = comp_of(rel)
        e = comps[c]
        e["path"] = c or "."
        e["files"] += 1
        name = rel.rsplit("/", 1)[-1]
        ext = os.path.splitext(name)[1]
        full = os.path.join(root, rel)
        if ext.lower() in BINARY_EXT:
            e["binaries"].append(rel)
            continue
        is_lic = bool(LICENSE_FILE_RX.match(name))
        if not (is_lic or ext in TEXT_EXT or is_manifest(rel, name)):
            continue
        text = read_text(full, limit)
        if text is None:
            continue
        if is_manifest(rel, name):
            e["manifests"].extend(parse_manifests(root, rel, name, text))
        hits = detect_text(text, head_only=not is_lic)
        if is_lic:
            e["license_files"].append({"file": rel, "licenses": sorted({h[0] for h in hits})})
        for spdx, fam, detail in hits:
            e["detected"][spdx] += 1
            e["families"][fam] += 1
            if "SPDX" in detail:
                e["spdx_tagged"] += 1
            if "exception" in detail:
                e["exceptions"].add(detail.split("exception: ", 1)[1])
            if fam in ("strong", "network", "weak", "nc") and not is_lic and len(e["copyleft_files"]) < 25:
                e["copyleft_files"].append({"file": rel, "license": spdx, "detail": detail})
        for m in MODULE_LICENSE_RX.finditer(text):
            if m.group(1) not in ("GPL", "GPL v2", "GPL and additional rights", "Dual BSD/GPL", "Dual MIT/GPL", "Dual MPL/GPL"):
                e["proprietary_kernel_modules"].append({"file": rel, "module_license": m.group(1)})
        for m in SNIPPET_RX.finditer(text):
            if len(snippets) < 60:
                line = text.count("\n", 0, m.start()) + 1
                snippets.append({"file": rel, "line": line, "evidence": m.group(0)[:160], "component": c or "."})

    # 2. ScanCode: run it if asked, then merge per-file detected expressions
    scancode_status = "not requested"
    if args.run_scancode and not args.scancode_json:
        sc_path = find_scancode()
        if not sc_path:
            scancode_status = "not installed (run install_scancode.py --yes after the user agrees)"
        else:
            res, scancode_status = run_scancode(sc_path, root, out_dir, excl | ({out_rel} if out_rel else set()),
                                                args.jobs, args.scancode_timeout)
            if res:
                args.scancode_json = res
    elif args.scancode_json:
        scancode_status = f"merged from {args.scancode_json}"
    if args.scancode_json:
        try:
            sc = json.load(open(args.scancode_json, encoding="utf-8"))
            for f in sc.get("files", []):
                expr = f.get("detected_license_expression_spdx") or f.get("license_expression")
                if not expr or f.get("type") != "file":
                    continue
                rel = f["path"].replace("\\", "/")
                e = comps[comp_of(rel)]
                e["detected"][f"{expr} (scancode)"] += 1
                fam = spdx_family(expr)
                e["families"][fam] += 1
                if fam in ("strong", "network", "weak", "nc") and len(e["copyleft_files"]) < 25 and not LICENSE_FILE_RX.match(rel.rsplit('/', 1)[-1]):
                    e["copyleft_files"].append({"file": rel, "license": expr, "detail": "scancode"})
        except (OSError, ValueError) as ex:
            print(f"warning: cannot read ScanCode JSON: {ex}", file=sys.stderr)

    # 3. linkage evidence
    objs = map_objects(args.map) if args.map else set()

    def linked(path):
        if not objs:
            return "unknown"
        base = path.rstrip("/").lower()
        tail = "/".join(base.split("/")[-2:]) if base not in (".", "") else ""
        for o in objs:
            ol = "/" + o.lower().lstrip("./")
            if tail and f"/{tail}/" in ol:
                return "yes"
        return "no-evidence"

    def file_linked(rel):
        if not objs:
            return "unknown"
        stem = os.path.splitext(rel)[0].lower()
        tail = "/".join(stem.split("/")[-2:])
        return "yes" if any(("/" + o.lower().lstrip("./")).find("/" + tail + ".") >= 0 or
                            ("/" + o.lower().lstrip("./")).find("/" + tail + "_") >= 0 for o in objs) else "no-evidence"

    for e in comps.values():
        for f in e["copyleft_files"]:
            f["linked"] = file_linked(f["file"])

    out = []
    for c, e in sorted(comps.items(), key=lambda kv: kv[0]):
        first_party = c == "" or not any(p.lower() in COMPONENT_PARENTS for p in c.split("/")) and not e["license_files"]
        declared = sorted({m["declared"] for m in e["manifests"] if m.get("declared")
                           and m.get("ecosystem") not in ("yocto-image", "buildroot-image")})
        image = [m for m in e["manifests"] if m.get("ecosystem") in ("yocto-image", "buildroot-image")]
        own = [m for m in e["manifests"] if m.get("name") and os.path.dirname(m["source"]) == c and m not in image
               and m.get("ecosystem") not in ("modustoolbox", "west", "pypi-req", "go", "pub", "cocoapods", "maven", "git-submodule")
               and not m["source"].endswith(("requirements.txt", ".mtb", "west.yml", "go.mod", "pubspec.lock", "Podfile.lock", ".gitmodules"))]
        parts_c = c.split("/") if c else []
        if image:
            cname = f"image manifest ({parts_c[-1] if parts_c else 'root'})"
        elif own:
            cname = own[0]["name"]
        elif len(parts_c) >= 3 and parts_c[-3].lower() == "mtb_shared":
            cname = parts_c[-2]
        elif parts_c:
            cname = parts_c[-1]
        else:
            cname = "(first-party / root)"
        cver = own[0].get("version") if own else (parts_c[-1] if len(parts_c) >= 3 and parts_c[-3].lower() == "mtb_shared" else None)
        fams = set(e["families"])
        for d in declared:
            fams.add(spdx_family(d))
        for m in e["manifests"]:
            if m.get("ecosystem") in ("yocto-image", "buildroot-image") and m.get("declared"):
                fams.add(spdx_family(m["declared"]))
        worst = next((f for f in ["network", "strong", "nc", "proprietary", "weak", "restricted", "unknown", "permissive",
                                   "public-domain"] if f in fams), "none-found")
        out.append({
            "component": cname,
            "path": e["path"], "first_party": bool(first_party),
            "ecosystem": (image[0]["ecosystem"] if image else own[0]["ecosystem"] if own else
                          ("modustoolbox" if "mtb_shared" in parts_c else None)), "version": cver,
            "image_packages": [{"name": m["name"], "version": m.get("version"), "license": m.get("declared")} for m in image],
            "declared_licenses": declared, "detected_licenses": dict(e["detected"].most_common()),
            "most_restrictive_family": worst, "license_exceptions": sorted(e["exceptions"]),
            "license_files": e["license_files"], "copyleft_files": e["copyleft_files"], "spdx_tagged_files": e["spdx_tagged"],
            "files": e["files"], "binaries": e["binaries"][:30], "linked_into_binary": linked(e["path"]),
            "proprietary_kernel_modules": e["proprietary_kernel_modules"],
            "manifest_dependencies": [m for m in e["manifests"] if m is not (own[0] if own else None)][:200],
        })
    inv = {"root": root, "files_scanned": len(files), "map_files": args.map, "scancode": bool(args.scancode_json),
           "scancode_status": scancode_status,
           "components": out, "snippet_provenance": snippets,
           "notes": ["Heuristic: confirm each component's licence from its licence file and how it is built/distributed.",
                     "first_party=true with copyleft files usually means copied-in third-party code: high priority to check.",
                     "linked_into_binary is only 'yes' with a linker map; 'unknown' means no map was provided."]}
    with open(os.path.join(out_dir, "components.json"), "w", encoding="utf-8") as fh:
        json.dump(inv, fh, indent=2, ensure_ascii=False)

    risky = {"network", "strong", "nc", "proprietary", "weak", "restricted", "unknown"}
    with open(os.path.join(out_dir, "license_scan.md"), "w", encoding="utf-8") as fh:
        fh.write(f"# Licence inventory: {root}\n\n{len(files)} files, {len(out)} components. "
                 f"Linker map: {'yes' if objs else 'no'}. ScanCode: {scancode_status}. **Leads, not conclusions.**\n\n")
        fh.write("| Component | Path | Version | Declared | Detected | Most restrictive | Linked | First-party? |\n|---|---|---|---|---|---|---|---|\n")
        for o in sorted(out, key=lambda o: (o["most_restrictive_family"] not in risky, o["path"])):
            det = ", ".join(f"{k}×{v}" for k, v in list(o["detected_licenses"].items())[:4])
            fh.write(f"| {o['component']} | `{o['path']}` | {o['version'] or ''} | {', '.join(o['declared_licenses'])} | {det} | "
                     f"**{o['most_restrictive_family']}** | {o['linked_into_binary']} | {'yes' if o['first_party'] else ''} |\n")
        cf = [(o, f) for o in out for f in o["copyleft_files"] if o["first_party"]]
        if cf:
            fh.write("\n## Copyleft-licensed files inside first-party code (likely copied-in code)\n\n")
            for o, f in cf:
                fh.write(f"- `{f['file']}`: {f['license']} ({f['detail']}); linked: {f.get('linked')}\n")
        tp = [(o, f) for o in out for f in o["copyleft_files"] if not o["first_party"]]
        if tp:
            fh.write("\n## Copyleft files in third-party components (check whether each is built and shipped)\n\n")
            for o, f in tp:
                fh.write(f"- `{f['file']}`: {f['license']} ({f['detail']}); linked: {f.get('linked')}\n")
        im = [o for o in out if o.get("image_packages")]
        for o in im:
            fh.write(f"\n## Image manifest `{o['path']}`: {len(o['image_packages'])} packages\n\n| Package | Version | Licence | Family |\n|---|---|---|---|\n")
            for pkg in o["image_packages"]:
                fh.write(f"| {pkg['name']} | {pkg.get('version') or ''} | {pkg.get('license') or ''} | {spdx_family(pkg.get('license') or '')} |\n")
        pk = [(o, k) for o in out for k in o["proprietary_kernel_modules"]]
        if pk:
            fh.write("\n## Kernel modules declaring a non-GPL licence\n\n")
            for o, k in pk:
                fh.write(f"- `{k['file']}`: MODULE_LICENSE(\"{k['module_license']}\")\n")
        if snippets:
            fh.write("\n## Code provenance comments (snippets copied from the web)\n\n")
            for s in snippets:
                fh.write(f"- `{s['file']}:{s['line']}`: {s['evidence']}\n")
        unk = [o for o in out if o["most_restrictive_family"] in ("unknown", "none-found") and not o["first_party"]]
        if unk:
            fh.write("\n## Third-party components with no licence found\n\n")
            for o in unk:
                fh.write(f"- `{o['path']}` ({o['component']})\n")
        deps = [(o, m) for o in out for m in o["manifest_dependencies"] if not m.get("declared")]
        if deps:
            fh.write(f"\n## Declared dependencies without licence information ({len(deps)}): resolve from the package registry or lockfile\n\n")
            for o, m in deps[:80]:
                fh.write(f"- {m['ecosystem']}: {m['name']} {m.get('version') or ''} (from `{m['source']}`)\n")
    print(f"{len(out)} components, {len(snippets)} provenance comments -> {out_dir}/components.json, license_scan.md")


if __name__ == "__main__":
    main()
