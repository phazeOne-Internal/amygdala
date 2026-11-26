#!/usr/bin/env python3
"""Export the automated leads (static_leads.json, hotspots.json) as SARIF 2.1.0.

    python3 leads_to_sarif.py --root <repo-root> --out leads.sarif [--static static_leads.json] [--hotspots hotspots.json]

SARIF is what GitHub code scanning (upload-sarif), GitLab and the Azure DevOps "SARIF SAST Scans Tab"
extension read, so the leads show up beside the diff and can be dismissed with a reason instead of
living only in a report file.

Leads are not findings. Every result carries the tool that produced it and a rule description that says
so; nobody should treat a SARIF entry from this file as a confirmed defect.

Each result gets a stable fingerprint (partialFingerprints["amygdala/v1"]) built from the rule, the
file and the text of the flagged source line, not its line number, so a lead keeps its identity when
code above it moves. The CI entry point (ci/amygdala_ci.py) uses the same fingerprint for its baseline.

Standard library only; Python 3.8 or later; Windows, macOS and Linux.
"""
import argparse
import hashlib
import json
import os
import re
import sys

if sys.version_info < (3, 8):
    sys.exit("This script needs Python 3.8 or later (any interpreter on PATH is fine); found " + sys.version.split()[0])

TOOL_NAME = "Amygdala"
TOOL_URI = "https://github.com/phazeOne-Internal/amygdala"

# Hotspot rules whose hits are an inventory to read rather than a likely defect.
HOTSPOT_NOTE_RULES = {
    "volatile", "alloc", "infinite-timeout", "busy-delay", "tick-compare", "watchdog", "fault-handler",
    "reset-reason", "version", "todo", "disabled-code", "irq-disable", "flash-write", "memcpy-var-len",
    "strncpy", "isr-blocking", "format-string", "plaintext-proto", "debug-shell",
}
_WS = re.compile(r"\s+")
# A flagged line may hold the very secret that made it a lead. Lines that look like credentials, keys or
# key material have their string literals and byte arrays blanked before they reach any output file.
_SECRETY = re.compile(r"(?i)passw|passwd|pwd|secret|api_?key|token|psk|passkey|pin_code|auth_key|private|certificate|"
                      r"\b\w*(key|iv|nonce)\w*\s*\[|-----BEGIN")
_STRING = re.compile(r'"(?:[^"\\]|\\.){4,}"')
_HEXRUN = re.compile(r"(?:0x[0-9a-fA-F]{1,2}\s*,\s*){4,}(?:0x[0-9a-fA-F]{1,2})?")


def redact(code):
    """Blank string literals and byte-array runs on lines that look like they carry a secret."""
    if not code or not _SECRETY.search(code):
        return code or ""
    code = _STRING.sub('"…"', code)
    return _HEXRUN.sub("…", code)


def plugin_version():
    here = os.path.dirname(os.path.abspath(__file__))
    manifest = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(here))), ".claude-plugin", "plugin.json")
    try:
        with open(manifest, encoding="utf-8") as f:
            return json.load(f).get("version", "0")
    except (OSError, ValueError):
        return "0"


def norm(text):
    return _WS.sub(" ", (text or "")).strip()


class SourceLines:
    """Reads flagged source lines from the repository, one file read per file, tolerant of anything."""

    def __init__(self, root):
        self.root = root
        self.cache = {}

    def line(self, rel, lineno):
        if not self.root or not rel or not lineno:
            return ""
        if rel not in self.cache:
            lines = []
            try:
                with open(os.path.join(self.root, rel), encoding="utf-8", errors="replace") as f:
                    lines = f.read().splitlines()
            except OSError:
                pass
            self.cache[rel] = lines
        lines = self.cache[rel]
        return redact(lines[lineno - 1]) if 0 < lineno <= len(lines) else ""


def fingerprint(kind, rule, rel, code, line=None):
    """Stable identity for a lead: rule + file + normalised source text (falls back to the line number)."""
    body = norm(code) or f"line {line}"
    raw = "|".join([kind, rule or "", (rel or "").replace("\\", "/"), body])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


def level_for(tool, rule, severity):
    sev = (severity or "").lower()
    if tool == "hotspots":
        return "note" if rule in HOTSPOT_NOTE_RULES else "warning"
    if tool == "lizard":
        return "note"
    if tool == "flawfinder":
        m = re.search(r"\d", sev)
        lvl = int(m.group(0)) if m else 0
        return "warning" if lvl >= 3 else "note"
    if sev in ("error", "fatal"):
        return "error"
    if sev in ("warning",):
        return "warning"
    return "note"


def results_from_static(static, src):
    """One SARIF result per tool hit (a merged location with three hits gives three results)."""
    out = []
    for lead in static.get("leads", []):
        rel = lead.get("file", "")
        line = lead.get("line")
        code = src.line(rel, line)
        hits = lead.get("hits", [])
        for h in hits:
            tool = h.get("tool", "static")
            rule = h.get("rule") or "unknown"
            out.append({
                "tool": tool, "rule": rule, "rule_desc": h.get("message") or rule,
                "category": None, "cwe": h.get("cwe"),
                "level": level_for(tool, rule, h.get("severity")),
                "message": (h.get("message") or rule) + (f" (also flagged by {len(hits) - 1} other tool(s) at this line)" if len(hits) > 1 else ""),
                "file": rel, "line": line, "code": code,
                "fingerprint": fingerprint("static", f"{tool}/{rule}", rel, code, line),
                "merged_tools": sorted({x.get("tool", "") for x in hits}),
            })
    return out


def results_from_hotspots(hot, src):
    out = []
    for rule, info in hot.get("hits", {}).items():
        for s in info.get("samples", []):
            rel = s.get("file", "")
            line = s.get("line")
            code = redact(s.get("code")) or src.line(rel, line)
            out.append({
                "tool": "hotspots", "rule": rule, "rule_desc": info.get("description") or rule,
                "category": info.get("category"), "cwe": None,
                "level": level_for("hotspots", rule, None),
                "message": info.get("description") or rule,
                "file": rel, "line": line, "code": code,
                "fingerprint": fingerprint("hotspot", rule, rel, code, line),
                "merged_tools": ["hotspots"],
            })
    return out


def to_sarif(results, root_note=""):
    rules, rule_index = [], {}
    sarif_results = []
    for r in results:
        rid = f"{r['tool']}/{r['rule']}"
        if rid not in rule_index:
            rule_index[rid] = len(rules)
            tags = [t for t in ("lead", r["tool"], r.get("category")) if t]
            cwe_digits = re.sub(r"\D", "", str(r.get("cwe") or ""))
            if cwe_digits:
                tags.append(f"external/cwe/cwe-{cwe_digits}")
            rules.append({
                "id": rid, "name": r["rule"],
                "shortDescription": {"text": r["rule_desc"][:200]},
                "fullDescription": {"text": f"Lead from {r['tool']}: {r['rule_desc']} Unverified: read the code in context before treating it as a defect."},
                "defaultConfiguration": {"level": r["level"]},
                "properties": {"tags": tags},
            })
        res = {
            "ruleId": rid, "ruleIndex": rule_index[rid], "level": r["level"],
            "message": {"text": r["message"]},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": (r["file"] or "").replace("\\", "/"), "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": int(r["line"]) if r.get("line") else 1},
            }}],
            "partialFingerprints": {"amygdala/v1": r["fingerprint"]},
            "properties": {"tool": r["tool"], "also_flagged_by": [t for t in r.get("merged_tools", []) if t != r["tool"]]},
        }
        if r.get("category"):
            res["properties"]["category"] = r["category"]
        sarif_results.append(res)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": TOOL_NAME, "version": plugin_version(), "informationUri": TOOL_URI,
                "rules": rules,
            }},
            "automationDetails": {"id": "amygdala/leads"},
            "results": sarif_results,
            "properties": {"note": "Automated leads from pattern scanning, static analysers and metrics; not reviewed. " + root_note},
        }],
    }


def load(path):
    if not path:
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main():
    ap = argparse.ArgumentParser(description="Export static_leads.json and hotspots.json as SARIF 2.1.0 (leads, not findings).")
    ap.add_argument("--root", help="repository root the lead paths are relative to (used to read the flagged lines)")
    ap.add_argument("--static", help="static_leads.json from run_static_tools.py")
    ap.add_argument("--hotspots", help="hotspots.json from hotspots.py --json")
    ap.add_argument("--out", required=True, help="SARIF file to write (UTF-8)")
    args = ap.parse_args()
    if not args.static and not args.hotspots:
        ap.error("give --static and/or --hotspots")
    src = SourceLines(args.root)
    results = []
    try:
        if args.static:
            results += results_from_static(load(args.static), src)
        if args.hotspots:
            results += results_from_hotspots(load(args.hotspots), src)
    except (OSError, ValueError) as ex:
        sys.exit(f"could not read input: {ex}")
    results.sort(key=lambda r: (r["file"], r.get("line") or 0, r["tool"], r["rule"]))
    doc = to_sarif(results)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1)
    print(f"{len(results)} result(s), {len(doc['runs'][0]['tool']['driver']['rules'])} rule(s) -> {args.out}")


if __name__ == "__main__":
    main()
