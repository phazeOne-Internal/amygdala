#!/usr/bin/env python3
"""Track fix progress in a firmware:review findings.json. Cross-platform, no dependencies.

  python fix_tracker.py <findings.json> plan
        Ordered work list (Red -> Amber -> Green, then area, then ID) of findings not yet resolved,
        with a suggested fix type for each. JSON to stdout.

  python fix_tracker.py <findings.json> show FW-003
        One finding in full (JSON).

  python fix_tracker.py <findings.json> set FW-003 fixed --note "..." [--commit abc123] [--also FW-004 ...]
        Record a status. Statuses: open, in_progress, fixed, fixed_needs_hw, action_required, deferred, wont_fix.
        wont_fix and deferred require --note (who decided, and why). Keeps a backup findings.json.bak once.

  python fix_tracker.py <findings.json> render
        Re-render report.html / report.md / findings.csv using the firmware:review skill's renderer,
        so the manager's report shows fix progress.

  python fix_tracker.py <findings.json> summary
        Counts by status and RAG, and the list of human actions still outstanding.
"""
import argparse
import datetime
import json
import os
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

STATUSES = ["open", "in_progress", "fixed", "fixed_needs_hw", "action_required", "deferred", "wont_fix"]
RESOLVED = {"fixed", "wont_fix"}
RAG_ORDER = {"red": 0, "amber": 1, "green": 2}
CAT_ORDER = {c: i for i, c in enumerate([
    "memory-safety", "security", "secure-boot-ota", "robustness", "concurrency", "hardware-power",
    "dependencies", "field-readiness", "regulatory", "code-quality"])}

# Heuristic classification — the agent confirms it after reading the finding.
DESIGN_WORDS = ("provision", "per-device", "redesign", "architecture", "add ota", "no ota", "no field firmware update",
                "no way to update", "challenge-response", "secure element", "pairing scheme", "unique credential")
ACTION_WORDS = ("rotate", "revoke", "compromised", "git history", "re-issue", "reissue")
PROCESS_CATS = {"regulatory"}


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def save(path, d):
    bak = path + ".bak"
    if not os.path.exists(bak):
        shutil.copy2(path, bak)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(d, fh, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def status(f):
    return f.get("status") or "open"


def kind(f):
    text = " ".join(str(f.get(k, "")) for k in ("title", "description", "recommendation")).lower()
    if f.get("category") in PROCESS_CATS or not (f.get("location") or {}).get("line") and f.get("category") in ("field-readiness",):
        return "process-or-evidence"
    if any(w in text for w in DESIGN_WORDS) or f.get("effort") == "L":
        return "design-decision"
    if any(w in text for w in ACTION_WORDS):
        return "code-fix+human-action"
    if f.get("confidence") == "needs-verification":
        return "verify-first"
    return "code-fix"


def find_renderer(findings_path):
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "..", "..", "review", "scripts", "render_report.py"),               # sibling skill (firmware plugin)
        os.path.join(here, "..", "..", "firmware-review", "scripts", "render_report.py"),      # sibling skill (standalone copy)
        os.path.join(os.getcwd(), ".claude", "skills", "firmware-review", "scripts", "render_report.py"),
        os.path.join(os.path.expanduser("~"), ".claude", "skills", "firmware-review", "scripts", "render_report.py"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return os.path.abspath(c)
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("findings")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("plan")
    s = sub.add_parser("show"); s.add_argument("id")
    s = sub.add_parser("set")
    s.add_argument("id"); s.add_argument("status", choices=STATUSES)
    s.add_argument("--note", default=""); s.add_argument("--commit", default="")
    s.add_argument("--also", nargs="*", default=[], help="other finding IDs resolved by the same change")
    sub.add_parser("render")
    sub.add_parser("summary")
    args = ap.parse_args()
    path = os.path.abspath(args.findings)
    d = load(path)
    by_id = {f["id"]: f for f in d["findings"]}

    if args.cmd == "plan":
        todo = [f for f in d["findings"] if status(f) not in RESOLVED]
        todo.sort(key=lambda f: (RAG_ORDER.get(f["rag"], 9), CAT_ORDER.get(f["category"], 99), f["id"]))
        out = [{"id": f["id"], "rag": f["rag"], "status": status(f), "suggested_type": kind(f),
                "effort": f.get("effort"), "location": f.get("location"), "title": f["title"]} for f in todo]
        json.dump({"remaining": len(out), "plan": out}, sys.stdout, indent=2, ensure_ascii=False)
        print()
    elif args.cmd == "show":
        f = by_id.get(args.id)
        if not f:
            sys.exit(f"no finding {args.id}")
        json.dump(f, sys.stdout, indent=2, ensure_ascii=False)
        print()
    elif args.cmd == "set":
        ids = [args.id] + args.also
        missing = [i for i in ids if i not in by_id]
        if missing:
            sys.exit(f"unknown finding id(s): {missing}")
        if args.status in ("wont_fix", "deferred") and not args.note:
            sys.exit(f"{args.status} needs --note: who decided, and why")
        today = datetime.date.today().isoformat()
        for i in ids:
            f = by_id[i]
            f["status"] = args.status
            res = f.setdefault("resolution", {})
            note = args.note if i == args.id else (args.note + f" (resolved together with {args.id})").strip()
            if note:
                res["note"] = note
            if args.commit:
                res["commit"] = args.commit
            res["date"] = today
        save(path, d)
        print(f"{', '.join(ids)} -> {args.status}")
    elif args.cmd == "render":
        r = find_renderer(path)
        if not r:
            sys.exit("could not find the review skill's scripts/render_report.py (install the firmware plugin)")
        rc = subprocess.run([sys.executable, r, path, "--out-dir", os.path.dirname(path)]).returncode
        sys.exit(rc)
    elif args.cmd == "summary":
        counts = {}
        for f in d["findings"]:
            counts.setdefault(status(f), {"red": 0, "amber": 0, "green": 0})[f["rag"]] += 1
        actions = [{"id": f["id"], "title": f["title"], "note": (f.get("resolution") or {}).get("note", "")}
                   for f in d["findings"] if status(f) in ("action_required", "fixed_needs_hw")]
        json.dump({"by_status": counts, "outstanding_human_actions": actions}, sys.stdout, indent=2, ensure_ascii=False)
        print()


if __name__ == "__main__":
    main()
