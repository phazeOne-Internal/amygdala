#!/usr/bin/env python3
"""Render a firmware review findings.json into report.html, report.md and findings.csv.

Usage: render_report.py <findings.json> [--out-dir DIR]

Validates the JSON first; exits 1 with a list of problems if it is invalid.
"""
import argparse
import csv
import html
import json
import os
import sys

for _s in (sys.stdout, sys.stderr):  # Windows consoles default to cp1252; code snippets may not be ASCII
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

CATEGORIES = [
    ("memory-safety", "Memory safety"),
    ("security", "Security"),
    ("secure-boot-ota", "Secure boot & OTA"),
    ("robustness", "Robustness & recovery"),
    ("concurrency", "Concurrency & real-time"),
    ("hardware-power", "Hardware, storage & power"),
    ("dependencies", "Third-party dependencies"),
    ("field-readiness", "Field readiness & diagnostics"),
    ("regulatory", "Regulatory compliance"),
    ("code-quality", "Code quality & style"),
]
CAT_LABEL = dict(CATEGORIES)
CAT_ORDER = {c: i for i, (c, _) in enumerate(CATEGORIES)}
RAGS = ["red", "amber", "green"]
RAG_ORDER = {r: i for i, r in enumerate(RAGS)}
RAG_LABEL = {"red": "RED", "amber": "AMBER", "green": "GREEN", "grey": "NOT ASSESSED", "partial": "PARTIAL"}
RAG_EMOJI = {"red": "🔴", "amber": "🟠", "green": "🟢", "grey": "⚪", "partial": "🟡"}
RAG_MEANING = {
    "red": "Must fix before release / ASAP",
    "amber": "Fix before release, or EM formally accepts risk",
    "green": "Improve when convenient",
}
# Report profile. Defaults are the firmware review; another skill (e.g. a licence review) can override
# them with an optional "report" object in findings.json: title, categories, verdict, rag_meaning, legend, disclaimer.
TITLE = "Firmware review"
VERDICTS = {
    "red": "NOT READY FOR FIELD RELEASE",
    "amber": "CONDITIONAL — RESOLVE OR ACCEPT AMBER ITEMS",
    "green": "READY, SUBJECT TO STATED COVERAGE",
}
LEGEND = {
    "red": "Must fix before release / ASAP — exploitable, bricks or locks up devices, loses data, safety impact, or blocks market access.",
    "amber": "Fix before release, or the engineering manager formally accepts the risk with a target date — plausible field failure, defence-in-depth gap, or undiagnosable failure mode.",
    "green": "Improve when convenient — maintainability, style, low-risk hardening.",
}
DISCLAIMER = ("This is a static review of source code. It does not replace on-target testing, fuzzing or penetration testing. "
              "Regulatory mappings are engineering guidance, not legal advice; confirm applicability with your compliance owner.")


def apply_profile(d):
    global TITLE, DISCLAIMER, CATEGORIES, CAT_LABEL, CAT_ORDER
    prof = d.get("report") or {}
    TITLE = prof.get("title", TITLE)
    DISCLAIMER = prof.get("disclaimer", DISCLAIMER)
    VERDICTS.update(prof.get("verdict", {}))
    LEGEND.update(prof.get("legend", {}))
    RAG_MEANING.update(prof.get("rag_meaning", {}))
    if prof.get("categories"):
        CATEGORIES = [tuple(c) for c in prof["categories"]]
        CAT_LABEL = dict(CATEGORIES)
        CAT_ORDER = {c: i for i, (c, _) in enumerate(CATEGORIES)}


CONFIDENCES = {"confirmed", "likely", "needs-verification"}
# Fix-tracking status (set by the firmware-fix skill). Absent means "open".
STATUSES = {
    "open": "Open", "in_progress": "In progress", "fixed": "Fixed",
    "fixed_needs_hw": "Fixed in code, needs hardware test", "action_required": "Code fixed, human action required",
    "deferred": "Deferred", "wont_fix": "Won't fix (risk accepted)",
}
RESOLVED = {"fixed", "wont_fix"}   # everything else still counts towards the verdict


def status_of(f):
    return f.get("status") or "open"


def is_open(f):
    return status_of(f) not in RESOLVED
EFFORTS = {"S", "M", "L"}
COVERAGE = {"reviewed", "partial", "not_reviewed"}
TOOL_STATUS = {"ran", "not_available", "failed", "skipped"}


def validate(d):
    errs, warns = [], []
    if not isinstance(d, dict):
        return ["top level must be an object"], warns
    for k in ("project", "summary", "findings", "coverage"):
        if k not in d:
            errs.append(f"missing top-level key '{k}'")
    p = d.get("project", {})
    for k in ("name", "review_date"):
        if not p.get(k):
            errs.append(f"project.{k} is required")
    ids = set()
    for i, f in enumerate(d.get("findings", [])):
        where = f"findings[{i}] ({f.get('id', '?')})"
        for k in ("id", "title", "rag", "category", "confidence", "location", "description", "impact", "recommendation"):
            if k not in f or f[k] in (None, "") and k != "location":
                errs.append(f"{where}: missing '{k}'")
        if f.get("id") in ids:
            errs.append(f"{where}: duplicate id")
        ids.add(f.get("id"))
        if f.get("rag") not in RAGS:
            errs.append(f"{where}: rag must be one of {RAGS}")
        if f.get("category") not in CAT_LABEL:
            errs.append(f"{where}: category '{f.get('category')}' not in {list(CAT_LABEL)}")
        if f.get("confidence") not in CONFIDENCES:
            errs.append(f"{where}: confidence must be one of {sorted(CONFIDENCES)}")
        if f.get("effort") and f["effort"] not in EFFORTS:
            errs.append(f"{where}: effort must be S, M or L")
        loc = f.get("location")
        if not isinstance(loc, dict) or "file" not in loc:
            errs.append(f"{where}: location must be an object with 'file' (and 'line' int or null)")
        elif loc.get("line") is not None and not isinstance(loc.get("line"), int):
            errs.append(f"{where}: location.line must be an integer or null")
        if f.get("status") and f["status"] not in STATUSES:
            errs.append(f"{where}: status must be one of {sorted(STATUSES)}")
        if f.get("status") == "wont_fix" and not (f.get("resolution") or {}).get("note"):
            errs.append(f"{where}: status wont_fix needs resolution.note explaining who accepted the risk and why")
        if f.get("rag") == "red" and f.get("confidence") == "needs-verification":
            warns.append(f"{where}: Red finding with confidence 'needs-verification' — consider Amber, or verify it")
    seen_areas = set()
    for i, c in enumerate(d.get("coverage", [])):
        if c.get("area") not in CAT_LABEL:
            errs.append(f"coverage[{i}]: area '{c.get('area')}' not a valid category")
        if c.get("status") not in COVERAGE:
            errs.append(f"coverage[{i}]: status must be one of {sorted(COVERAGE)}")
        seen_areas.add(c.get("area"))
    missing = [c for c in CAT_LABEL if c not in seen_areas]
    if missing:
        warns.append(f"coverage missing areas {missing} — they will show as 'Not assessed'")
    for i, t in enumerate(d.get("tools", [])):
        if t.get("status") not in TOOL_STATUS:
            errs.append(f"tools[{i}]: status must be one of {sorted(TOOL_STATUS)}")
    return errs, warns


def loc_str(loc):
    if not loc or not loc.get("file"):
        return "—"
    return f"{loc['file']}:{loc['line']}" if loc.get("line") else loc["file"]


def compute(d):
    findings = sorted(d["findings"], key=lambda f: (RAG_ORDER[f["rag"]], CAT_ORDER[f["category"]], f["id"]))
    counts = {r: sum(1 for f in findings if f["rag"] == r and is_open(f)) for r in RAGS}
    tracking = any(f.get("status") for f in findings)
    if counts["red"]:
        verdict = ("red", VERDICTS["red"],
                   f"{counts['red']} Red issue(s) must be fixed before this firmware ships.")
    elif counts["amber"]:
        verdict = ("amber", VERDICTS["amber"],
                   f"No Red issues. {counts['amber']} Amber issue(s) need fixing or formal risk acceptance before release.")
    else:
        verdict = ("green", VERDICTS["green"],
                   "No open Red or Amber issues in the areas reviewed." if tracking else
                   "No Red or Amber issues found in the areas reviewed.")
    if tracking:
        done = sum(1 for f in findings if not is_open(f))
        verdict = (verdict[0], verdict[1], verdict[2] + f" Fix progress: {done} of {len(findings)} findings resolved; "
                   "counts and ratings below reflect open items only.")
    cov = {c["area"]: c for c in d.get("coverage", [])}
    score = []
    for cat, label in CATEGORIES:
        fs = [f for f in findings if f["category"] == cat and is_open(f)]
        c = {r: sum(1 for f in fs if f["rag"] == r) for r in RAGS}
        status = cov.get(cat, {}).get("status", "not_reviewed")
        if fs:
            rating = next(r for r in RAGS if c[r])
        elif status == "reviewed":
            rating = "green"
        elif status == "partial":
            rating = "partial"
        else:
            rating = "grey"
        score.append({"cat": cat, "label": label, "rating": rating, "counts": c, "status": status,
                      "notes": cov.get(cat, {}).get("notes", "")})
    return findings, counts, verdict, score


# ---------------------------------------------------------------- HTML

CSS = """
:root{--red:#c62828;--red-bg:#fdecea;--amber:#b45f00;--amber-solid:#f39c12;--amber-bg:#fff4e0;--green:#2e7d32;--green-bg:#e8f5e9;
--grey:#6b7280;--grey-bg:#f3f4f6;--ink:#1f2937;--muted:#6b7280;--line:#e5e7eb;--card:#fff;--bg:#f8fafc}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:var(--ink);background:var(--bg)}
.wrap{max-width:1180px;margin:0 auto;padding:28px 24px 60px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:34px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--line)}
.meta{color:var(--muted);font-size:13.5px}.meta b{color:var(--ink);font-weight:600}
.verdict{margin:20px 0;border-radius:10px;padding:18px 22px;color:#fff;display:flex;gap:18px;align-items:center}
.verdict.red{background:var(--red)}.verdict.amber{background:var(--amber-solid);color:#2b1a00}.verdict.green{background:var(--green)}
.verdict .big{font-size:22px;font-weight:700;letter-spacing:.3px}.verdict .sub{opacity:.95}
.tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;border-top:5px solid var(--grey)}
.tile.red{border-top-color:var(--red)}.tile.amber{border-top-color:var(--amber-solid)}.tile.green{border-top-color:var(--green)}
.tile .n{font-size:32px;font-weight:700;line-height:1.1}.tile .l{font-weight:600}.tile .d{color:var(--muted);font-size:13px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 20px}
table{border-collapse:collapse;width:100%;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top;font-size:14px}
th{background:#f1f5f9;font-weight:600;font-size:13px;color:#374151}tr:last-child td{border-bottom:none}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:700;letter-spacing:.4px;white-space:nowrap}
.badge.red{background:var(--red);color:#fff}.badge.amber{background:var(--amber-solid);color:#2b1a00}.badge.green{background:var(--green);color:#fff}
.badge.grey{background:var(--grey-bg);color:var(--grey);border:1px solid #d1d5db}.badge.partial{background:#fff;color:var(--amber);border:1.5px solid var(--amber-solid)}
.chip{display:inline-block;padding:1px 8px;border-radius:6px;background:var(--grey-bg);font-size:12px;color:#374151;margin:0 4px 4px 0}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.8px}
pre{background:#0f172a;color:#e2e8f0;padding:12px 14px;border-radius:8px;overflow:auto;white-space:pre}
.loc{font-family:ui-monospace,Menlo,monospace;font-size:12.8px;color:#334155}
.counts span{display:inline-block;min-width:26px;text-align:center;border-radius:5px;font-size:12px;font-weight:700;margin-right:3px;padding:1px 4px}
.c-red{background:var(--red-bg);color:var(--red)}.c-amber{background:var(--amber-bg);color:var(--amber)}.c-green{background:var(--green-bg);color:var(--green)}.c-zero{color:#cbd5e1}
.filters{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 14px;align-items:center}
.filters button{border:1px solid var(--line);background:#fff;border-radius:999px;padding:5px 13px;cursor:pointer;font-size:13px}
.filters button.on{background:var(--ink);color:#fff;border-color:var(--ink)}.filters select{padding:5px 8px;border-radius:8px;border:1px solid var(--line)}
details.f{background:var(--card);border:1px solid var(--line);border-left:6px solid var(--grey);border-radius:8px;margin-bottom:10px}
details.f.red{border-left-color:var(--red)}details.f.amber{border-left-color:var(--amber-solid)}details.f.green{border-left-color:var(--green)}
details.f summary{cursor:pointer;padding:12px 16px;display:flex;gap:10px;align-items:baseline;flex-wrap:wrap;list-style:none}
details.f summary::-webkit-details-marker{display:none}
details.f summary .id{font-weight:700;color:#475569;font-size:13px}details.f summary .t{font-weight:600;flex:1 1 420px}
details.f .body{padding:0 18px 14px}.body h4{margin:12px 0 4px;font-size:13px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted)}
.body p{margin:0 0 6px}ul{margin:6px 0 6px 20px;padding:0}
.st-fixed{background:var(--green-bg);color:var(--green);font-weight:600}.st-wont_fix,.st-deferred{background:var(--grey-bg)}
.st-fixed_needs_hw,.st-action_required,.st-in_progress{background:var(--amber-bg);color:var(--amber);font-weight:600}
details.f.resolved{opacity:.62}
.legend td:first-child{width:130px}.small{font-size:13px;color:var(--muted)}
@media print{body{background:#fff}.filters{display:none}details.f{break-inside:avoid}details.f .body{display:block!important}
.verdict,.badge,.tile,details.f{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
@media (max-width:760px){.tiles{grid-template-columns:repeat(2,1fr)}}
"""

JS = """
const st={rag:'all',cat:'all'};
function apply(){document.querySelectorAll('details.f').forEach(e=>{
 const ok=(st.rag==='all'||e.dataset.rag===st.rag)&&(st.cat==='all'||e.dataset.cat===st.cat);e.style.display=ok?'':'none';});
 document.querySelectorAll('.filters button[data-rag]').forEach(b=>b.classList.toggle('on',b.dataset.rag===st.rag));}
document.querySelectorAll('.filters button[data-rag]').forEach(b=>b.onclick=()=>{st.rag=b.dataset.rag;apply();});
document.getElementById('catsel').onchange=e=>{st.cat=e.target.value;apply();};
document.getElementById('expand').onclick=()=>document.querySelectorAll('details.f').forEach(d=>d.open=true);
document.getElementById('collapse').onclick=()=>document.querySelectorAll('details.f').forEach(d=>d.open=false);
window.addEventListener('beforeprint',()=>document.querySelectorAll('details.f').forEach(d=>{d.open=true;d.style.display='';}));
apply();
"""


def e(s):
    return html.escape(str(s if s is not None else ""))


def para(s):
    return "".join(f"<p>{e(x)}</p>" for x in str(s or "").split("\n\n") if x.strip())


def badge(r):
    return f'<span class="badge {r}">{RAG_LABEL[r]}</span>'


def render_html(d, findings, counts, verdict, score):
    p = d["project"]
    plat = p.get("platform", {}) or {}
    scope = p.get("scope", {}) or {}
    s = d.get("summary", {}) or {}
    out = []
    a = out.append
    a(f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
      f"<title>{e(TITLE)} — {e(p['name'])}</title><style>{CSS}</style></head><body><div class='wrap'>")
    a(f"<h1>{e(TITLE)} — {e(p['name'])}</h1><div class='meta'>")
    bits = [f"<b>Date</b> {e(p['review_date'])}"]
    if p.get("version"):
        bits.append(f"<b>Version</b> {e(p['version'])}")
    if p.get("reviewer"):
        bits.append(f"<b>Reviewer</b> {e(p['reviewer'])}")
    a(" &nbsp;·&nbsp; ".join(bits))
    if plat.get("summary"):
        a(f"<br><b>Platform</b> {e(plat['summary'])}"
          + (f" <span class='small'>(detection confidence: {e(plat.get('detection_confidence'))})</span>" if plat.get("detection_confidence") else ""))
    if scope:
        a(f"<br><b>Scope</b> {e(scope.get('files_reviewed', '?'))} first-party files"
          + (f", ~{int(scope['first_party_loc']):,} lines" if scope.get("first_party_loc") else "")
          + (f" in {e(', '.join(scope.get('first_party_paths', [])))}" if scope.get("first_party_paths") else ""))
    a("</div>")

    vr, vt, vs = verdict
    a(f"<div class='verdict {vr}'><div><div class='big'>{RAG_EMOJI[vr]} {e(vt)}</div><div class='sub'>{e(vs)}</div></div></div>")

    a("<div class='tiles'>")
    for r in RAGS:
        a(f"<div class='tile {r}'><div class='n'>{counts[r]}</div><div class='l'>{RAG_LABEL[r].title()}</div><div class='d'>{RAG_MEANING[r]}</div></div>")
    a(f"<div class='tile'><div class='n'>{len(findings)}</div><div class='l'>Total findings</div><div class='d'>across {sum(1 for x in score if x['status'] != 'not_reviewed')} of {len(CATEGORIES)} areas assessed</div></div>")
    a("</div>")

    a("<h2>Summary for engineering management</h2><div class='card'>")
    a(para(s.get("overview", "")))
    if s.get("key_risks"):
        a("<h4 style='margin:10px 0 4px'>Key risks</h4><ul>" + "".join(f"<li>{e(x)}</li>" for x in s["key_risks"]) + "</ul>")
    if s.get("strengths"):
        a("<h4 style='margin:10px 0 4px'>What is working well</h4><ul>" + "".join(f"<li>{e(x)}</li>" for x in s["strengths"]) + "</ul>")
    a("</div>")

    a("<h2>RAG scorecard by area</h2><table><tr><th>Area</th><th>Rating</th><th>Findings (R / A / G)</th><th>Coverage</th></tr>")
    for x in score:
        c = x["counts"]
        cnt = "".join(f"<span class='{('c-' + r) if c[r] else 'c-zero'}'>{c[r]}</span>" for r in RAGS)
        covtxt = {"reviewed": "Reviewed", "partial": "Partial", "not_reviewed": "Not reviewed"}[x["status"]]
        a(f"<tr><td><b>{e(x['label'])}</b></td><td>{badge(x['rating'])}</td><td class='counts'>{cnt}</td>"
          f"<td>{covtxt}{(' — <span class=small>' + e(x['notes']) + '</span>') if x['notes'] else ''}</td></tr>")
    a("</table>")

    reds = [f for f in findings if f["rag"] == "red" and is_open(f)]
    if reds:
        a("<h2>🔴 Must fix before release</h2><table><tr><th>ID</th><th>Issue</th><th>Area</th><th>Location</th><th>Effort</th></tr>")
        for f in reds:
            a(f"<tr><td><a href='#{e(f['id'])}'><b>{e(f['id'])}</b></a></td><td>{e(f['title'])}<div class='small'>{e(f['impact'])}</div></td>"
              f"<td>{e(CAT_LABEL[f['category']])}</td><td class='loc'>{e(loc_str(f.get('location')))}</td><td>{e(f.get('effort', ''))}</td></tr>")
        a("</table>")

    a("<h2>All findings</h2><div class='filters'>")
    for key, label in [("all", f"All ({len(findings)})"), ("red", f"Red ({counts['red']})"),
                       ("amber", f"Amber ({counts['amber']})"), ("green", f"Green ({counts['green']})")]:
        a(f"<button data-rag='{key}'>{label}</button>")
    a("<select id='catsel'><option value='all'>All areas</option>"
      + "".join(f"<option value='{c}'>{e(l)}</option>" for c, l in CATEGORIES) + "</select>"
      "<button id='expand'>Expand all</button><button id='collapse'>Collapse all</button></div>")
    for f in findings:
        a(f"<details class='f {f['rag']}{'' if is_open(f) else ' resolved'}' id='{e(f['id'])}' data-rag='{f['rag']}' data-cat='{f['category']}'>"
          f"<summary><span class='id'>{e(f['id'])}</span>{badge(f['rag'])}<span class='t'>{e(f['title'])}</span>"
          f"<span class='chip'>{e(CAT_LABEL[f['category']])}</span><span class='loc'>{e(loc_str(f.get('location')))}</span>"
          + (f"<span class='chip st-{e(status_of(f))}'>{e(STATUSES[status_of(f)])}</span>" if f.get('status') else "")
          + "</summary><div class='body'>")
        res = f.get("resolution") or {}
        if f.get("status") and (res.get("note") or res.get("commit")):
            a(f"<h4>Resolution</h4><p><b>{e(STATUSES[status_of(f)])}</b>"
              + (f" — commit <code>{e(res['commit'])}</code>" if res.get("commit") else "")
              + (f" ({e(res['date'])})" if res.get("date") else "") + "</p>" + para(res.get("note", "")))
        a(f"<div><span class='chip'>Confidence: {e(f['confidence'])}</span>"
          + (f"<span class='chip'>Effort: {e(f['effort'])}</span>" if f.get("effort") else "")
          + "".join(f"<span class='chip'>{e(r)}</span>" for r in f.get("references", [])) + "</div>")
        a("<h4>What's wrong</h4>" + para(f["description"]))
        a("<h4>Field impact</h4>" + para(f["impact"]))
        if f.get("evidence"):
            a(f"<h4>Evidence</h4><pre>{e(f['evidence'])}</pre>")
        if f.get("other_locations"):
            a("<h4>Also at</h4><ul>" + "".join(f"<li class='loc'>{e(loc_str(o))}</li>" for o in f["other_locations"]) + "</ul>")
        a("<h4>Recommendation</h4>" + para(f["recommendation"]))
        a("</div></details>")

    if d.get("next_steps"):
        a("<h2>Recommended next steps</h2><div class='card'><ol>" + "".join(f"<li>{e(x)}</li>" for x in d["next_steps"]) + "</ol></div>")

    a("<h2>Coverage and method</h2>")
    if d.get("tools"):
        a("<table><tr><th>Tool</th><th>Status</th><th>Notes</th></tr>"
          + "".join(f"<tr><td>{e(t.get('name'))}</td><td>{e(t.get('status'))}</td><td>{e(t.get('notes', ''))}</td></tr>" for t in d["tools"])
          + "</table><br>")
    if scope.get("excluded_paths"):
        a(f"<p class='small'><b>Excluded (vendored / generated):</b> {e(', '.join(scope['excluded_paths']))}. Third-party code was assessed for versions and configuration, not line-by-line.</p>")
    a("<table class='legend'><tr><th>Rating</th><th>Meaning</th></tr>"
      "<tr><td>" + badge("red") + f"</td><td>{e(LEGEND['red'])}</td></tr>"
      "<tr><td>" + badge("amber") + f"</td><td>{e(LEGEND['amber'])}</td></tr>"
      "<tr><td>" + badge("green") + f"</td><td>{e(LEGEND['green'])}</td></tr>"
      "<tr><td>" + badge("partial") + "</td><td>Area partly reviewed; no issues found in the part reviewed.</td></tr>"
      "<tr><td>" + badge("grey") + "</td><td>Area not reviewed — absence of findings is not evidence of quality.</td></tr></table>")
    a(f"<p class='small'>{e(DISCLAIMER)}</p>")
    a(f"</div><script>{JS}</script></body></html>")
    return "".join(out)


# ---------------------------------------------------------------- Markdown

def md_cell(s):
    return str(s or "").replace("|", "\\|").replace("\n", " ")


def render_md(d, findings, counts, verdict, score):
    p = d["project"]
    plat = p.get("platform", {}) or {}
    scope = p.get("scope", {}) or {}
    s = d.get("summary", {}) or {}
    L = []
    a = L.append
    a(f"# {TITLE} — {p['name']}\n")
    meta = [f"**Date:** {p['review_date']}"]
    if p.get("version"):
        meta.append(f"**Version:** {p['version']}")
    if p.get("reviewer"):
        meta.append(f"**Reviewer:** {p['reviewer']}")
    a(" · ".join(meta) + "  ")
    if plat.get("summary"):
        a(f"**Platform:** {plat['summary']}" + (f" (detection confidence: {plat['detection_confidence']})" if plat.get("detection_confidence") else "") + "  ")
    if scope:
        a(f"**Scope:** {scope.get('files_reviewed', '?')} first-party files"
          + (f", ~{int(scope['first_party_loc']):,} lines" if scope.get("first_party_loc") else "")
          + (f" in {', '.join('`' + x + '`' for x in scope.get('first_party_paths', []))}" if scope.get("first_party_paths") else ""))
    vr, vt, vs = verdict
    a(f"\n## {RAG_EMOJI[vr]} Verdict: {vt}\n\n{vs}\n")
    a(f"| 🔴 Red | 🟠 Amber | 🟢 Green | Total |\n|---|---|---|---|\n| **{counts['red']}** | **{counts['amber']}** | **{counts['green']}** | {len(findings)} |\n")
    a("## Summary\n")
    a(s.get("overview", "") + "\n")
    if s.get("key_risks"):
        a("**Key risks**\n\n" + "\n".join(f"- {x}" for x in s["key_risks"]) + "\n")
    if s.get("strengths"):
        a("**What is working well**\n\n" + "\n".join(f"- {x}" for x in s["strengths"]) + "\n")
    a("## RAG scorecard\n\n| Area | Rating | R | A | G | Coverage |\n|---|---|---|---|---|---|")
    for x in score:
        c = x["counts"]
        covtxt = {"reviewed": "Reviewed", "partial": "Partial", "not_reviewed": "Not reviewed"}[x["status"]]
        a(f"| {x['label']} | {RAG_EMOJI[x['rating']]} {RAG_LABEL[x['rating']]} | {c['red']} | {c['amber']} | {c['green']} | {md_cell(covtxt + (' — ' + x['notes'] if x['notes'] else ''))} |")
    a("")
    reds = [f for f in findings if f["rag"] == "red" and is_open(f)]
    if reds:
        a("## 🔴 Must fix before release\n\n| ID | Issue | Location | Effort |\n|---|---|---|---|")
        for f in reds:
            a(f"| [{f['id']}](#{f['id'].lower()}) | {md_cell(f['title'])} | `{loc_str(f.get('location'))}` | {f.get('effort', '')} |")
        a("")
    a("## Findings\n")
    for r in RAGS:
        group = [f for f in findings if f["rag"] == r]
        if not group:
            continue
        a(f"### {RAG_EMOJI[r]} {RAG_LABEL[r].title()} — {RAG_MEANING[r]}\n")
        for f in group:
            a(f"#### {f['id']}\n")
            a(f"**{RAG_EMOJI[r]} {RAG_LABEL[r]} · {f['title']}**\n")
            line = [f"**Area:** {CAT_LABEL[f['category']]}", f"**Location:** `{loc_str(f.get('location'))}`",
                    f"**Confidence:** {f['confidence']}"]
            if f.get("effort"):
                line.append(f"**Effort:** {f['effort']}")
            if f.get("status"):
                line.append(f"**Status:** {STATUSES[status_of(f)]}")
            a(" · ".join(line) + "\n")
            if f.get("references"):
                a("**References:** " + ", ".join(f["references"]) + "\n")
            a(f"**What's wrong.** {f['description']}\n")
            a(f"**Field impact.** {f['impact']}\n")
            if f.get("evidence"):
                a("```c\n" + f["evidence"].rstrip() + "\n```\n")
            if f.get("other_locations"):
                a("**Also at:** " + ", ".join(f"`{loc_str(o)}`" for o in f["other_locations"]) + "\n")
            a(f"**Recommendation.** {f['recommendation']}\n")
            res = f.get("resolution") or {}
            if f.get("status") and (res.get("note") or res.get("commit")):
                a(f"**Resolution.** {STATUSES[status_of(f)]}" + (f" — commit `{res['commit']}`" if res.get("commit") else "")
                  + (f" ({res['date']})" if res.get("date") else "") + (f". {res['note']}" if res.get("note") else "") + "\n")
    if d.get("next_steps"):
        a("## Recommended next steps\n\n" + "\n".join(f"{i + 1}. {x}" for i, x in enumerate(d["next_steps"])) + "\n")
    a("## Coverage and method\n")
    if d.get("tools"):
        a("| Tool | Status | Notes |\n|---|---|---|\n" + "\n".join(f"| {md_cell(t.get('name'))} | {t.get('status')} | {md_cell(t.get('notes', ''))} |" for t in d["tools"]) + "\n")
    if scope.get("excluded_paths"):
        a(f"Excluded (vendored / generated): {', '.join('`' + x + '`' for x in scope['excluded_paths'])}. Third-party code was assessed for versions and configuration, not line-by-line.\n")
    a(f"**RAG key:** 🔴 Red — {RAG_MEANING['red']} · 🟠 Amber — {RAG_MEANING['amber']} · "
      f"🟢 Green — {RAG_MEANING['green']} · 🟡 Partial — partly reviewed, nothing found · ⚪ Not assessed — not reviewed.\n")
    a(f"_{DISCLAIMER}_\n")
    return "\n".join(L)


def write_csv(path, findings):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["ID", "RAG", "Area", "Title", "File", "Line", "Confidence", "Effort", "Impact",
                    "Recommendation", "References", "Status", "Owner", "Resolution", "Commit"])
        for f in findings:
            loc = f.get("location") or {}
            w.writerow([f["id"], f["rag"].upper(), CAT_LABEL[f["category"]], f["title"], loc.get("file", ""),
                        loc.get("line") or "", f["confidence"], f.get("effort", ""), f["impact"],
                        f["recommendation"], "; ".join(f.get("references", [])), STATUSES[status_of(f)], "",
                        (f.get("resolution") or {}).get("note", ""), (f.get("resolution") or {}).get("commit", "")])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("findings")
    ap.add_argument("--out-dir")
    args = ap.parse_args()
    with open(args.findings, encoding="utf-8") as fh:
        try:
            d = json.load(fh)
        except json.JSONDecodeError as ex:
            sys.exit(f"invalid JSON: {ex}")
    if isinstance(d, dict):
        apply_profile(d)
    errs, warns = validate(d)
    for w in warns:
        print("warning:", w, file=sys.stderr)
    if errs:
        print("findings.json has problems:", file=sys.stderr)
        for x in errs:
            print("  -", x, file=sys.stderr)
        sys.exit(1)
    out = args.out_dir or os.path.dirname(os.path.abspath(args.findings))
    os.makedirs(out, exist_ok=True)
    findings, counts, verdict, score = compute(d)
    with open(os.path.join(out, "report.html"), "w", encoding="utf-8") as fh:
        fh.write(render_html(d, findings, counts, verdict, score))
    with open(os.path.join(out, "report.md"), "w", encoding="utf-8") as fh:
        fh.write(render_md(d, findings, counts, verdict, score))
    write_csv(os.path.join(out, "findings.csv"), findings)
    print(f"Verdict: {verdict[1]} — red {counts['red']}, amber {counts['amber']}, green {counts['green']}")
    for n in ("report.html", "report.md", "findings.csv"):
        print("wrote", os.path.join(out, n))


if __name__ == "__main__":
    main()
