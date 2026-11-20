# Licence report: findings.json for the shared renderer

`scripts/render_report.py` is the same renderer the firmware-review skill uses. It turns `findings.json` into `report.html` (legal/management), `report.md` (developers) and `findings.csv` (tracking). The licence review supplies its own title, categories and verdict wording through the `report` object below. **Copy this block verbatim** into every licence `findings.json`.

```json
"report": {
  "title": "Open-source licence review",
  "categories": [
    ["strong-copyleft", "Strong copyleft (GPL family)"],
    ["network-copyleft", "Network copyleft (AGPL / SSPL)"],
    ["weak-copyleft", "Weak copyleft (LGPL / MPL / EPL)"],
    ["installation-info", "GPLv3 vs locked boot / signed images"],
    ["unlicensed-provenance", "No licence / copied code"],
    ["restricted-vendor", "Vendor & non-commercial terms"],
    ["license-conflict", "Licence conflicts"],
    ["linux-obligations", "Embedded Linux source obligations"],
    ["attribution", "Attribution & notices"],
    ["sbom-process", "SBOM & compliance process"]
  ],
  "verdict": {
    "red": "NOT CLEARED FOR DISTRIBUTION",
    "amber": "CONDITIONAL — OBLIGATIONS OR DECISIONS OUTSTANDING",
    "green": "NO BLOCKING LICENCE ISSUES FOUND, SUBJECT TO COVERAGE"
  },
  "rag_meaning": {
    "red": "Blocks distribution until resolved",
    "amber": "Obligations to meet or decision needed",
    "green": "Tidy-up"
  },
  "legend": {
    "red": "Blocks distribution until resolved: copyleft reaching proprietary code, GPLv3 vs locked boot, no licence, non-commercial terms, licence conflicts. Needs engineering change or a legal decision.",
    "amber": "Shippable once obligations are met or a decision is recorded: source offers, notices, modified MPL files, unknown dependency licences.",
    "green": "Tidy-up: attribution in place, build-only tools, SPDX hygiene."
  },
  "disclaimer": "Automated and AI-assisted licence triage. Not legal advice. Red items and all distribution decisions should be confirmed by your open-source compliance owner or legal counsel."
}
```

Other top-level keys are the same as in the firmware review (`project`, `summary`, `coverage`, `tools`, `findings`, `next_steps`), with these conventions:

- `project.platform.summary`: the products covered, e.g. "PSoC 6 MCU firmware (ModusToolbox) · Yocto Linux gateway · React Native companion app".
- `project.scope`: `first_party_paths` = your code. `excluded_paths` = anything not scanned (state why). Third-party code **is** scanned for licences.
- `coverage[]`: one entry per category above. Use `partial` when, for example, no linker map or Yocto manifest was available, so linkage was inferred.
- `tools[]`: `license_scan.py`, ScanCode (ran / not_available / skipped), plus any manifest evidence used (linker map, `license.manifest`, `legal-info`).
- Each finding:
  - `category`: one of the keys above.
  - `location.file`: the component directory, licence file or offending source file, always a path **in the reviewed repository**. For absence findings (no notices, no SBOM, no lockfile), point at the most relevant repo file, e.g. the app's `package.json`, the firmware `Makefile` or the Yocto `local.conf`, never at a file this review generated. `line`: the header line or `null`.
  - `evidence`: the licence header, SPDX tag, manifest line or `MODULE_LICENSE` line (short).
  - `description`: the licence, how it's combined, and which product it ships in.
  - `impact`: the concrete obligation or exposure ("distributing the firmware would require releasing all firmware source under GPL-2.0").
  - `recommendation`: the options: replace with a permissive alternative (name one if you know it), isolate it as a separate program, obtain a commercial licence, remove it, or meet the obligation (and how).
  - `references`: licence identifiers and clauses (e.g. "GPL-3.0 §6 Installation Information", "LGPL-2.1 §6").
  - Group by component: one finding per component per issue, with all affected files in `other_locations`.
- Confidence: `confirmed` when the licence text and the linkage are both evidenced (e.g. licence file plus linker map). `likely` when the licence is clear but the linkage is inferred. `needs-verification` otherwise.
