# Report format: RAG rules and findings.json schema

## RAG rating rules

Rate each finding on **field impact × likelihood**.

| | Impact: severe (exploit, brick, data loss, safety, market-access blocker) | Impact: moderate (degraded function, recoverable failure, undiagnosable issue, defence-in-depth gap) | Impact: minor (maintainability, style, small inefficiency) |
|---|---|---|---|
| **Likely** (reachable from external input, or will happen in normal use or over normal lifetime) | 🔴 Red | 🟠 Amber | 🟢 Green |
| **Possible** (needs unusual conditions, insider access, or a chain of failures) | 🔴 Red if remote/at scale, else 🟠 Amber | 🟠 Amber | 🟢 Green |
| **Unlikely / unverified** | 🟠 Amber | 🟢 Green–🟠 Amber | 🟢 Green |

What each rating asks of the team:

- **🔴 Red — Must fix before release / ASAP.** Blocks field release. If the product is already in the field, it needs a fix in the next update and possibly a customer or regulator notification.
- **🟠 Amber — Fix before release, or the engineering manager formally accepts the risk** with a target fix date.
- **🟢 Green — Improve when convenient.** Add to the tech-debt backlog.

The **overall verdict** is set by the script from the findings:
- any Red → **🔴 NOT READY FOR FIELD RELEASE**
- no Red, any Amber → **🟠 CONDITIONAL — resolve or accept Amber items**
- only Green → **🟢 READY, subject to the coverage limits stated**

Each **area** in the scorecard takes the worst rating of its findings. An area with no findings is Green only if its coverage status is `reviewed`; `partial` with no findings shows Amber-outlined "Partial — no issues found"; `not_reviewed` shows grey "Not assessed".

## findings.json schema

```json
{
  "project": {
    "name": "Smart Thermostat FW",
    "repo_path": "/path/to/repo",
    "version": "v1.4.2 or git commit if known",
    "review_date": "2026-11-19 14:05",
    "reviewer": "Claude (amygdala:review skill)",
    "platform": {
      "summary": "Infineon PSoC 6 (CY8C624ABZI) · ModusToolbox 3.x · FreeRTOS 10.5 · Wi-Fi (AIROC CYW43012) · MQTT/TLS to AWS IoT",
      "detection_confidence": "high",
      "notes": "CM4 application with prebuilt CM0+ image"
    },
    "scope": {
      "first_party_paths": ["source/", "include/"],
      "excluded_paths": ["mtb_shared/", "libs/", "bsps/"],
      "files_reviewed": 42,
      "first_party_loc": 8120
    }
  },
  "summary": {
    "overview": "2-4 sentences for the engineering manager: what the product is, overall state, the main themes.",
    "key_risks": ["One line per top risk, plain language"],
    "strengths": ["Things done well"]
  },
  "coverage": [
    {"area": "secure-boot-ota", "status": "partial", "notes": "Bootloader is a prebuilt vendor binary; only the app-side OTA was reviewed."}
  ],
  "tools": [
    {"name": "hotspots.py", "status": "ran", "notes": "37 leads, 9 became findings"},
    {"name": "cppcheck", "status": "not_available", "notes": "Recommend adding to CI"}
  ],
  "findings": [
    {
      "id": "FW-001",
      "title": "MQTT topic copied into 64-byte stack buffer without length check",
      "rag": "red",
      "category": "memory-safety",
      "confidence": "confirmed",
      "location": {"file": "source/mqtt_task.c", "line": 214},
      "other_locations": [{"file": "source/cmd_parser.c", "line": 88}],
      "evidence": "char topic[64];\nstrcpy(topic, msg->topic);",
      "description": "What is wrong, in a few sentences.",
      "impact": "Concrete field scenario: trigger → what the customer/attacker gets.",
      "recommendation": "Specific fix, optionally with a short code sketch, and how to test it.",
      "effort": "S",
      "origin": "first-party",
      "references": ["CWE-121", "ETSI EN 303 645 5.13", "EU CRA Annex I"]
    }
  ],
  "next_steps": ["Optional ordered list of recommended actions beyond individual findings, e.g. 'Add cppcheck and -Werror to CI'"],
  "code_health": { "...": "optional: paste code_health.json from run_static_tools.py unchanged; see below" }
}
```

### `code_health` (optional, mechanical)

`run_static_tools.py` writes `code_health.json` next to `static_leads.json`. Copy it into `findings.json` as the top-level
`code_health` value without editing it; the renderer draws the **Code health (maintainability)** section from it. It holds:

- `tool`, `status`, `notes`: lizard's run status, same values as `tools[].status`. When lizard was not installed the section
  still appears, says so, and shows the layering result alone.
- `thresholds`: `{"ccn": 15, "nloc": 100, "params": 5}`. `totals`: functions, files, `nloc`, `avg_ccn`, `max_ccn`, `avg_nloc`,
  `over_threshold`, `pct_over`. `by_directory`: one row per directory, worst first. `worst_functions`: up to 15, each with
  `name`, `file`, `line`, `nloc`, `ccn`, `params` and `over` (which thresholds it exceeds).
- `rating`: `good` | `fair` | `poor` | `unknown`, with `rating_basis` stating the numbers it came from. Good: at most 5% of
  functions over a threshold and no function over complexity 30. Fair: at most 15% and none over 60. Otherwise poor.
- `layering`: `status` (`checked` | `not_inferable`), `lower_files`, `upper_files`, `basis`, `upward_includes`, `upward_calls`,
  `register_access_in_app`, `samples` (up to five locations per rule) and `note` when the layers could not be told apart.

Maintainability is reported separately from the RAG verdict on purpose: it says how hard the code is to change safely, not
whether it is correct. A `poor` rating with no findings is still a `green` verdict, and the report says why that matters.

### Field rules

- `review_date`: the date **and time** the review was run, local time, `YYYY-MM-DD HH:MM` (read the clock when you start writing findings; don't guess). The renderer adds its own `Generated` stamp with the time zone on every render, so a re-render by the fix skill shows when the report was last produced.
- `id`: `FW-001`, `FW-002`… Number in the order they will be displayed is not required — the script sorts by RAG then category.
- `rag`: `red` | `amber` | `green`.
- `category`: one of `memory-safety`, `security`, `secure-boot-ota`, `robustness`, `concurrency`, `hardware-power`, `dependencies`, `field-readiness`, `regulatory`, `code-quality`.
- `confidence`: `confirmed` | `likely` | `needs-verification`. Red requires `confirmed` or `likely` (the script warns otherwise).
- `location`: `file` relative to the repo root; `line` an integer, or `null` for findings that are about absence (e.g. "no watchdog") or process. For absence findings, point to the most relevant place (e.g. `main.c` init sequence) if there is one.
- `evidence`: short code excerpt (≤ ~15 lines), or `""` for absence/process findings.
- `effort`: `S` (< 1 day), `M` (1–5 days), `L` (> 1 week / design change).
- `coverage[].area`: same values as `category`. Include all ten areas, so the scorecard is complete. `status`: `reviewed` | `partial` | `not_reviewed`.
- `tools[].status`: `ran` | `not_available` | `failed` | `skipped`.
- `origin` (optional): `first-party` (default) for defects in the code under review, or `third-party` for a published vulnerability or defect in a dependency the product links. Third-party findings are labelled as such in every output so readers can tell "our code is wrong" from "a library we use has a known issue". Use `third-party` for OSV.dev results and for any other advisory-based finding, and state in the description whether the affected feature is compiled in and reachable.
- Optional fields: `other_locations`, `references`, `next_steps`, `project.version`, `project.platform.notes`.

The script exits non-zero and prints the problems if the JSON is invalid — fix and re-run.
