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
    "review_date": "2026-11-19",
    "reviewer": "Claude (firmware-review skill)",
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
      "references": ["CWE-121", "ETSI EN 303 645 5.13", "EU CRA Annex I"]
    }
  ],
  "next_steps": ["Optional ordered list of recommended actions beyond individual findings, e.g. 'Add cppcheck and -Werror to CI'"]
}
```

### Field rules

- `id`: `FW-001`, `FW-002`… Number in the order they will be displayed is not required — the script sorts by RAG then category.
- `rag`: `red` | `amber` | `green`.
- `category`: one of `memory-safety`, `security`, `secure-boot-ota`, `robustness`, `concurrency`, `hardware-power`, `dependencies`, `field-readiness`, `regulatory`, `code-quality`.
- `confidence`: `confirmed` | `likely` | `needs-verification`. Red requires `confirmed` or `likely` (the script warns otherwise).
- `location`: `file` relative to the repo root; `line` an integer, or `null` for findings that are about absence (e.g. "no watchdog") or process. For absence findings, point to the most relevant place (e.g. `main.c` init sequence) if there is one.
- `evidence`: short code excerpt (≤ ~15 lines), or `""` for absence/process findings.
- `effort`: `S` (< 1 day), `M` (1–5 days), `L` (> 1 week / design change).
- `coverage[].area`: same values as `category`. Include all ten areas, so the scorecard is complete. `status`: `reviewed` | `partial` | `not_reviewed`.
- `tools[].status`: `ran` | `not_available` | `failed` | `skipped`.
- Optional fields: `other_locations`, `references`, `next_steps`, `project.version`, `project.platform.notes`.

The script exits non-zero and prints the problems if the JSON is invalid — fix and re-run.
