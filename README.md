# FWCodeReview

Claude Code skills from ./phazeOne for reviewing embedded / IoT firmware and companion software.

| Skill | What it does |
|---|---|
| `firmware-review` | Reviews a whole firmware codebase (memory safety, security, secure boot / OTA, robustness, concurrency, hardware and power, dependencies, field diagnostics, code quality, IoT regulation) and produces a RAG-rated report: `report.html` for engineering managers, `report.md` for developers, `findings.csv` for Jira / ADO. Auto-detects the platform (PSoC 6 / ModusToolbox, Zephyr, nRF Connect, ESP-IDF, STM32, FreeRTOS, bare metal). |
| `firmware-fix` | Works through the findings of a `firmware-review` report one at a time, Red first, with one commit per finding and a status update in the report. |
| `oss-license-review` | Scans a codebase for open-source licence risk, works out what ships and how it is linked, and produces a RAG licence report, a draft THIRD_PARTY_NOTICES file and a CycloneDX SBOM. |

The HTML report is branded as a ./phazeOne deliverable, styled after <https://www.phazeone.com/>, and carries a **Get in touch** link to <https://www.phazeone.com/contact>. Brand text, URLs, contact details and the body theme live in the `BRAND` dict at the top of `.claude/skills/firmware-review/scripts/render_report.py`.

## Layout

```
.claude/skills/
  firmware-review/      SKILL.md, references/, scripts/, assets/, evals/
  firmware-fix/
  oss-license-review/
```

Scripts are plain Python 3 with no third-party dependencies and run on macOS, Linux and Windows. Static-analysis tools (cppcheck, clang-tidy, flawfinder, semgrep) are optional; the skill asks before installing anything.

## Using the skills

- **In this repo**: Claude Code picks the skills up automatically from `.claude/skills/`.
- **In any project**: copy the three skill folders into that project's `.claude/skills/`, or into `~/.claude/skills/` to make them available everywhere.
- **Running a review**: ask Claude to review the firmware, or invoke `/firmware-review`. When the review finishes the HTML report opens in your browser; in CI or headless runs it is written to disk and not launched (see `render_report.py --help` and the `FW_REVIEW_OPEN` environment variable).

## Evals

`.claude/skills/firmware-review/evals/` holds the eval cases (synthetic firmware projects with planted defects, plus graders). Run them with `claude plugin eval` or the skill-creator eval runner. Eval fixtures include deliberately committed sample keys and credentials; they are test data, not real secrets.

## Roadmap

- Package the skills as a Claude Code plugin for distribution.
