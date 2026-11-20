# Example reports: 2025 eCTF insecure example

Both skills run unmodified against MITRE's [2025 eCTF insecure example](https://github.com/mitre-cyber-academy/2025-ectf-insecure-example) (commit 7c26fc2, Apache-2.0), a deliberately insecure satellite-TV decoder for the Analog Devices MAX78000. The same source is the eval fixture at `evals/review/ectf-2025-insecure-example/`.

| Skill | Verdict | Red | Amber | Green | Open |
|---|---|---|---|---|---|
| `amygdala:review` | Not ready for field release | 5 | 13 | 4 | [report.html](https://phazeone-internal.github.io/amygdala/examples/ectf-2025/review/report.html) · [report.md](review/report.md) · [findings.csv](review/findings.csv) |
| `amygdala:oss` | Conditional, obligations or decisions outstanding | 0 | 5 | 4 | [report.html](https://phazeone-internal.github.io/amygdala/examples/ectf-2025/oss/report.html) · [report.md](oss/report.md) · [SBOM](oss/sbom.cdx.json) · [THIRD_PARTY_NOTICES.md](oss/THIRD_PARTY_NOTICES.md) |

How they were produced, on macOS with cppcheck, flawfinder, semgrep and ScanCode Toolkit 32.5.0 installed:

- clang-tidy was skipped because the project has no `compile_commands.json` and building it needs the MSDK; the report records that.
- The optional OSV.dev dependency lookup was skipped because nobody was present to consent to it; the report records "skipped (no consent)".
- The one edit to the tool output: `project.repo_path` in each `findings.json` was replaced with the fixture name, because it held a temporary folder path.
- Secret values the review found are redacted in every file, as the skill requires.

`report.html` is the engineering-manager view and `report.md` the developer view of the same `findings.json`. The OSS notices file is the skill's draft, with the gaps it could not fill left visible.
