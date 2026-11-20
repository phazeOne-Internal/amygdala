# Amygdala Firmware Code Review Tool

A Claude Code plugin from ./phazeOne that spots the dangers in embedded / IoT firmware before they reach the field: review the code, check its open-source licences, and work through the findings.

| Skill | What it does |
|---|---|
| `amygdala:review` | Reviews a whole firmware codebase (memory safety, security, secure boot / OTA, robustness, concurrency, hardware and power, dependencies, field diagnostics, code quality, IoT regulation) and produces a RAG-rated report: `report.html` for engineering managers, `report.md` for developers, `findings.csv` for Jira / ADO. Auto-detects the platform (PSoC 6 / ModusToolbox, Zephyr, nRF Connect, ESP-IDF, STM32, FreeRTOS, bare metal). |
| `amygdala:oss` | Scans a codebase for open-source licence risk, works out what ships and how it is linked, and produces a RAG licence report, a draft THIRD_PARTY_NOTICES file and a CycloneDX SBOM. |
| `amygdala:fix` | Works through the findings of a `amygdala:review` report one at a time, Red first, with one commit per finding and a status update in the report. |

## Example reports

See what the output looks like before installing anything. Both skills were run against MITRE's 2025 eCTF insecure example decoder (Apache-2.0):

- [`amygdala:review` report](https://phazeone-internal.github.io/amygdala/examples/ectf-2025/review/report.html): Not ready for field release, 5 Red, 13 Amber, 4 Green.
- [`amygdala:oss` report](https://phazeone-internal.github.io/amygdala/examples/ectf-2025/oss/report.html): Conditional, obligations or decisions outstanding, 0 Red, 5 Amber, 4 Green.

The developer Markdown, CSV, SBOM and notices files, and how the reports were produced, are in [docs/examples/ectf-2025](docs/examples/ectf-2025/README.md).

## Requirements

- Claude Code.
- Python 3.8 or later on PATH as `python3` (macOS / Linux) or `py` / `python` (Windows). Every bundled script needs it. Each skill checks for it first and, if it is missing, shows the install command for your OS and asks before running it. On Windows use a python.org build or `winget install Python.Python.3.12`; the Microsoft Store stub is not enough.
- Optional: cppcheck, clang-tidy, flawfinder, semgrep (review) and ScanCode Toolkit (oss). The skills detect what is installed, show the install commands for anything missing, and never install without a yes.

## Install

From the private marketplace in this repository (Claude Code 2.1.275 or later):

```
/plugin install amygdala --marketplace phazeOne-Internal/amygdala
```

Or in two steps, which also works on older versions:

```
/plugin marketplace add phazeOne-Internal/amygdala
/plugin install amygdala@phazeone-amygdala
```

For a local checkout, add the folder instead: `/plugin marketplace add /path/to/amygdala`. Restart Claude Code after installing. The skills then appear as `/amygdala:review`, `/amygdala:oss` and `/amygdala:fix`.

## Layout

```
.claude-plugin/marketplace.json    private marketplace: lists the plugin below
plugin/
  .claude-plugin/plugin.json       plugin manifest (name: amygdala)
  skills/
    review/                        SKILL.md, references/, scripts/, assets/
    oss/                           SKILL.md, references/, scripts/
    fix/                           SKILL.md, scripts/
evals/
  review/                          eval cases for amygdala:review (synthetic projects with planted defects, plus the eCTF 2025 insecure example)
  oss/                             eval cases for amygdala:oss
  run.py                           runs the cases through claude plugin eval
docs/examples/                     example reports (served by GitHub Pages)
tests/                             script test suite and its two sample findings files
```

Scripts are plain Python 3 (3.8 or later) with no third-party dependencies and run on macOS, Linux and Windows. They run under whatever `python3` (or `py` on Windows) is on your PATH, including a toolchain's bundled interpreter such as PlatformIO's, ModusToolbox's or ESP-IDF's, and they never install anything into, or modify, the interpreter they run under. The one script that uses the network, the opt-in OSV.dev lookup, verifies TLS through the interpreter's CA bundle, certifi, or the operating system store, whichever is available. Static-analysis tools (cppcheck, clang-tidy, flawfinder, semgrep) are optional; the skill asks before installing anything.

## Using the skills

- **Running a review**: ask Claude to review the firmware, or invoke `/amygdala:review`. The review runs entirely on your machine. One optional step, a lookup of published vulnerabilities for the product's third-party libraries, sends their public repository URLs and tags to OSV.dev; the skill shows exactly what it would send and asks first (details in [SECURITY.md](SECURITY.md)). Results from it are labelled as third-party component issues, separate from defects in your own code. When the review finishes the HTML report opens in your browser; in CI or headless runs it is written to disk and not launched (see `render_report.py --help` and the `FW_REVIEW_OPEN` environment variable).
- **Licence review**: ask about licences, copyleft, an SBOM or a notices file, or invoke `/amygdala:oss`.
- **Fixing findings**: invoke `/amygdala:fix` with the `findings.json` from a review. It fixes one finding at a time and pauses for approval after each.
- **Without the plugin**: each folder under `plugin/skills/` is also a standalone skill. Copy it into a project's `.claude/skills/` or into `~/.claude/skills/`; `amygdala:fix` looks for the review skill's renderer next to itself and in those two locations.

## Evals

`evals/review/` and `evals/oss/` hold the eval cases: synthetic firmware projects with planted defects, one real third-party design (MITRE's eCTF 2025 insecure example decoder, Apache-2.0, see `evals/review/ectf-2025-insecure-example/README.md`), and the graders for each. They live outside `plugin/` so an installed plugin never carries them. Run them with `python evals/run.py review|oss|all`, which assembles a temporary copy of the plugin with the cases inside and calls `claude plugin eval`; each case runs the skill for real and costs tokens. Eval fixtures include deliberately committed sample keys and credentials; they are test data, not real secrets.

## Testing

`tests/test_scripts.py` runs every bundled script the way the skills do, on the eval fixtures and on two sample `findings.json` files, and checks the outputs: platform detection, hotspot and static-tool leads, the OSV plan mode (nothing is sent), report rendering with the firmware and licence profiles, secret redaction, the CI browser guard, the licence inventory, notices and SBOM generation, and the fix tracker. Standard library only:

```
python -m unittest discover -s tests -v
```

GitHub Actions (`.github/workflows/ci.yml`) runs it on every pull request and push to `main`:

- the suite on Ubuntu, Windows and macOS with the oldest supported Python and the current one;
- on each of the three, a job that installs cppcheck, flawfinder and semgrep using the exact commands `run_static_tools.py --check` prints for that operating system (`tests/install_tools.py`), then requires all three to run on the fixture, so the install advice the skill gives users is tested, not just typed;
- on each of the three, a job that installs ScanCode Toolkit with `install_scancode.py --yes` (including the libmagic prerequisite on Apple Silicon) and runs a real `--run-scancode` scan;
- plugin and marketplace validation with `claude plugin validate`. The model-graded evals under `evals/` are not part of CI; run them locally with `claude plugin eval`.

## Security

See [SECURITY.md](SECURITY.md) for what each skill reads, writes, executes and needs from the network, the rules every skill follows (repository contents are untrusted data; nothing leaves the machine; installs need consent; secret values are redacted from reports), and how to report a vulnerability. The skills are maintained against the [OWASP Agentic Skills Top 10](https://github.com/OWASP/www-project-agentic-skills-top-10) guidance for skill developers.

## Acknowledgements

The skills invoke Cppcheck, clang-tidy, Flawfinder, Semgrep and ScanCode Toolkit when they are installed, and draw on ETSI, NIST, CWE, CERT C, OWASP and the SPDX and CycloneDX projects. See [ACKNOWLEDGEMENTS.md](ACKNOWLEDGEMENTS.md) for the full list with licences.

## Releasing

Bump `version` in `plugin/.claude-plugin/plugin.json`, commit, then `claude plugin tag plugin` creates the matching `amygdala--v<version>` tag to push. Before submitting to the public plugin directory, add a square PNG icon at `plugin/.claude-plugin/icon.png`; `claude plugin validate plugin --profile directory` lists what the directory still refuses.

## Licence

Apache License 2.0; see [LICENSE](LICENSE). The eval fixture under `evals/review/ectf-2025-insecure-example/` is MITRE's 2025 eCTF insecure example, also Apache-2.0, included unmodified with its own licence file; see [ACKNOWLEDGEMENTS.md](ACKNOWLEDGEMENTS.md).
