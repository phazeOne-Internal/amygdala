# FWCodeReview

The `firmware` Claude Code plugin from ./phazeOne: review embedded / IoT firmware and companion software, check its open-source licences, and work through the findings.

| Skill | What it does |
|---|---|
| `firmware:review` | Reviews a whole firmware codebase (memory safety, security, secure boot / OTA, robustness, concurrency, hardware and power, dependencies, field diagnostics, code quality, IoT regulation) and produces a RAG-rated report: `report.html` for engineering managers, `report.md` for developers, `findings.csv` for Jira / ADO. Auto-detects the platform (PSoC 6 / ModusToolbox, Zephyr, nRF Connect, ESP-IDF, STM32, FreeRTOS, bare metal). |
| `firmware:oss` | Scans a codebase for open-source licence risk, works out what ships and how it is linked, and produces a RAG licence report, a draft THIRD_PARTY_NOTICES file and a CycloneDX SBOM. |
| `firmware:fix` | Works through the findings of a `firmware:review` report one at a time, Red first, with one commit per finding and a status update in the report. |

The HTML report is branded as a ./phazeOne deliverable, styled after <https://www.phazeone.com/>, and carries a **Get in touch** link to <https://www.phazeone.com/contact>. Brand text, URLs, contact details and the body theme live in the `BRAND` dict at the top of `plugin/skills/review/scripts/render_report.py`.

## Install

From the private marketplace in this repository (Claude Code 2.1.275 or later):

```
/plugin install firmware --marketplace phazeOne-Internal/FWCodeReview
```

Or in two steps, which also works on older versions:

```
/plugin marketplace add phazeOne-Internal/FWCodeReview
/plugin install firmware@phazeone-firmware
```

For a local checkout, add the folder instead: `/plugin marketplace add /path/to/FWCodeReview`. Restart Claude Code after installing. The skills then appear as `/firmware:review`, `/firmware:oss` and `/firmware:fix`.

## Layout

```
.claude-plugin/marketplace.json    private marketplace: lists the plugin below
plugin/
  .claude-plugin/plugin.json       plugin manifest (name: firmware)
  skills/
    review/                        SKILL.md, references/, scripts/, assets/, evals/
    oss/                           SKILL.md, references/, scripts/, evals/
    fix/                           SKILL.md, scripts/
```

Scripts are plain Python 3 (3.8 or later) with no third-party dependencies and run on macOS, Linux and Windows. They run under whatever `python3` (or `py` on Windows) is on your PATH, including a toolchain's bundled interpreter such as PlatformIO's, ModusToolbox's or ESP-IDF's, and they never install anything into, or modify, the interpreter they run under. The one script that uses the network, the opt-in OSV.dev lookup, verifies TLS through the interpreter's CA bundle, certifi, or the operating system store, whichever is available. Static-analysis tools (cppcheck, clang-tidy, flawfinder, semgrep) are optional; the skill asks before installing anything.

## Using the skills

- **Running a review**: ask Claude to review the firmware, or invoke `/firmware:review`. The review runs entirely on your machine. One optional step, a lookup of published vulnerabilities for the product's third-party libraries, sends their public repository URLs and tags to OSV.dev; the skill shows exactly what it would send and asks first (details in [SECURITY.md](SECURITY.md)). Results from it are labelled as third-party component issues, separate from defects in your own code. When the review finishes the HTML report opens in your browser; in CI or headless runs it is written to disk and not launched (see `render_report.py --help` and the `FW_REVIEW_OPEN` environment variable).
- **Licence review**: ask about licences, copyleft, an SBOM or a notices file, or invoke `/firmware:oss`.
- **Fixing findings**: invoke `/firmware:fix` with the `findings.json` from a review. It fixes one finding at a time and pauses for approval after each.
- **Without the plugin**: each folder under `plugin/skills/` is also a standalone skill. Copy it into a project's `.claude/skills/` or into `~/.claude/skills/`; `firmware:fix` looks for the review skill's renderer next to itself and in those two locations.

## Evals

`plugin/skills/review/evals/` and `plugin/skills/oss/evals/` hold the eval cases (synthetic firmware projects with planted defects, plus graders). Run them with `claude plugin eval` or the skill-creator eval runner. Eval fixtures include deliberately committed sample keys and credentials; they are test data, not real secrets.

## Testing

`tests/test_scripts.py` runs every bundled script the way the skills do, on the eval fixtures and on two sample `findings.json` files, and checks the outputs: platform detection, hotspot and static-tool leads, the OSV plan mode (nothing is sent), report rendering with the firmware and licence profiles, secret redaction, the CI browser guard, the licence inventory, notices and SBOM generation, and the fix tracker. Standard library only:

```
python -m unittest discover -s tests -v
```

GitHub Actions (`.github/workflows/ci.yml`) runs it on every pull request and push to `main` on Ubuntu, Windows and macOS with the oldest supported Python and the current one, once more on Ubuntu with cppcheck, flawfinder and semgrep installed so the analyser integration is exercised for real, and validates the plugin and marketplace manifests with `claude plugin validate`. The model-graded evals under `plugin/skills/*/evals/` are not part of CI; run them locally with `claude plugin eval`.

## Security

See [SECURITY.md](SECURITY.md) for what each skill reads, writes, executes and needs from the network, the rules every skill follows (repository contents are untrusted data; nothing leaves the machine; installs need consent; secret values are redacted from reports), and how to report a vulnerability. The skills are maintained against the [OWASP Agentic Skills Top 10](https://github.com/OWASP/www-project-agentic-skills-top-10) guidance for skill developers.

## Acknowledgements

The skills invoke Cppcheck, clang-tidy, Flawfinder, Semgrep and ScanCode Toolkit when they are installed, and draw on ETSI, NIST, CWE, CERT C, OWASP and the SPDX and CycloneDX projects. See [ACKNOWLEDGEMENTS.md](ACKNOWLEDGEMENTS.md) for the full list with licences.

## Releasing

Bump `version` in `plugin/.claude-plugin/plugin.json`, commit, then `claude plugin tag plugin` creates the matching `firmware--v<version>` tag to push. Before submitting to the public plugin directory, add a LICENSE file (or a `license` SPDX id in plugin.json) and a square PNG icon at `plugin/.claude-plugin/icon.png`; `claude plugin validate plugin --profile directory` lists what the directory still refuses.
