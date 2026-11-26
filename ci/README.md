# Amygdala in a CI/CD pipeline

The same checks the skills run, without the model: pattern leads, static-analyser leads, function size and complexity, the maintainability band and layering check, the open-source component inventory, and (opt-in) the OSV.dev vulnerability lookup. One Python file drives the bundled scripts, compares the result with a committed baseline, fails the build on **new** items only, and writes the report, SARIF and JUnit files a pipeline can publish.

What it is not: a code review. Nobody reads the code, so nothing it produces is a verified finding, and the report says so on every page. Run `amygdala:review` (interactively, or on a pull request) to turn leads into findings.

```
python3 ci/amygdala_ci.py all --root <firmware-repo>
```

Exit code 0: every gate passed. 1: a gate failed. 2: usage or configuration error. 3: a script failed.

## What runs

| Step | Writes | What it is |
|---|---|---|
| `platform` | `platform.json` | MCU, SDK, RTOS and library inventory |
| `hotspots` | `hotspots.json`, `hotspots.md` | pattern leads over first-party code |
| `static` | `static_leads.json`, `static_leads.md`, `maintainability.json` | cppcheck, clang-tidy, flawfinder, semgrep and lizard, merged by file:line; function metrics, maintainability band, layering |
| `maintainability` | the lizard part of `static` on its own | |
| `vulns` | `osv_plan.json`, or `osv_leads.json` when sending is enabled | OSV.dev lookup for third-party components. **Plan only by default; nothing leaves the runner** |
| `licences` | `components.json`, `license_scan.md` | open-source components, declared and detected licences, copyleft files |
| `sbom` | `sbom.cdx.json`, `THIRD_PARTY_NOTICES.md` | only from a reviewer-confirmed component list; skipped otherwise, because an SBOM is never guessed |
| `report` | `findings.json`, `report.html`, `report.md`, `findings.csv`, `leads.sarif`, `junit.xml`, `gates.json`, `summary.md` | evaluates the gates and sets the exit code |

`all` runs them in that order. Run them one at a time for one job per step; `report` reads whatever the earlier steps left in the output directory and marks the gates it cannot evaluate as skipped. The output directory (default `<root>/amygdala-ci`) is never scanned.

Tool installation: `python3 ci/amygdala_ci.py check --root <repo>` prints which analysers are installed and the install command for each missing one, for the runner's operating system. `python3 ci/install_tools.py static cppcheck flawfinder semgrep lizard` installs them that way. Lizard is the one to have: a pure-Python install that feeds the Maintainability section.

## Gates and the baseline

Gates fail on items that are **new since the baseline**, so an existing backlog never blocks a pipeline but new risk does. Each lead has a fingerprint built from the rule, the file and the text of the flagged line, not its line number, so a lead keeps its identity when code above it moves.

| Gate | Fails when | Default |
|---|---|---|
| `required-tools` | a listed analyser did not run | none required |
| `hotspot-rules` | a new hit for a listed pattern rule | private keys, hard-coded passwords, TLS verification off, image validation off, sample signing keys, blocking calls inside an interrupt handler |
| `static-agreement` | a new line flagged by at least N analysers | N = 2 |
| `static-errors` | a new analyser lead rated error | on |
| `functions-over-thresholds` | a new function over lizard's thresholds (complexity > 15, > 100 lines, > 5 parameters) | on |
| `maintainability-rating` | the codebase band is this bad or worse (absolute, not baseline-relative) | poor |
| `vulnerabilities` | a new published advisory for a third-party component | on, but only evaluated when `osv.send` is true |
| `licence-families` | a new third-party component in a listed licence family | strong copyleft, network copyleft, non-commercial |

First run on an existing codebase: expect it to fail. Read the report, fix what you can, then accept the rest:

```
python3 ci/amygdala_ci.py baseline --root <repo>
git add amygdala-ci-baseline.json && git commit -m "Accept current amygdala-ci leads as baseline: <why>"
```

Refresh the baseline the same way after deliberately accepting new items. Without a baseline file every item counts as new, which is the safe direction.

Configuration lives in `amygdala-ci.json` at the root of the firmware repository; copy [`amygdala-ci.example.json`](amygdala-ci.example.json), which documents every key. Unknown keys fail the run so a typo cannot silently disable a gate. It is JSON rather than YAML because the standard library has no YAML parser and the scripts carry no dependencies.

## What the pipeline can publish

- **SARIF** (`leads.sarif`): GitHub code scanning (`github/codeql-action/upload-sarif`), GitLab and the Azure DevOps "SARIF SAST Scans Tab" extension read it. Leads then appear beside the diff and can be dismissed with a reason. Each result names the tool that produced it and says it is unverified.
- **JUnit** (`junit.xml`): one test per gate and one per tool, so GitHub, GitLab and Azure DevOps show pass and fail lists in their native test view with no extension.
- **The reports** (`report.html`, `report.md`, `findings.csv`): the same renderer as the skills, with a CI profile whose verdict reads "automated checks passed, this is not a code review" or "automated checks failed, new items to verify". Failed gates appear as Amber items with confidence `needs-verification`; Red is never used, because nothing has been verified.
- **GitHub step summary**: when `GITHUB_STEP_SUMMARY` is set, the gate and tool tables are appended to it automatically. The same Markdown is in `summary.md`.

## What leaves the runner

Nothing, unless `osv.send` is true in the config (or `--send` is passed). Then, for each third-party component, its public repository URL and tag go to `api.osv.dev`; no source, no project name, no findings. The plan of what would be sent is in `osv_plan.json` after any run, so a team can read it before deciding. Everything else, including semgrep with metrics off, stays on the runner. See [SECURITY.md](../SECURITY.md).

Secret values on flagged lines (passwords, keys, key material) are blanked before they reach any output file, the baseline or the console.

## Example: GitHub Actions

```yaml
jobs:
  amygdala:
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      security-events: write     # only for the SARIF upload
    steps:
      - uses: actions/checkout@v4
      - uses: actions/checkout@v4
        with:
          repository: phazeOne-Internal/amygdala
          ref: main                # pin a tag for a real pipeline
          path: .amygdala
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python .amygdala/ci/install_tools.py static cppcheck flawfinder semgrep lizard
      - run: python .amygdala/ci/amygdala_ci.py all --root . --exclude .amygdala --out-dir "$RUNNER_TEMP/amygdala-ci"
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: ${{ runner.temp }}/amygdala-ci/leads.sarif
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: amygdala-ci
          path: ${{ runner.temp }}/amygdala-ci
```

A composite action and GitLab and Azure DevOps templates that wrap these steps are the next addition; until then the commands above are the whole integration on any CI system with Python 3.8 or later.

## Adding Claude to the pipeline

The entry point never calls a model. A pull-request stage that runs `amygdala:review` on the diff with the Claude Code GitHub Action is possible, and it is the only way to get verified, RAG-rated findings in a pipeline, but it sends the changed code to Anthropic's API and costs tokens on every run. Keep it advisory (a PR comment and an artifact), not a gate, and say in the repository's docs that it exists.
