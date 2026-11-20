---
name: oss-license-review
description: Scan a codebase for open-source licence risk (GPL, LGPL, AGPL, SSPL and other copyleft, plus no-licence, non-commercial and vendor-restricted code) across MCU firmware, embedded Linux images and companion mobile/desktop/cloud apps; work out what actually ships and how it is linked; and produce a Red/Amber/Green licence risk report for engineering, management and legal, a draft THIRD_PARTY_NOTICES file and a CycloneDX SBOM. Use this whenever the user asks about open-source licences, GPL or copyleft risk, licence compliance, third-party code, attribution or notices files, an SBOM, OSS audits, due diligence, or whether code can be shipped or distributed, even if they don't say "licence".
---

# Open-source licence review

Your job is to find licence problems that would stop the product shipping, or force the company to release source it didn't intend to, and to list the obligations that must be met for everything else. The readers are engineers (what to change), managers (can we ship?) and whoever owns legal and compliance (what decisions they need to make).

Licence risk isn't about which licences appear in the repo. It's about **what ships, how it's combined with proprietary code, and to whom it's distributed.** A GPL script in `tools/` is harmless. A GPL file compiled into firmware is not. Every conclusion should say which of these it rests on.

This is engineering triage, not legal advice. Say so in the report, and route Reds to legal. Don't soften findings to avoid that, though: a clear "this blocks distribution" is what makes the legal review quick.

Scripts are plain Python 3 and cross-platform. On Windows use `py` or `python` instead of `python3`. Write outputs with each script's `--out-dir` rather than `>` redirects; Windows PowerShell 5.1 writes UTF-16.

## 1. Understand the product

Find out what's in the repo and what ships. Look for:
- **MCU firmware:** ModusToolbox (`*.mtb`, `Makefile` with `TARGET`), Zephyr (`west.yml`, `prj.conf`), ESP-IDF (`sdkconfig`), PlatformIO, STM32Cube, plain CMake/Make. The `firmware-review` skill's `detect_platform.py` helps if it's installed.
- **Embedded Linux:** Yocto (`meta-*/`, `*.bb`, `conf/local.conf`, `tmp/deploy/licenses/`), Buildroot (`Config.in`, `package/*/*.mk`, `.config` with `BR2_`, `legal-info/`), kernel trees (`Kbuild`, `MODULE_LICENSE`), OpenWrt.
- **Companion apps and services:** `package.json` / `node_modules`, `Podfile.lock`, `build.gradle`, `pubspec.lock`, `go.mod`, `Cargo.toml`, Python `requirements.txt` / `pyproject.toml`, Dockerfiles.

Ask the user, briefly, only for things you can't determine and that change the rating:
- Is secure boot or a signed / read-only image used on shipped devices? This decides GPLv3 / LGPLv3.
- Which apps or services are distributed to customers, and which only run on company servers? This decides GPL vs AGPL.
- Is a build output available, such as a linker `.map`, Yocto `license.manifest` or Buildroot `legal-info/`?

If the user isn't available, assume the riskier option, and state the assumption in the report's coverage notes.

## 2. Inventory licences

### a. Make sure ScanCode is available (ask if it isn't)

ScanCode Toolkit is the industry-standard licence scanner. It recognises thousands of licence texts and variants, and extracts copyright holders, which the notices need. The bundled scanner only knows the ~30 most common licences, so on real product trees ScanCode materially improves the result. Check for it first:

```bash
python3 <skill-dir>/scripts/license_scan.py <repo-root> --check
```

If `scancode.installed` is false, **always ask the user** before going further. Use the AskUserQuestion tool if it's available, otherwise ask in chat. Don't skip the question, and don't install without a yes: it's a large, machine-wide change. Preview what would run first:

```bash
python3 <skill-dir>/scripts/install_scancode.py --dry-run
```

Then ask, showing the planned commands from the dry run and the size ("several hundred MB; first run unpacks licence data"):
- **Install ScanCode now (recommended):** run `python3 <skill-dir>/scripts/install_scancode.py --yes`. It installs for the current user only, without admin rights. It prefers `pipx`; on macOS it can set pipx up with Homebrew first, which the dry run will show. It never installs into a virtualenv or a toolchain's private Python (PlatformIO, ModusToolbox, ESP-IDF). It prints the path of the installed `scancode`; the skill finds it even if it isn't on PATH yet.
- **I'll install it myself:** give them the commands from the dry run (and the release-archive link for Windows or offline machines), and wait.
- **Continue without ScanCode:** use the bundled scanner, and record "ScanCode: not run (user declined)" in the report's tools and coverage sections, so readers know the scan was lighter.

**On Windows:**
- Python must be a real 64-bit install from python.org, or via `winget install Python.Python.3.12`. The Microsoft Store "python" alias is skipped.
- Without pipx, the installer uses `py -m pip install --user`. `pipx` can be added with `py -m pip install --user pipx`, if the user prefers it.
- ScanCode trees and deep `mtb_shared` paths can exceed Windows' 260-character path limit. If ScanCode reports path errors, suggest enabling long paths (Group Policy or the `LongPathsEnabled` registry key, which needs admin), or moving the repo to a short path like `C:\src\`.
- The self-contained release archive (`scancode.bat`) is the fallback when pip can't install it. Unpack it to `C:\scancode-toolkit\` or the user folder, and the skill will find it.

If the install fails, show the user the last lines of the output, offer the self-contained release archive from the ScanCode GitHub releases page, and carry on with the bundled scanner meanwhile. Don't retry with other methods the user didn't approve.

### b. Run the inventory

```bash
python3 <skill-dir>/scripts/license_scan.py <repo-root> --out-dir <out-dir> --run-scancode \
    [--map <build>/<app>.map ...] [--exclude <dir> ...]
```

`--run-scancode` runs ScanCode automatically if it's installed, then merges its per-file results. It's silently skipped if ScanCode isn't installed, and the summary line says so. ScanCode can take a long time on big trees: tens of minutes for a full ModusToolbox `mtb_shared`, longer with embedded Linux sources. Tell the user before starting, and run it in the background if your environment supports that. Use `--scancode-timeout` to allow longer runs, or `--scancode-json <file>` to merge an existing result instead.

Default `<out-dir>` is `license-review/` at the repo root. The script scans **everything, including vendored and third-party directories**: licence files, SPDX tags, licence header text, `MODULE_LICENSE`, package manifests (`.mtb`, `west.yml`, npm, pip, Gradle, Cargo, Go, pub, CocoaPods, Yocto recipes and manifests, Buildroot), git submodules, and "copied from <url>" / Stack Overflow comments. It writes:
- `components.json`: one entry per component, with declared and detected licences, licence files, copyleft files, linkage evidence and flags;
- `license_scan.md`: a summary sorted by risk, with special sections for copyleft files inside first-party code, proprietary kernel modules, web snippets, components with no licence, and dependencies with no licence data.

Pass every linker map you can find (`find . -name "*.map"` under the build directories). It's the only proof of what's linked into MCU firmware.

**Known ScanCode false positives**, which you should check before rating:
- "All Rights Reserved" inside a permissive licence file (common in MIT/BSD copyright lines) shows up as `LicenseRef-scancode-proprietary-license`.
- Package or dependency names containing "gpl" (e.g. in `package.json`) show up as GPL.
- Licence *names* mentioned in documentation or comments, rather than licence grants, show up as that licence.

Confirm each one against the actual file before it changes a rating.

**These are leads.** Header detection is heuristic. Mixed directories may be split oddly. Manifests can be stale. Lockfile-only dependencies (Gradle, CocoaPods, Go, pip requirements) have no licence data offline. Say so in the report, and recommend the ecosystem's licence tool (e.g. `license-checker` for npm, the Gradle licence plugin, `pip-licenses`, Yocto `license.manifest`), or run it yourself if it's already installed.

## 3. Assess each component

Read `references/license-risk.md` (licence families, RAG rules) and `references/linkage.md` (what ships and how it's combined, per product type). For each component whose licence isn't plainly permissive, and for every first-party file carrying a copyleft or foreign header:

1. **Confirm the licence:** read the licence file and a few headers. Check for exceptions (`WITH ...`, "As a special exception") and dual licensing (`OR`). Note mismatches between the manifest and the files.
2. **Does it ship?** Is it compiled or linked into the firmware (map file, build config), installed in the Linux image (manifest, recipe in the image), or bundled in the app (runtime dependency, not `devDependencies`)? Or is it only a build or test tool?
3. **How is it combined?** Statically linked, dynamically linked, a separate program, a firmware blob, or a network service.
4. **Under which conditions?** Locked boot or signed images, modified or unmodified, which markets and devices (vendor licences).
5. **Rate it** with the RAG rules, and write the finding as described in `references/report-format.md`.

Priorities, in order:
1. Copyleft headers in **first-party** directories: this is usually code someone copied in.
2. Strong, network or weak copyleft in anything that ships.
3. Components with no licence, or that are non-commercial.
4. GPLv3 / LGPLv3 with locked boot.
5. Kernel modules.
6. Vendor licence terms against the actual silicon.
7. Attribution completeness.

Group repeats: one finding per component per issue, with the files listed. Be concrete about the exposure, e.g. "Distributing this firmware would require offering the complete firmware source under GPL-2.0", and give realistic options: a permissive replacement (name one if you know it), isolation, a commercial licence, removal, or meeting the obligation. Credit good practice too (SPDX tags, Yocto `INCOMPATIBLE_LICENSE`, an existing notices file, `legal-info` in CI).

## 4. Confirmed component list, notices and SBOM

Write `<out-dir>/confirmed_components.json` with your conclusions for every component: name, version, licence (SPDX expression as concluded, not as guessed), path, `shipped_in` (e.g. `["mcu-firmware"]`, `["linux-image"]`, `["android-app"]`), `distribution` (`linked` | `dynamic` | `separate-program` | `firmware-blob` | `build-tool` | `test-only` | `not-distributed`), `license_file`, supplier, purl if known, and `modified`. The format is in the `make_outputs.py` docstring. Leave out nothing you inventoried; mark build-only items as such rather than dropping them. Then:

```bash
python3 <skill-dir>/scripts/make_outputs.py <repo-root> --confirmed <out-dir>/confirmed_components.json --out-dir <out-dir>
```

This produces:
- **`THIRD_PARTY_NOTICES.md`:** a draft attribution file for shipped components, with the licence texts copied from the repo. It's marked DRAFT for compliance review. Where a licence text isn't in the repo, it says so, and that's an Amber attribution finding.
- **`sbom.cdx.json`:** a CycloneDX 1.5 SBOM of all components, with distribution recorded as a property. It is also useful for EU CRA SBOM obligations.

## 5. RAG report

Write `<out-dir>/findings.json` using the `report` profile block in `references/report-format.md` (copy it verbatim), then:

```bash
python3 <skill-dir>/scripts/render_report.py <out-dir>/findings.json --out-dir <out-dir> --open
```

This produces `report.html` (verdict, scorecard, must-resolve list), `report.md` and `findings.csv`. The renderer is the same script as the `firmware-review` skill's, so the HTML report has the same ./phazeOne look and feel: branded header with a **Get in touch** button, hero, light-blue body, call-to-action and footer linking to https://www.phazeone.com/contact. Keep that branding in place.

Always pass `--open`. In an interactive session it launches `report.html` in the default browser when the render finishes and prints `opened ...`. In CI or headless runs (`CI`, `GITHUB_ACTIONS` and similar set, no display on Linux, or an SSH session) it prints `not opening a browser: <reason>` with the `file://` path and exits 0; treat that as success. `FW_REVIEW_OPEN=0` suppresses launching everywhere and `--force-open` launches even in CI. Before the final message, make sure the last render was of the final `findings.json` and ran with `--open`. Fill in `coverage` honestly: no linker map means MCU linkage is `partial`, and no app lockfile means app dependencies are `partial` or `not_reviewed`. An unscanned area must never show Green.

## 6. Tell the user

Keep it short in chat:
- the verdict;
- each Red in one line, with the decision it needs (engineering change or legal);
- Amber and Green counts;
- the outstanding obligations (source offers, notices);
- what couldn't be assessed;
- where the files are.

Remind them that the notices file and SBOM are drafts for compliance review, and that this isn't legal advice.

If the user then wants Reds removed (e.g. replacing a GPL library), that's code work. Treat it like any change: one item at a time, with their approval. Never delete third-party code or rewrite git history on your own initiative.
