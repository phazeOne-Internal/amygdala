# Acknowledgements

These skills stand on a lot of other people's work. Nothing below is bundled in this repository; the tools are invoked if the user has installed them, and the standards and guidance are referenced. Thank you to everyone who maintains them.

## Analysis tools the skills run

| Tool | Used by | What it adds | Licence |
|---|---|---|---|
| [Cppcheck](https://cppcheck.sourceforge.io/) | amygdala:review, amygdala:fix | General C/C++ defect detection without a build | GPL-3.0-or-later |
| [clang-tidy](https://clang.llvm.org/extra/clang-tidy/) (LLVM project) | amygdala:review, amygdala:fix | Semantic checks and the Clang static analyzer, when a `compile_commands.json` exists | Apache-2.0 with LLVM exceptions |
| [Flawfinder](https://dwheeler.com/flawfinder/) by David A. Wheeler | amygdala:review, amygdala:fix | CWE-tagged scan of risky C library calls | GPL-2.0-or-later |
| [Semgrep](https://semgrep.dev/) (CLI engine) | amygdala:review, amygdala:fix | Runs our bundled embedded-C rules locally, metrics off | LGPL-2.1 (engine). The rules in `assets/semgrep/embedded-c.yml` are our own |
| [ScanCode Toolkit](https://github.com/aboutcode-org/scancode-toolkit) by nexB / AboutCode | amygdala:oss | Licence and copyright detection in source and packages | Apache-2.0 (code), CC-BY-4.0 (licence data) |
| [OSV.dev](https://osv.dev/) (Google / OpenSSF) | amygdala:review (opt-in) | Published-vulnerability lookup for third-party dependencies by repository and tag | API free of charge; advisory data under each source's licence, mostly CC-BY 4.0, CC0 or Apache-2.0 |
| [pipx](https://pipx.pypa.io/) | amygdala:oss installer | Isolated per-user install of ScanCode | MIT |
| [Python](https://www.python.org/) | all | All bundled scripts are standard-library Python 3 | PSF-2.0 |

Running a tool as a separate process does not make the skills derivative works of it; each tool keeps its own licence and we redistribute none of them. OSV.dev is a web service rather than a tool we run; it is called only with the user's consent, as described in SECURITY.md.

## Formats and identifiers

- [CycloneDX](https://cyclonedx.org/) (OWASP) for the SBOM produced by amygdala:oss. Specification under Apache-2.0.
- [SPDX licence identifiers](https://spdx.org/licenses/) (Linux Foundation) for naming licences in findings and notices. Licence list data under CC0-1.0.
- [CWE](https://cwe.mitre.org/) (MITRE) identifiers for weakness classification in findings. Used under the CWE terms of use.

## Standards and guidance the checklists draw on

- [ETSI EN 303 645](https://www.etsi.org/) Cyber Security for Consumer Internet of Things, and the EN 18031 series for the EU Radio Equipment Directive.
- The EU Cyber Resilience Act (Regulation (EU) 2024/2847), the UK Product Security and Telecommunications Infrastructure Act 2022, the Australian Cyber Security Act 2024, Singapore CLS and Japan JC-STAR, as summarised in `references/regulatory.md`. These are engineering guidance, not legal advice.
- [NIST IR 8425](https://csrc.nist.gov/) and NIST IR 8259A/B for the US consumer IoT baseline.
- SEI [CERT C Coding Standard](https://wiki.sei.cmu.edu/confluence/display/c) and MISRA C, cited as the reason a pattern is risky. MISRA rules are referenced by number only; no MISRA text is reproduced.
- [OWASP Agentic Skills Top 10](https://github.com/OWASP/www-project-agentic-skills-top-10) (CC BY-SA 4.0), which shaped the security rules in each SKILL.md and SECURITY.md.
- Vendor documentation for the platforms the skills recognise: Infineon ModusToolbox and PSoC 6, Zephyr and nRF Connect, Espressif ESP-IDF, STMicroelectronics STM32Cube, NXP MCUXpresso, FreeRTOS and MCUboot. Product names are trademarks of their owners.

## Design

- [IBM Plex Mono](https://github.com/IBM/plex) by IBM, under the SIL Open Font License 1.1, loaded from Google Fonts when a report is opened. The report falls back to the system monospace font offline.
- The report layout follows [phazeone.com](https://www.phazeone.com/). The ./phazeOne name, logo and hero artwork belong to ./phazeOne and are not covered by this repository's licence.

## Runtime

- [Claude Code](https://claude.com/claude-code) by Anthropic, which runs the skills. The skills follow Anthropic's SKILL.md format.

If we have missed a project you maintain, or stated a licence wrongly, please tell us at hello@phazeone.com and we will correct it.
