# Open-source licence review — 2025 eCTF insecure example decoder (MITRE reference design)

**Date:** 2026-11-20 19:44 · **Generated:** 2026-11-20 19:50 GMT (UTC+0000) · **Version:** 2025 reference design (tools package 2025.01.15; no git metadata in the reviewed copy) · **Reviewer:** ./phazeOne amygdala:oss  
**Platform:** Analog Devices MAX78000 (FTHR_RevA) bare-metal decoder firmware · ADI MSDK v2024_02 · GNU Arm GCC in a Docker build container · host-side Python design and tool packages (detection confidence: high)  
**Scope:** 40 first-party files, ~4,060 lines in `decoder/src/`, `decoder/inc/`, `decoder/project.mk`, `decoder/firmware.ld`, `design/`, `tools/`, `frames/`

## 🟠 Verdict: CONDITIONAL — OBLIGATIONS OR DECISIONS OUTSTANDING

No Red issues. 5 Amber issue(s) need their obligations met or a recorded decision before distribution.

| 🔴 Red | 🟠 Amber | 🟢 Green | Total |
|---|---|---|---|
| **0** | **5** | **4** | 9 |

## Summary

MITRE's 2025 eCTF insecure example is a small MAX78000 decoder firmware plus host-side Python tooling, released by MITRE under Apache-2.0. In the code that is actually in the repository nothing blocks distribution: there is no GPL, LGPL or AGPL code, and the Maxim startup file that ScanCode marks as 'proprietary' is a permissive MIT-style licence. The open items are about what the repository does not contain: the ADI MSDK is downloaded and linked at build time and was not scanned, there is no third-party notices file or SBOM for the firmware, and the optional wolfSSL crypto example would statically link GPL code into the firmware if anyone turns it on.

**Key risks**

- Turning on the eCTF Crypto Example (CRYPTO_EXAMPLE=1) compiles wolfSSL (GPL-3.0-or-later unless you buy a commercial licence) into the firmware image. That would become a Red: copyleft over the whole image, plus GPLv3 installation information on a locked-boot device.
- The ADI MSDK v2024_02 libraries linked into the firmware are downloaded at build time and were not scanned, so their licences and notices are not confirmed.
- No third-party notices file ships with the firmware, although Apache-2.0 (MITRE code, and probably the MSDK) and the Maxim MIT-style startup licence both require notices to go with binary distributions.
- Every source file says it is 'provided only for educational purposes for the 2025 MITRE eCTF competition'. Anyone reusing the code commercially should record how that statement relates to the Apache-2.0 grant.

**What is working well**

- A single, clear project licence: Apache-2.0 in LICENSE.txt, with MITRE's public-release approval (Case 24-03351-Code).
- Consistent MITRE copyright headers on every first-party source file.
- GPL wolfSSL is kept out of the repository (gitignored), and the crypto example that uses it is off by default.
- Third-party Maxim files keep their original copyright and licence headers intact.
- The build environment is defined in a Dockerfile, so the toolchain and SDK version (MSDK v2024_02) can be identified and audited.

## RAG scorecard

| Area | Rating | R | A | G | Coverage |
|---|---|---|---|---|---|
| Strong copyleft (GPL family) | 🟠 AMBER | 0 | 1 | 1 | Partial — Repository scanned with ScanCode 32.5.0 and license_scan.py: no GPL code found. No linker map exists, so firmware linkage is inferred from the Makefile. The MSDK and the toolchain C runtime (newlib-nano, libgcc) are linked but were not in the repository. |
| Network copyleft (AGPL / SSPL) | 🟢 GREEN | 0 | 0 | 0 | Reviewed — No network services. No AGPL or SSPL found in the repository or in the declared Python dependencies. Host tooling is assumed internal. |
| Weak copyleft (LGPL / MPL / EPL) | 🟢 GREEN | 0 | 0 | 1 | Partial — Only tqdm (MPL-2.0 AND MIT) in internal host tooling, used unmodified. The MSDK was not scanned. Python dependency licences come from known public metadata; there is no lockfile and nothing installed to check against offline. |
| GPLv3 vs locked boot / signed images | 🟡 PARTIAL | 0 | 0 | 0 | Partial — Locked boot assumed (eCTF bootloader). No GPLv3 or LGPLv3 code is compiled into the default build; libgcc's GCC Runtime Library Exception applies. wolfSSL (GPLv3) would trigger this if enabled. MSDK not scanned. |
| No licence / copied code | 🟢 GREEN | 0 | 0 | 1 | Reviewed — Every repository file falls under LICENSE.txt or carries its own Maxim licence header. No snippet or 'copied from' comments found. |
| Vendor & non-commercial terms | 🟠 AMBER | 0 | 2 | 0 | Partial — The Maxim startup and Makefile licences were read in full. The MSDK's own terms were not checked because it is not in the repository. Usage-restriction wording in the MITRE headers is raised as a finding. |
| Licence conflicts | 🟡 PARTIAL | 0 | 0 | 0 | Partial — No conflict found among Apache-2.0, the Maxim MIT-style licence, newlib and libgcc (with its exception). The MSDK combination is unconfirmed. |
| Embedded Linux source obligations | 🟢 GREEN | 0 | 0 | 0 | Reviewed — Not applicable: bare-metal MCU firmware, no embedded Linux image. The Ubuntu Docker image is a build environment only and is not distributed with the device. |
| Attribution & notices | 🟠 AMBER | 0 | 1 | 1 | Reviewed — No NOTICE or third-party notices file in the repository. A draft THIRD_PARTY_NOTICES.md was generated, and it has gaps for the MSDK, newlib and libgcc texts. |
| SBOM & compliance process | 🟠 AMBER | 0 | 1 | 0 | Reviewed — No SBOM or compliance process found in the repository. A draft CycloneDX 1.5 SBOM was generated from the confirmed component list. |

## Findings

### 🟠 Amber — Obligations to meet or decision needed

#### OSS-001

**🟠 AMBER · Optional wolfSSL crypto example would statically link GPL code into the firmware**

**Area:** Strong copyleft (GPL family) · **Location:** `decoder/Makefile:174` · **Confidence:** likely · **Effort:** S · **Origin:** Third-party component

> Third-party component: a published vulnerability or defect in a library this product uses, not in the code under review. The description states whether it is compiled in and reachable here.

**References:** GPL-3.0 §5(c) whole work, GPL-3.0 §6 Installation Information (User Products), wolfSSL dual licensing (GPL / commercial)

**What's wrong.** The reference design includes an optional 'eCTF Crypto Example' (simple_crypto.c/.h) built on wolfCrypt. It is off by default (CRYPTO_EXAMPLE=0), and wolfSSL is not in the repository: the README tells developers to download it into decoder/wolfssl/, and .gitignore excludes that directory. If it is turned on, the Makefile adds wolfssl/wolfcrypt/src to VPATH, and MSDK auto-search compiles those sources straight into the single statically linked MAX78000 image. wolfSSL is dual-licensed: GPL-3.0-or-later for current releases (GPL-2.0-or-later before 5.6.6), or a commercial licence from wolfSSL Inc.

**Field impact.** In the default build: no exposure. With the crypto example on under the GPL option, distributing the firmware would mean offering the complete corresponding source of the whole image (MITRE code, MSDK and wolfSSL) under GPL-3.0. On a device that only boots signed or packaged images, GPL-3.0 section 6 also requires the Installation Information needed to install modified firmware. Either of these would make this a Red.

```c
ifeq ($(CRYPTO_EXAMPLE), 1)
VPATH += wolfssl/wolfcrypt/src
...
#include "wolfssl/wolfcrypt/aes.h"
# project.mk: CRYPTO_EXAMPLE=0
```

**Also at:** `decoder/project.mk`, `decoder/inc/simple_crypto.h:18`, `decoder/src/simple_crypto.c:14`, `README.md:13`, `.gitignore:323`

**Recommendation.** Decide this now and record it. Either (a) keep CRYPTO_EXAMPLE=0 and enforce it, for example a CI check that fails if decoder/wolfssl/ exists or CRYPTO_EXAMPLE=1 in a release build; or (b) buy a wolfSSL commercial licence before enabling it; or (c) use a permissive crypto library instead, such as Mbed TLS / TF-PSA-Crypto (Apache-2.0), Monocypher (BSD-2-Clause or CC0) or tinycrypt (BSD-3-Clause), or the MAX78000's hardware AES/TRNG drivers from the MSDK.

#### OSS-002

**🟠 AMBER · ADI MSDK v2024_02 is linked into the firmware but downloaded at build time and not scanned**

**Area:** Vendor & non-commercial terms · **Location:** `decoder/Dockerfile:30` · **Confidence:** needs-verification · **Effort:** S · **Origin:** Third-party component

> Third-party component: a published vulnerability or defect in a library this product uses, not in the code under review. The description states whether it is compiled in and reachable here.

**References:** Apache-2.0 §4, ADI MSDK licence files (to be confirmed)

**What's wrong.** The firmware links CMSIS device startup/system files, the MAX78000 peripheral drivers (flc, icc, uart, nvic_table, mxc_delay) and the FTHR_RevA board support package (LIB_BOARD and LIB_PERIPHDRIVERS are on by default), all from the Analog Devices MSDK. The Dockerfile fetches the MSDK at build time, so none of it is in the repository and neither scanner could check it. Most MSDK files are expected to be Apache-2.0, with some older Maxim MIT-style headers and Arm's Apache-2.0 CMSIS. Vendor SDKs can also carry use-with-vendor-silicon terms. That condition would be met here (the target is ADI's own MAX78000), but it has not been confirmed.

**Field impact.** The largest third-party part of the shipped image has unconfirmed licences and attributions. If any linked MSDK file is under a more restrictive or vendor-only licence, that is not known. Apache-2.0 §4 notice obligations for the MSDK are not being met at the moment (see OSS-003).

```c
wget https://github.com/analogdevicesinc/msdk/archive/refs/tags/v2024_02.zip
ENV MAXIM_PATH=/root/msdk-2024_02
...
include $(LIBS_DIR)/libs.mk
```

**Also at:** `decoder/Makefile:401`, `decoder/Makefile:409`, `decoder/project.mk`

**Recommendation.** Run ScanCode over msdk-2024_02/Libraries (at least CMSIS/Device/Maxim/MAX78000, PeriphDrivers and Boards/MAX78000/FTHR_RevA) together with a linker map from 'make release' (pass it with --map), then update confirmed_components.json with the concluded licences and licence-file paths and regenerate the notices and SBOM. Record any ADI use-restriction text from the MSDK licence files.

#### OSS-004

**🟠 AMBER · 'Educational purposes only' wording in every source header sits beside the Apache-2.0 grant**

**Area:** Vendor & non-commercial terms · **Location:** `decoder/src/decoder.c:8` · **Confidence:** needs-verification · **Effort:** S

**References:** Apache-2.0 §2 (grant), Apache-2.0 §7 (disclaimer of warranty)

**What's wrong.** All 26 MITRE-authored source files carry this statement and a MITRE copyright line, but no licence identifier. The root LICENSE.txt grants Apache-2.0 with 'Approved for Public Release; Distribution Unlimited', so read in context the statement is most likely a quality and warranty disclaimer, not an extra licence condition. Read on its own, though, 'provided only for educational purposes' can be taken as a field-of-use restriction, and no file states which governs.

**Field impact.** For the eCTF competition itself: none. For anyone reusing this code in a commercial product: an unresolved question about whether non-educational use is permitted. That needs a recorded position before the code ships outside the competition.

```c
This code is being provided only for educational purposes for the 2025 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
```

**Also at:** `decoder/src/host_messaging.c:8`, `decoder/src/simple_crypto.c:8`, `decoder/src/simple_flash.c:8`, `decoder/src/simple_uart.c:8`, `decoder/inc/`, `design/ectf25_design/`, `tools/ectf25/`, `LICENSE.txt`

**Recommendation.** If you reuse this code commercially, record a position from legal, ideally backed by written confirmation from MITRE that Apache-2.0 governs and the header text is a disclaimer. If you maintain a fork, add 'SPDX-License-Identifier: Apache-2.0' to each first-party file so the grant sits next to the wording.

#### OSS-003

**🟠 AMBER · No third-party notices ship with the firmware binary**

**Area:** Attribution & notices · **Location:** `LICENSE.txt` · **Confidence:** confirmed · **Effort:** S

**References:** Apache-2.0 §4(a), §4(c), Maxim Integrated MIT-style licence (notice condition), newlib COPYING.NEWLIB

**What's wrong.** The firmware image (max78000.bin / .elf) combines MITRE Apache-2.0 code, the Maxim MIT-style startup file, the MSDK (probably Apache-2.0) and newlib-nano (BSD-style per-file notices). The repository has no NOTICE file, no THIRD_PARTY_NOTICES file and no documented place where these notices go with the binary. LICENSE.txt covers only the MITRE code.

**Field impact.** Distributing the binary without these notices does not meet Apache-2.0 §4(a) (give recipients a copy of the licence), the Maxim licence condition (the copyright notice and permission notice must be included in all copies or substantial portions) or newlib's BSD-style attribution conditions. This is easy to fix, but it is an obligation.

**Also at:** `decoder/startup_firmware.S:3`, `README.md`

**Recommendation.** Review and complete the generated draft THIRD_PARTY_NOTICES.md: add the MSDK, newlib and libgcc licence texts it marks as missing, and cut the Maxim entry down to its licence header. Ship it with every firmware release (release bundle, product documentation or a support web page).

#### OSS-005

**🟠 AMBER · No SBOM, and the build pulls the SDK and base image by mutable reference**

**Area:** SBOM & compliance process · **Location:** `decoder/Dockerfile:5` · **Confidence:** confirmed · **Effort:** M

**References:** EU CRA Annex I Part II (1) SBOM, CycloneDX 1.5

**What's wrong.** There is no SBOM and no compliance process in the repository. The build image tracks the moving ubuntu:24.04 tag and installs unpinned apt packages, including the toolchain that supplies newlib and libgcc. The MSDK zip is fetched with no checksum, and the Python dependencies are unpinned with no lockfile. So the exact third-party content of a given firmware build cannot be reproduced or listed afterwards.

**Field impact.** Release-by-release notices and SBOMs cannot be shown to be accurate. Under the EU Cyber Resilience Act, a manufacturer placing a product like this on the EU market must keep an SBOM of at least its top-level dependencies.

```c
FROM ubuntu:24.04
RUN apt-get update && apt-get upgrade -y && apt-get install -y ...
wget https://github.com/analogdevicesinc/msdk/archive/refs/tags/v2024_02.zip
```

**Also at:** `decoder/Dockerfile:30`, `design/pyproject.toml`, `tools/pyproject.toml`

**Recommendation.** Pin the base image by digest and the apt toolchain packages by version, verify the MSDK zip against a recorded SHA-256, and add a lockfile (pip-tools or uv) for the host packages. Regenerate sbom.cdx.json for each release from a linker map and a confirmed component list; the draft produced by this review is a starting point.

### 🟢 Green — Tidy-up

#### OSS-007

**🟢 GREEN · Build container toolchain is GPL but build-only; linked runtime is covered by exceptions**

**Area:** Strong copyleft (GPL family) · **Location:** `decoder/Dockerfile:15` · **Confidence:** likely · **Effort:** S · **Origin:** Third-party component

> Third-party component: a published vulnerability or defect in a library this product uses, not in the code under review. The description states whether it is compiled in and reachable here.

**References:** GCC Runtime Library Exception 3.1, newlib COPYING.NEWLIB

**What's wrong.** GCC, binutils, gdb, make, libtool and texinfo (GPL family) run only inside the build container and never ship. What reaches the image from the toolchain is libgcc (GPL-3.0-or-later WITH GCC-exception-3.1) and newlib-nano (mostly BSD-style). The exception allows linking libgcc into proprietary firmware, and newlib only needs attribution. The container image is not distributed to device recipients.

**Field impact.** No copyleft obligation on the firmware from the toolchain, provided the build container itself is not handed to customers or contract manufacturers. If it is, that is distribution of GPL programs, and the source-offer obligations apply.

```c
apt-get install -y gdb gdb-multiarch gcc-arm-none-eabi binutils-arm-none-eabi make python3.10 git wget libtool texinfo unzip
```

**Recommendation.** No change needed. Add the newlib and libgcc licence texts to the notices (OSS-003). If the Docker image is ever given to third parties, provide the Ubuntu source packages or a written offer.

#### OSS-008

**🟢 GREEN · Host Python dependencies are permissive or file-level copyleft and stay internal**

**Area:** Weak copyleft (LGPL / MPL / EPL) · **Location:** `tools/pyproject.toml` · **Confidence:** needs-verification · **Effort:** S · **Origin:** Third-party component

> Third-party component: a published vulnerability or defect in a library this product uses, not in the code under review. The description states whether it is compiled in and reachable here.

**References:** MPL-2.0 §3.2, MIT, BSD-3-Clause

**What's wrong.** The host packages depend on loguru (MIT), pyserial (BSD-3-Clause), tqdm (MPL-2.0 AND MIT) and psutil (BSD-3-Clause), plus setuptools at build time. These licences come from the packages' published metadata. Versions are unpinned and nothing was installed, so they were not checked against the actual dist-info files. In this review design/ and tools/ are internal host tooling, so these dependencies are not distributed.

**Field impact.** None while the tooling stays internal. If design/ or tools/ is ever given to customers or a factory, tqdm's MPL-2.0 files need source availability for any modifications (none are made), and every package needs its notice.

```c
dependencies = [
    "loguru",
    "pyserial",
    "tqdm",
    "psutil"
]
```

**Also at:** `design/pyproject.toml`

**Recommendation.** Run 'pip-licenses --with-license-file' in the installed venv to confirm, and pin versions in a lockfile (OSS-005). Re-rate if the host tooling becomes a deliverable.

#### OSS-006

**🟢 GREEN · Maxim startup file flagged 'proprietary' by ScanCode is a permissive MIT-style licence**

**Area:** No licence / copied code · **Location:** `decoder/startup_firmware.S:3` · **Confidence:** confirmed · **Effort:** S · **Origin:** Third-party component

> Third-party component: a published vulnerability or defect in a library this product uses, not in the code under review. The description states whether it is compiled in and reachable here.

**References:** MIT, ScanCode known false positive: 'All Rights Reserved' / IP-retention clause in permissive text

**What's wrong.** ScanCode reports 'MIT AND LicenseRef-scancode-proprietary-license' for both Maxim files. Reading the header confirms it is the MIT permission text plus two extra clauses: Maxim's name may only be used as its Branding Policy allows, and transferring the software grants no other IP. Neither restricts use, modification or redistribution of the code. startup_firmware.S is compiled into the firmware (STARTUPFILE in project.mk) and has been adapted for the eCTF bootloader entry point; the Makefile is build-only. These files are under Maxim's licence, not the repository's Apache-2.0.

**Field impact.** No distribution blocker. The only obligation is to keep the Maxim copyright and permission notice with the firmware (covered by OSS-003) and not use Maxim's name beyond what its branding policy allows.

```c
 * Copyright (C) 2023 Maxim Integrated Products, Inc., All Rights Reserved.
 * Permission is hereby granted, free of charge, ...
 * The mere transfer of this software does not imply any licenses
 * of trade secrets, proprietary technology, copyrights, patents, ...
```

**Also at:** `decoder/Makefile:2`

**Recommendation.** Record the concluded licence (MIT-style with Maxim branding and IP clauses) in the component list, as done in confirmed_components.json, so future scans don't escalate it. Keep the headers intact in any fork.

#### OSS-009

**🟢 GREEN · First-party files and Python packages don't declare their licence**

**Area:** Attribution & notices · **Location:** `design/pyproject.toml` · **Confidence:** confirmed · **Effort:** S

**References:** SPDX specification, PEP 639

**What's wrong.** None of the 26 MITRE-authored files carries an SPDX-License-Identifier. Neither pyproject.toml declares a licence, so pip-installed metadata for ectf25 and ectf25_design shows no licence. The licence is only established by the root LICENSE.txt.

**Field impact.** Hygiene only. Scanners and downstream SBOM tools report these packages as having no licence data, and files copied out of the repository lose their licence context.

```c
[project]
name = "ectf25_design"
version = "2025.0+example"
# (no license / license-files field)
```

**Also at:** `tools/pyproject.toml`, `decoder/src/decoder.c:1`

**Recommendation.** Add 'SPDX-License-Identifier: Apache-2.0' to first-party headers, and 'license = "Apache-2.0"' plus 'license-files = ["LICENSE.txt"]' to both pyproject.toml files.

## Recommended next steps

1. Build once with 'make release' and keep the linker map; rerun the scan with --map and include msdk-2024_02/Libraries to close OSS-002 and the partial coverage areas.
2. Record the wolfSSL decision (keep disabled, commercial licence, or permissive replacement) and enforce it in CI (OSS-001).
3. Complete and ship THIRD_PARTY_NOTICES.md with each firmware release (OSS-003).
4. Get a legal position on the 'educational purposes only' header wording before any commercial reuse (OSS-004).
5. Pin the build inputs and generate an SBOM per release (OSS-005).
6. Treat the notices file and SBOM produced here as drafts for compliance review.

## Coverage and method

| Tool | Status | Notes |
|---|---|---|
| license_scan.py | ran | 40 files and 3 components (root, design, tools). It flagged the root as 'proprietary' because of the Maxim files; that is a confirmed false positive. It did not list the pyproject dependencies, which ScanCode did. |
| ScanCode Toolkit 32.5.0 | ran | Run with --license --copyright --package --info and exited 0 with no errors. It found Apache-2.0 (LICENSE.txt) and MIT AND LicenseRef-scancode-proprietary-license (decoder/Makefile, decoder/startup_firmware.S; the proprietary part is the Maxim IP-retention clause, a known false-positive pattern), MITRE copyright on 26 source files, 2 PyPI packages and 4 distinct dependencies (loguru, pyserial, tqdm, psutil). It found no licence on the dependencies. |
| Linker map | not_available | No build output in the repository (*.map is gitignored). Linkage is inferred from decoder/Makefile and decoder/project.mk. |
| pip-licenses / Python lockfile | not_available | No lockfile and no installed environment. Dependency licences come from known public metadata and need confirming. |
| make_outputs.py | ran | Draft THIRD_PARTY_NOTICES.md (5 shipped components, 3 without licence text in the repository) and sbom.cdx.json (19 components). |

Excluded (vendored / generated): `ADI MSDK v2024_02 (downloaded inside the Docker build at build time; not present in the repository, so not scanned)`, `decoder/wolfssl/ (optional crypto example library; not present, gitignored)`, `Ubuntu 24.04 toolchain packages (inside the build container; not present)`. Third-party code was assessed for versions and configuration, not line-by-line.

**RAG key:** 🔴 Red — Blocks distribution until resolved · 🟠 Amber — Obligations to meet or decision needed · 🟢 Green — Tidy-up · 🟡 Partial — partly reviewed, nothing found · ⚪ Not assessed — not reviewed.

_Automated and AI-assisted licence triage. Not legal advice. Red items and all distribution decisions should be confirmed by your open-source compliance owner or legal counsel._

## Acknowledgements

- Analysis tools used for this report: ScanCode Toolkit (AboutCode).
- Classification, checklists and regulatory mapping draw on MITRE CWE, SEI CERT C, MISRA C, ETSI EN 303 645, EN 18031, NIST IR 8425, the OWASP Agentic Skills Top 10, SPDX and CycloneDX.
- Typeface: IBM Plex Mono by IBM (SIL Open Font License 1.1).
- Produced with the ./phazeOne open-source licence review skill for Claude Code. Our thanks to the maintainers of every project above.

---
Prepared by **./phazeOne** — IoT, Firmware and Hardware Solutions. https://www.phazeone.com/ · Need help with these findings? [Get in touch](https://www.phazeone.com/contact) · +44 (0) 1280 811117 · hello@phazeone.com
