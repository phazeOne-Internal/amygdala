# Licence risk: classification and RAG rules

Risk depends on three things together: **which licence**, **how the code is combined with yours** (see `linkage.md`), and **how it is distributed** (shipped in a device or app, or only used to build). The same GPL library is Red when it's statically linked into firmware, and Green when it's a build script that never leaves the build server.

This is engineering triage, not legal advice. Every Red should go to whoever owns open-source compliance or legal. The report's job is to make their review fast and complete.

## Licence families

| Family | Examples | What it requires, in short |
|---|---|---|
| **Network copyleft** | AGPL-3.0, SSPL-1.0 | Like GPL, plus source must be offered to users who interact with it **over a network**. Affects cloud services and back-ends, even if never "distributed". SSPL extends this to the whole service stack and is generally treated as unacceptable for commercial use. |
| **Strong copyleft** | GPL-2.0, GPL-3.0, EUPL-1.2, OSL-3.0, CC-BY-SA (for code) | Distributing a program that includes or links the code requires distributing the **complete corresponding source of the combined work** under the same licence. GPL-3.0 also requires **installation information** for "User Products" (see below) and has an explicit patent licence. |
| **Weak copyleft (library)** | LGPL-2.1, LGPL-3.0 | You may link from proprietary code, **but** the user must be able to replace/relink the LGPL part (provide object files or dynamic linking), plus source for the LGPL part and any changes to it. LGPL-3.0 inherits GPL-3.0's installation-information rule. |
| **Weak copyleft (file)** | MPL-2.0, EPL-1.0/2.0, CDDL-1.0 | Copyleft applies to the **files** of that component. Modified files must be made available in source; your other files are unaffected. Larger works may combine freely. |
| **Non-commercial** | CC-BY-NC, "for non-commercial use only", many "free for evaluation" licences | **Not usable in a commercial product at all** without a separate licence. |
| **Restricted / vendor** | Infineon/Cypress EULA, Nordic 5-Clause, Permissive Binary License, ST SLA0044, Espressif licences for blobs, "may only be used with <vendor> devices" | Usually fine for the product they were written for, but check: use restricted to the vendor's silicon, redistribution in binary only, no reverse engineering, attribution. A port to another MCU can breach them. |
| **Proprietary / unknown** | "All rights reserved", "Confidential", no licence at all, code copied from a website or forum | **No licence means no permission.** Code with no licence, or under a proprietary licence you haven't purchased, can't legally be shipped. |
| **Permissive** | MIT, BSD-2/3-Clause, Apache-2.0, ISC, Zlib, BSL-1.0, PSF | Free to use in closed products. Obligations: **keep copyright and licence notices** (in documentation shipped with the product, for binaries); Apache-2.0 also requires reproducing any NOTICE file and stating changes, and has a patent termination clause. |
| **Public domain** | Unlicense, CC0 | No obligations, but some jurisdictions don't recognise public-domain dedication. Usually fine. |

**Exceptions change everything.** `GPL-2.0 WITH Linux-syscall-note`, `GPL-3.0 WITH GCC-exception-3.1` (libgcc, libstdc++), `GPL-2.0 WITH Classpath-exception-2.0`, eCos, `Autoconf-exception`, `Bison-exception` and similar exceptions can make otherwise-copyleft code safe to link into proprietary programs. Read the exception text, and rate the component on its actual terms.

**Dual / multi-licensing:** `MIT OR GPL-2.0` means you may choose MIT; record which licence you rely on. `A AND B` means both apply.

**"or later":** `GPL-2.0-or-later` lets the recipient use GPL-3.0 terms. `GPL-2.0-only` code can't be combined with GPL-3.0-only code (licence conflict).

## RAG rules

### 🔴 Red: blocks distribution until resolved (legal or engineering)
- **Strong or network copyleft code compiled or statically linked into proprietary firmware or a proprietary app** (GPL in an MCU image; GPL library in an iOS/Android app; AGPL in a back-end that users reach over the network).
- **GPL-3.0 / LGPL-3.0 code in a device with locked secure boot or a read-only, signed rootfs**, if no installation information can be provided ("anti-tivoisation"). This is the classic consumer IoT conflict. GPL-2.0 has no such clause.
- **LGPL code statically linked into an MCU image or iOS app** with no relinking provision (object files plus instructions). On MCUs this is usually impractical, so treat it as Red unless the vendor gives an explicit static-linking exception.
- **Proprietary kernel module** (`MODULE_LICENSE("Proprietary")`) in an embedded Linux product: it taints the kernel, can't use GPL-only symbols, and is a GPL compliance risk. Also any kernel code changes without a source-offer plan.
- **Non-commercial or "evaluation only" licence** in a shipped product.
- **No licence / unknown provenance** for code that ships: copied snippets with no licence, a third-party directory with no licence file, code from forum posts (Stack Overflow answers are CC-BY-SA, which is copyleft and needs attribution).
- **Licence conflict:** e.g. GPL-2.0-only combined with Apache-2.0 or GPL-3.0-only in one linked program.
- **Vendor licence breached:** e.g. Infineon/Cypress or Nordic code used on a non-vendor MCU, or a "Nordic devices only" library in a product without that chip.

### 🟠 Amber: fix or obtain a decision before release
- **GPL/LGPL components shipped as separate programs or dynamically linked** (BusyBox, Linux kernel, glibc in an embedded Linux image). This is allowed, but obligations apply: written source offer or source on the media, licence texts, build/installation scripts for the kernel. Rate Amber until there's evidence the compliance process exists (e.g. Yocto `archiver` class, Buildroot `legal-info`, a published source tarball).
- **File-level copyleft (MPL/EPL/CDDL) with local modifications:** modified files must be released.
- **Permissive components with missing attribution:** no licence text or NOTICE shipped in the product documentation, or "About" screen / notices file absent.
- **Declared licence and file headers disagree** (e.g. the manifest says MIT, a file says GPL). The component needs a proper check.
- **Copyleft in build tools or tests that might get distributed** (e.g. GPL scripts packed into an SDK you give customers, or a GPL tool bundled in a firmware-update utility).
- **Licence unknown for a declared dependency** (manifest lists it but no licence data). Resolve from the registry or lockfile.
- **Apache-2.0 with modifications but no change notices.** **Patent-retaliation interplay** worth legal awareness (e.g. Apache-2.0 alongside GPL-2.0-only is a conflict, so check combinations).

### 🟢 Green: tidy-up
- Permissive components where attribution is in place.
- Copyleft code used only as build tooling that never leaves your build environment (GCC itself, Kconfig scripts, Python build helpers).
- Missing SPDX tags on first-party files (hygiene; helps future scans).
- Minor inconsistencies in notices.

## Process / evidence items (usually Amber, `needs-verification`)
- Is there an open-source policy and an owner?
- Written source offer process for GPL/LGPL components (embedded Linux)?
- Third-party notices shipped with the product (manual, app "About" screen, web page)?
- SBOM generated per release (also required by the EU CRA)?
- Contributor/vendor agreements for code written by contractors (who owns it)?
