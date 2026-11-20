# Linkage and distribution, per product type

Copyleft obligations attach to what is **distributed** (or, for AGPL, made available over a network), and how much of your code they reach depends on **how the code is combined**. Before rating a component, answer: does it ship, and how is it combined with our code?

Contents: MCU firmware · Embedded Linux · Mobile apps · Desktop / cloud / back-end · Evidence sources

## MCU firmware (PSoC 6 / ModusToolbox, Zephyr, FreeRTOS, ESP-IDF, bare metal)

- **Everything that is compiled is statically linked into one image.** There is no "dynamic linking" escape. Any GPL code compiled in makes the whole image a combined work. LGPL code needs relinking support, which is impractical on MCUs, so treat it like GPL unless there's an explicit exception.
- **What actually gets compiled:**
  - **ModusToolbox:** the build auto-discovers sources under the application and every library in `mtb_shared`/`libs`, filtered by `COMPONENTS`, `DISABLE_COMPONENTS`, `TARGET_`/`COMPONENT_`/`TOOLCHAIN_` directory naming and `CY_IGNORE`. Directories named `COMPONENT_XYZ` are only built when `XYZ` is in `COMPONENTS`. A GPL file in a library's `COMPONENT_FOO/` folder isn't built unless `FOO` is enabled.
  - **Zephyr / nRF Connect:** modules from `west.yml` are only built when their Kconfig option is enabled (`prj.conf`, board defconfig). Many Zephyr modules (e.g. some HALs, `hal_*`, `mbedtls`, `tinycrypt`) are Apache-2.0/BSD; check each enabled one. Zephyr's own `scripts/` contain GPL tools that are build-only.
  - **ESP-IDF:** components in `components/` and `managed_components/` are built if they're required (`REQUIRES`/`PRIV_REQUIRES`) or are `COMPONENTS`-listed.
  - **CMake / Make:** `target_sources`, `SRCS`, `OBJS`.
- **Best evidence: the linker map** (`build/<target>/<config>/<app>.map` for ModusToolbox, `build/zephyr/zephyr.map`, `build/<proj>.map` for ESP-IDF). It lists every object and archive member that was pulled into the image. Pass it to `license_scan.py --map`. If no build exists, say "linkage inferred from build configuration".
- **Toolchain runtime:** libgcc, libstdc++ (GCC Runtime Library Exception: OK), newlib / newlib-nano (mostly BSD-style, a few files under other licences, generally considered fine), picolibc (BSD). The ARM GCC toolchain itself is GPL, but it's a build tool. Note which C library is used; don't flag it Red.
- **Binary blobs:** Wi-Fi/BT firmware (e.g. CYW43xxx `.bin`/`clm_blob`, Nordic SoftDevice, Espressif PHY libs) are shipped inside or alongside the image under vendor licences. Check redistribution terms, then list them in the notices and SBOM.
- **Bootloaders:** MCUboot is Apache-2.0. Vendor secure bootloaders are vendor-licensed. A GPL bootloader such as U-Boot (GPL-2.0+) is usually a separate program, Amber with source obligations, unless it's linked with your code.
- **Secure boot + GPL-3.0:** if any GPL-3.0/LGPL-3.0 code ships in a device whose boot chain refuses unsigned images, the installation-information requirement bites (consumer "User Products"). That's Red unless legal has a position.

## Embedded Linux (Yocto, Buildroot, OpenWrt, vendor BSPs)

- **The Linux kernel** is GPL-2.0-only (`WITH Linux-syscall-note` for UAPI headers, so userspace programs aren't affected by using syscalls). Obligations: provide the complete corresponding source of the kernel you ship, including your patches, config, device trees and any GPL modules, with a written offer or alongside. Typically Amber until the process exists.
- **Kernel modules:** out-of-tree modules are generally considered derivative works. `MODULE_LICENSE("GPL")` (or the dual variants) is fine with source obligations. **`MODULE_LICENSE("Proprietary")` or a missing licence is Red**: it needs a legal decision and taints the kernel.
- **Userspace:** separate programs (BusyBox, systemd, OpenSSH) communicate with your code via exec, pipes or sockets, so their GPL doesn't extend to your separate programs. Obligations for each GPL program still apply: source offer, licence text.
- **Libraries:**
  - **Proprietary program dynamically linking an LGPL library** (glibc, many GUI libs): OK, with obligations (allow replacement, licence text, source of the LGPL library). If the rootfs is read-only and signed, LGPL-3.0's installation-information rule applies (Red/Amber).
  - **Proprietary program linking a GPL library** (readline, some GPL-only crypto/compression variants, libgpiod tools vs library): **Red**, because the program becomes a combined work.
  - **Static linking LGPL into a proprietary program:** needs object files for relinking. Amber/Red.
- **Yocto evidence:** `tmp/deploy/licenses/<image>/license.manifest` lists every package and its licence. `INCOMPATIBLE_LICENSE = "GPL-3.0* LGPL-3.0*"` in `local.conf` or the distro config is a common, good control, so check whether it's set. Recipes' `LICENSE =` fields give the declared licence. The `archiver` class produces source releases.
- **Buildroot evidence:** `make legal-info` produces `legal-info/manifest.csv` plus licence texts and sources. `BR2_*` options in `.config` decide which packages ship.
- **Containers on the device:** each image layer is distributed software. Treat it the same way.

## Mobile apps (iOS / Android / Flutter / React Native)

- **iOS:** frameworks are usually statically linked or bundled. GPL code in an iOS app is Red. LGPL needs relinking (impractical) and is usually Red. App Store terms are widely considered incompatible with GPL distribution.
- **Android:** Java/Kotlin libraries via Gradle (`build.gradle` dependencies) are bundled in the APK/AAB. GPL is Red. LGPL in a `.so` loaded dynamically is Amber with obligations. Check `licenses` in the Maven POM; the Google `oss-licenses` plugin output is good evidence.
- **React Native / npm:** the JavaScript bundle includes the code of every runtime dependency (`dependencies`, not `devDependencies`), so GPL dependencies are Red. Use `node_modules/<pkg>/package.json` `license` fields. `license-checker` output, or a lockfile plus registry metadata, are good evidence.
- **Flutter / Dart:** `pubspec.lock` packages. Licences live in the pub cache; Flutter's `LicenseRegistry` / `showLicensePage` is the usual notices mechanism.
- **Notices:** apps normally show open-source notices in an "About / Licences" screen. Check that one exists.

## Desktop tools, cloud services and back-ends

- **Not distributed** (runs only on your servers): GPL obligations usually don't trigger, but **AGPL and SSPL do**, as soon as users interact with the software over a network. Modified AGPL code in a service users reach is Red. Unmodified AGPL used as a separate service (e.g. a database) needs legal advice on the "interaction" scope; rate it Amber at least.
- **Distributed tools** (factory provisioning tool, desktop configurator, firmware-update utility given to customers or contract manufacturers): these are distribution, so the normal GPL/LGPL rules apply.
- **Python / pip:** check `*.dist-info/METADATA` (`License:`, `License-Expression:`, classifiers). Pure-Python GPL imports in a distributed proprietary tool are generally treated as linking (Red), though some lawyers disagree, so flag Amber with a legal note if it's only imported, not modified.

## Evidence sources, strongest first

1. Linker map (MCU), Yocto `license.manifest` / Buildroot `legal-info`, app licence-plugin output: what really ships.
2. ScanCode results (`scancode --license --copyright --package --info`).
3. `license_scan.py` inventory: licence files, SPDX tags, header text, manifests.
4. Build configuration (Makefile `COMPONENTS`, Kconfig, Gradle/npm dependency type) when nothing above exists.

State in the report which evidence each conclusion rests on.
