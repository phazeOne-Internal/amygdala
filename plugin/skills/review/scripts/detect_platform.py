#!/usr/bin/env python3
"""Detect the embedded platform, SDK, RTOS and key libraries of a firmware repo.

Usage: detect_platform.py <repo-root> [--max-files N]

Prints JSON to stdout:
  platforms   - candidate platforms ranked by score, with evidence
  rtos        - detected RTOS(es) with evidence
  libraries   - notable libraries (TLS, IP stack, bootloader, cloud, BLE...) with version hints
  languages   - file counts and line counts per language
  vendored_dirs / first_party_dirs - suggested review scope
  build_files - build/config files found

Heuristic only: confirm by reading the build files.
"""
import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict

if sys.version_info < (3, 8):
    sys.exit("This script needs Python 3.8 or later (any interpreter on PATH is fine); found " + sys.version.split()[0])

for _s in (sys.stdout, sys.stderr):  # Windows consoles default to cp1252; code snippets may not be ASCII
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

SRC_EXT = {
    ".c": "C", ".h": "C/C++ header", ".cpp": "C++", ".cc": "C++", ".cxx": "C++",
    ".hpp": "C++ header", ".s": "Assembly", ".S": "Assembly", ".asm": "Assembly",
    ".ino": "Arduino", ".rs": "Rust", ".py": "Python",
}

# Directory names that are almost always vendored / generated / build output.
VENDOR_DIR_NAMES = {
    "mtb_shared", "libs", "deps", "third_party", "thirdparty", "third-party", "vendor",
    "vendors", "external", "extern", "ext", "modules", "zephyr", "nrf", "nrfxlib",
    "bootloader", "mcuboot", "middlewares", "drivers", "cmsis", "hal_driver",
    "managed_components", "components", "lib", ".pio", "bsps", "generatedsource",
    "build", "out", "dist", "cmake-build-debug", "cmake-build-release", "node_modules",
    ".git", ".github", ".vscode", ".idea", "docs", "doc",
}
SKIP_ALWAYS = {".git", "node_modules", "build", "out", ".pio", "cmake-build-debug", "cmake-build-release"}

# (platform, regex applied to file path, weight, description)
PATH_MARKERS = [
    ("Infineon PSoC 6 / ModusToolbox", r"(^|/)[^/]+\.mtb$", 3, "ModusToolbox .mtb manifest"),
    ("Infineon PSoC 6 / ModusToolbox", r"(^|/)design\.modus$", 4, "Device Configurator design.modus"),
    ("Infineon PSoC 6 / ModusToolbox", r"(^|/)mtb_shared(/|$)", 4, "mtb_shared directory"),
    ("Infineon PSoC 6 / ModusToolbox", r"TARGET_CY8C(KIT|PROTO)?-?06", 5, "PSoC 6 BSP target"),
    ("Infineon PSoC 6 / ModusToolbox", r"mtb-pdl-cat1|mtb-hal-cat1|psoc6pdl|psoc6hal", 5, "PSoC 6 PDL/HAL library"),
    ("Zephyr RTOS", r"(^|/)prj\.conf$", 4, "Zephyr prj.conf"),
    ("Zephyr RTOS", r"(^|/)west\.yml$", 4, "west manifest"),
    ("Zephyr RTOS", r"\.overlay$", 2, "devicetree overlay"),
    ("ESP-IDF (Espressif)", r"(^|/)sdkconfig(\.defaults)?$", 5, "ESP-IDF sdkconfig"),
    ("ESP-IDF (Espressif)", r"(^|/)idf_component\.yml$", 4, "IDF component manifest"),
    ("STM32 (STM32Cube)", r"\.ioc$", 5, "STM32CubeMX project"),
    ("STM32 (STM32Cube)", r"stm32[a-z0-9]+xx_hal", 4, "STM32 HAL"),
    ("NXP MCUXpresso", r"\.mex$", 4, "MCUXpresso config"),
    ("PlatformIO / Arduino", r"(^|/)platformio\.ini$", 5, "platformio.ini"),
    ("PlatformIO / Arduino", r"\.ino$", 4, "Arduino sketch"),
    ("Mbed OS", r"(^|/)mbed_app\.json$", 5, "mbed_app.json"),
    ("Infineon XMC", r"xmclib|XMC[0-9]{4}", 4, "XMC library"),
    ("Infineon AIROC Bluetooth (CYW20xxx)", r"TARGET_CYW20|btsdk", 4, "AIROC BT SDK target"),
    ("Raspberry Pi Pico (RP2040/RP2350)", r"pico_sdk_import\.cmake", 5, "Pico SDK import"),
    ("Analog Devices MAX32/MAX78 (MSDK)", r"(^|/)project\.mk$", 2, "MSDK project.mk"),
    ("Analog Devices MAX32/MAX78 (MSDK)", r"(^|/)(msdk|MaximSDK)(/|$)", 4, "MSDK directory"),
]

# (platform, regex applied to source content, weight, description)
CONTENT_MARKERS = [
    ("Infineon PSoC 6 / ModusToolbox", r"#include\s*[<\"]cyhal\.h", 3, "includes cyhal.h"),
    ("Infineon PSoC 6 / ModusToolbox", r"#include\s*[<\"]cybsp\.h", 3, "includes cybsp.h"),
    ("Infineon PSoC 6 / ModusToolbox", r"#include\s*[<\"]cy_pdl\.h", 3, "includes cy_pdl.h"),
    ("Infineon PSoC 6 / ModusToolbox", r"\bCY8C6[0-9A-Z]+", 4, "PSoC 6 part number"),
    ("Infineon PSoC 6 / ModusToolbox", r"\bCY8CKIT-06[0-9A-Z-]*", 4, "PSoC 6 kit"),
    ("Infineon PSoC 6 / ModusToolbox", r"\bcyhal_[a-z_]+\(", 1, "cyhal_* calls"),
    ("Infineon PSoC 6 / ModusToolbox", r"\bCy_[A-Z][A-Za-z]+_[A-Za-z]+\(", 1, "PDL Cy_* calls"),
    ("Infineon PSoC 6 / ModusToolbox", r"^\s*TARGET\s*[?:]?=\s*(APP_)?CY8C", 5, "Makefile TARGET"),
    ("Zephyr RTOS", r"#include\s*[<\"]zephyr/", 4, "includes zephyr/"),
    ("Zephyr RTOS", r"\bk_(sleep|msleep|sem_take|mutex_lock|work_submit)\(", 2, "Zephyr kernel API"),
    ("Zephyr RTOS", r"^\s*CONFIG_[A-Z0-9_]+=", 1, "Kconfig settings"),
    ("Nordic nRF Connect SDK", r"sdk-nrf|nrfconnect/sdk|#include\s*[<\"](nrfx|nrf_|hal/nrf)", 3, "nRF Connect / nrfx"),
    ("Nordic nRF5 SDK (legacy)", r"#include\s*[<\"](nrf_sdh|app_error|nrf_log)\.h", 3, "nRF5 SDK headers"),
    ("ESP-IDF (Espressif)", r"#include\s*[<\"](esp_system|esp_wifi|esp_log|freertos/FreeRTOS)\.h", 3, "ESP-IDF headers"),
    ("ESP-IDF (Espressif)", r"idf_component_register", 4, "IDF CMake"),
    ("STM32 (STM32Cube)", r"#include\s*[<\"]stm32[a-z0-9]+xx(_hal)?\.h", 4, "STM32 headers"),
    ("STM32 (STM32Cube)", r"\bHAL_(GPIO|UART|SPI|I2C|Delay|Init)\w*\(", 1, "STM32 HAL calls"),
    ("NXP MCUXpresso", r"#include\s*[<\"]fsl_[a-z_]+\.h", 3, "NXP fsl_ drivers"),
    ("PlatformIO / Arduino", r"#include\s*[<\"]Arduino\.h", 4, "Arduino.h"),
    ("PlatformIO / Arduino", r"^\s*void\s+setup\s*\(\s*\)", 2, "Arduino setup()"),
    ("Mbed OS", r"#include\s*[<\"]mbed\.h", 4, "mbed.h"),
    ("Silicon Labs Gecko SDK", r"#include\s*[<\"](em_device|sl_[a-z_]+)\.h", 3, "Gecko SDK headers"),
    ("TI SimpleLink", r"#include\s*[<\"]ti/drivers/", 3, "TI drivers"),
    ("Microchip / Atmel", r"#include\s*[<\"](atmel_start|asf|xc)\.h", 3, "Microchip headers"),
    ("Raspberry Pi Pico (RP2040/RP2350)", r"#include\s*[<\"]pico/stdlib\.h", 4, "pico/stdlib.h"),
    ("Analog Devices MAX32/MAX78 (MSDK)", r"#include\s*[<\"]mxc_(device|delay|sys)\.h", 4, "includes mxc_device.h"),
    ("Analog Devices MAX32/MAX78 (MSDK)", r"\bMXC_(FLC|GPIO|UART|ICC|Delay|NVIC)[A-Za-z_]*\s*\(|\bMXC_F_[A-Z0-9_]+", 2, "MXC_ driver calls"),
    ("Analog Devices MAX32/MAX78 (MSDK)", r"\bMAX(32[0-9]{3}|78[0-9]{3})\b|BOARD\s*=\s*FTHR", 2, "MAX32/MAX78 part or board"),
]

RTOS_MARKERS = [
    ("FreeRTOS", r"(^|/)FreeRTOSConfig\.h$", "path", "FreeRTOSConfig.h"),
    ("FreeRTOS", r"#include\s*[<\"](freertos/)?FreeRTOS\.h", "content", "includes FreeRTOS.h"),
    ("FreeRTOS", r"\bxTaskCreate(Static)?\(", "content", "xTaskCreate"),
    ("Zephyr", r"#include\s*[<\"]zephyr/kernel\.h", "content", "zephyr/kernel.h"),
    ("Azure RTOS / Eclipse ThreadX", r"#include\s*[<\"]tx_api\.h", "content", "tx_api.h"),
    ("RT-Thread", r"#include\s*[<\"]rtthread\.h", "content", "rtthread.h"),
    ("CMSIS-RTOS2 / RTX", r"#include\s*[<\"]cmsis_os2?\.h", "content", "cmsis_os.h"),
    ("Mbed OS RTOS", r"\bThisThread::|rtos::Thread", "content", "Mbed RTOS API"),
    ("Infineon abstraction-rtos", r"\bcy_rtos_[a-z_]+\(", "content", "cy_rtos_* wrapper"),
]

LIB_MARKERS = [
    ("mbedTLS", r"#include\s*[<\"]mbedtls/", r"MBEDTLS_VERSION_STRING\s+\"([0-9.]+)\""),
    ("wolfSSL", r"#include\s*[<\"]wolfssl/", r"LIBWOLFSSL_VERSION_STRING\s+\"([0-9.]+)\""),
    ("lwIP", r"#include\s*[<\"]lwip/", None),
    ("FreeRTOS+TCP", r"FreeRTOS_IP\.h|FreeRTOS_Sockets\.h", None),
    ("MCUboot", r"bootutil/|MCUBOOT_[A-Z_]+|mcuboot", None),
    ("Infineon OTA (ota-update / anycloud-ota)", r"cy_ota_api\.h|cy_ota_[a-z_]+\(", None),
    ("Infineon secure-sockets", r"cy_secure_sockets\.h|cy_socket_[a-z_]+\(", None),
    ("Infineon Wi-Fi Connection Manager", r"cy_wcm\.h|cy_wcm_[a-z_]+\(", None),
    ("Infineon Wi-Fi Host Driver (WHD)", r"whd\.h|whd_[a-z_]+\(", None),
    ("Infineon / Cypress BTSTACK", r"wiced_bt_[a-z_]+|wiced_bt_stack\.h", None),
    ("Infineon kv-store", r"mtb_kvstore|mtb_kvstore_[a-z]+\(", None),
    ("Infineon emulated EEPROM", r"cy_em_eeprom|Cy_Em_EEPROM_", None),
    ("Infineon cy_retarget_io", r"cy_retarget_io", None),
    ("coreMQTT", r"core_mqtt\.h|MQTT_Connect\(", None),
    ("Infineon MQTT library", r"cy_mqtt_api\.h|cy_mqtt_[a-z_]+\(", None),
    ("Paho MQTT", r"MQTTClient\.h|MQTTAsync\.h", None),
    ("AWS IoT Device SDK", r"aws_iot_|core_mqtt_agent|AWS_IOT_|ota_appversion32", None),
    ("Azure IoT SDK", r"azure_iot|az_iot_", None),
    ("littlefs", r"lfs\.h|lfs_[a-z_]+\(", None),
    ("FatFs", r"ff\.h|f_open\(", None),
    ("NimBLE", r"nimble/|ble_gap_[a-z_]+\(", None),
    ("Zephyr Bluetooth", r"zephyr/bluetooth/", None),
    ("BTstack (BlueKitchen)", r"btstack\.h|hci_[a-z_]+\(.*btstack", None),
    ("cJSON", r"cJSON\.h|cJSON_Parse\(", None),
    ("TinyCBOR / zcbor", r"cbor\.h|zcbor_", None),
    ("Matter / CHIP", r"#include\s*[<\"](app|lib|platform)/[A-Za-z]+.*CHIP|chip::", None),
    ("TF-M / PSA", r"psa/crypto\.h|psa_[a-z_]+\(|tfm_", None),
    ("Optiga / secure element", r"optiga_|atcab_|se05x", None),
]

BUILD_FILES = re.compile(
    r"(^|/)(Makefile|CMakeLists\.txt|west\.yml|prj\.conf|sdkconfig(\.defaults)?|platformio\.ini|"
    r"mbed_app\.json|idf_component\.yml|[^/]+\.mtb|design\.modus|[^/]+\.ioc|Kconfig|"
    r"FreeRTOSConfig\.h|mbedtls[_a-z]*config\.h|[^/]*mcuboot[^/]*config[^/]*\.h|"
    r"[^/]+\.ld|[^/]+\.icf|[^/]+\.sct|\.gitmodules|library\.json|package\.json|policy[^/]*\.json)$"
)
MTB_VERSION = re.compile(r"github\.com/[^/]+/([^/#]+?)(?:\.git)?#([^#]+)#")
TEXT_EXT = set(SRC_EXT) | {".mk", ".txt", ".conf", ".yml", ".yaml", ".json", ".ld", ".overlay",
                           ".dts", ".dtsi", ".mtb", ".ini", ".cmake", ".ioc", ".modus", ""}


def is_vendor_dir(name):
    n = name.lower()
    return n in VENDOR_DIR_NAMES or n.startswith("cmake-build") or n.startswith("cmsis")


def walk(root, max_files):
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_ALWAYS and not d.startswith(".")]
        for f in filenames:
            files.append(os.path.relpath(os.path.join(dirpath, f), root))
            if len(files) >= max_files:
                return files, True
    return files, False


def read_text(path, limit=400_000):
    try:
        with open(path, "rb") as fh:
            data = fh.read(limit)
        if b"\x00" in data[:4096]:
            return None
        return data.decode("utf-8", errors="replace")
    except OSError:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--max-files", type=int, default=60000)
    ap.add_argument("--out", help="write output to this file (UTF-8) instead of stdout")
    args = ap.parse_args()
    root = os.path.abspath(args.root)
    if args.out:
        sys.stdout = open(args.out, "w", encoding="utf-8")
    if not os.path.isdir(root):
        sys.exit(f"not a directory: {root}")

    files, truncated = walk(root, args.max_files)
    plat_score = Counter()
    plat_evidence = defaultdict(list)
    rtos_evidence = defaultdict(list)
    lib_evidence = defaultdict(list)
    lib_versions = defaultdict(set)
    lang_files = Counter()
    lang_loc = Counter()
    fp_loc_by_top = Counter()
    vendor_loc_by_dir = Counter()
    build_files = []
    mtb_deps = {}
    content_hits_cap = Counter()

    for rel in files:
        relp = rel.replace(os.sep, "/")
        parts = relp.split("/")
        ext = os.path.splitext(relp)[1]
        in_vendor = any(is_vendor_dir(p) for p in parts[:-1])
        vendor_root = None
        if in_vendor:
            for i, p in enumerate(parts[:-1]):
                if is_vendor_dir(p):
                    vendor_root = "/".join(parts[: i + 1]) + "/"
                    break

        for plat, rx, w, desc in PATH_MARKERS:
            if re.search(rx, relp, re.I):
                if len(plat_evidence[plat]) < 8:
                    plat_evidence[plat].append(f"{desc}: {relp}")
                plat_score[plat] += w if not in_vendor else max(1, w // 2)
        for name, rx, kind, desc in RTOS_MARKERS:
            if kind == "path" and re.search(rx, relp):
                rtos_evidence[name].append(f"{desc}: {relp}")
        if BUILD_FILES.search(relp) and not (in_vendor and not relp.endswith(".mtb")):
            build_files.append(relp)

        if ext not in TEXT_EXT:
            continue
        text = read_text(os.path.join(root, rel))
        if text is None:
            continue

        if relp.endswith(".mtb"):
            m = MTB_VERSION.search(text)
            if m:
                mtb_deps[m.group(1)] = m.group(2)

        if ext in SRC_EXT:
            loc = text.count("\n") + 1
            lang_files[SRC_EXT[ext]] += 1
            lang_loc[SRC_EXT[ext]] += loc
            if in_vendor:
                vendor_loc_by_dir[vendor_root] += loc
            else:
                top = parts[0] + "/" if len(parts) > 1 else "(root)"
                fp_loc_by_top[top] += loc

        # Content markers: weigh first-party evidence fully, vendored lightly
        # (a vendored SDK tells you the platform too, but less decisively).
        for plat, rx, w, desc in CONTENT_MARKERS:
            key = (plat, desc)
            if content_hits_cap[key] >= 5:
                continue
            if re.search(rx, text, re.M):
                content_hits_cap[key] += 1
                plat_score[plat] += w if not in_vendor else 0.25
                if not in_vendor and len(plat_evidence[plat]) < 12:
                    plat_evidence[plat].append(f"{desc}: {relp}")
        for name, rx, kind, desc in RTOS_MARKERS:
            if kind == "content" and len(rtos_evidence[name]) < 5 and re.search(rx, text):
                rtos_evidence[name].append(f"{desc}: {relp}{' (vendored)' if in_vendor else ''}")
        for name, rx, vrx in LIB_MARKERS:
            if len(lib_evidence[name]) < 4 and re.search(rx, text):
                lib_evidence[name].append(relp + (" (vendored)" if in_vendor else ""))
            if vrx:
                for v in re.findall(vrx, text):
                    lib_versions[name].add(v)

    # FreeRTOS kernel version
    for rel in files:
        if os.path.basename(rel) == "task.h":
            t = read_text(os.path.join(root, rel)) or ""
            m = re.search(r"tskKERNEL_VERSION_NUMBER\s+\"(V?[0-9.]+)", t)
            if m:
                lib_versions["FreeRTOS kernel"].add(m.group(1))

    ranked = sorted(plat_score.items(), key=lambda kv: -kv[1])
    top = ranked[0][1] if ranked else 0
    second = ranked[1][1] if len(ranked) > 1 else 0
    if top == 0:
        confidence = "none"
    elif top >= 10 and top >= 2 * second:
        confidence = "high"
    elif top >= 5:
        confidence = "medium"
    else:
        confidence = "low"

    # Nordic on Zephyr: report both.
    out = {
        "root": root,
        "files_scanned": len(files),
        "truncated": truncated,
        "detection_confidence": confidence,
        "platforms": [
            {"platform": p, "score": round(s, 1), "evidence": plat_evidence[p]} for p, s in ranked[:5]
        ],
        "rtos": [{"rtos": k, "evidence": v} for k, v in rtos_evidence.items() if v],
        "libraries": [
            {"library": k, "where": v, "versions": sorted(lib_versions.get(k, []))}
            for k, v in sorted(lib_evidence.items()) if v
        ],
        "other_versions": {k: sorted(v) for k, v in lib_versions.items() if not lib_evidence.get(k)},
        "modustoolbox_deps": mtb_deps,
        "languages": {k: {"files": lang_files[k], "lines": lang_loc[k]} for k in lang_files},
        "first_party_dirs": dict(fp_loc_by_top.most_common()),
        "vendored_dirs": dict(vendor_loc_by_dir.most_common(25)),
        "build_files": sorted(build_files)[:80],
        "notes": [
            "Heuristic detection. Confirm with build files.",
            "first_party_dirs / vendored_dirs are suggestions by directory name; "
            "check e.g. 'drivers/' or 'components/' which may be first-party in some repos.",
        ],
    }
    json.dump(out, sys.stdout, indent=2)
    print()


if __name__ == "__main__":
    main()
