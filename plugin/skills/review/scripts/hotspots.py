#!/usr/bin/env python3
"""Grep first-party firmware code for risky patterns, to decide where to read first.

Usage: hotspots.py <repo-root> [--exclude DIR ...] [--json] [--max-per-rule N]

Output is a list of LEADS, not findings: every hit needs reading in context.
Vendored directories (mtb_shared, libs, deps, third_party, ...) are skipped by default;
add more with --exclude, or force a directory in with --include-vendor.
"""
import argparse
import json
import os
import re
import sys
from collections import defaultdict

if sys.version_info < (3, 8):
    sys.exit("This script needs Python 3.8 or later (any interpreter on PATH is fine); found " + sys.version.split()[0])

for _s in (sys.stdout, sys.stderr):  # Windows consoles default to cp1252; code snippets may not be ASCII
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

DEFAULT_EXCLUDES = {
    "mtb_shared", "libs", "deps", "third_party", "thirdparty", "third-party", "vendor", "external",
    "extern", "modules", "zephyr", "nrf", "nrfxlib", "mcuboot", "middlewares", "cmsis",
    "managed_components", ".pio", "bsps", "generatedsource", "build", "out", "node_modules",
    ".git", "drivers_vendor",
}
SRC_EXT = {".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".ino", ".s", ".S"}
CFG_EXT = {".conf", ".mk", ".txt", ".cmake", ".json", ".yml", ".yaml", ".ini", ".defaults", ".overlay", ""}
KEY_EXT = {".pem", ".key", ".der", ".crt", ".p12", ".pfx"}

# (rule id, category, description, regex, file kinds)  kinds: src, cfg, any
RULES = [
    ("unbounded-string", "memory-safety", "Unbounded string function",
     r"\b(strcpy|strcat|sprintf|vsprintf|gets|wcscpy|stpcpy)\s*\(", "src"),
    ("scanf-s", "memory-safety", "scanf/sscanf %s without width",
     r"\b[sf]?scanf\s*\([^;]*%s", "src"),
    ("memcpy-var-len", "memory-safety", "memcpy/memmove with non-constant length (check bound)",
     r"\bmem(cpy|move)\s*\([^;]*,\s*[^;]*\b(len|length|size|sz|n|count|cnt)\w*\s*\)", "src"),
    ("strncpy", "memory-safety", "strncpy (does not guarantee NUL termination)",
     r"\bstrncpy\s*\(", "src"),
    ("format-string", "memory-safety", "printf-family with non-literal format",
     r"\b(printf|sprintf|snprintf|fprintf|LOG_\w+|ESP_LOG\w|cy_log_msg)\s*\(\s*(?:[^\",)]+,\s*){0,2}[a-z_][a-z0-9_\->.\[\]]*\s*\)", "src"),
    ("alloc", "memory-safety", "Dynamic allocation (check failure handling and steady-state use)",
     r"\b(malloc|calloc|realloc|pvPortMalloc|k_malloc|os_malloc|heap_caps_malloc)\s*\(|\bnew\s+\w", "src"),
    ("alloca-vla", "memory-safety", "alloca / variable length array on stack",
     r"\balloca\s*\(|^\s*\w[\w\s\*]*\s\w+\s*\[\s*[a-z_]\w*\s*\]\s*;", "src"),

    ("hardcoded-password", "security", "Possible hardcoded password / secret",
     r"(?i)\b\w*(passw(or)?d|passwd|pwd|secret|api_?key|token|psk|passkey|pin_code|auth_key)\w*\s*(\[\s*\]\s*)?(=|\s)\s*\"[^\"]{3,}\"", "any"),
    ("private-key", "security", "Embedded private key / certificate material",
     r"-----BEGIN (RSA |EC |ENCRYPTED )?PRIVATE KEY-----|-----BEGIN CERTIFICATE-----", "any"),
    ("hex-key", "security", "Long hex/byte array literal (possible key)",
     r"(?i)\b\w*(key|secret|iv|nonce)\w*\s*\[[^\]]*\]\s*=\s*\{\s*(0x[0-9a-f]{2}\s*,\s*){15,}", "src"),
    ("tls-verify-off", "security", "TLS verification disabled or optional",
     r"(?i)VERIFY_NONE|VERIFY_OPTIONAL|setInsecure\s*\(|skip_cert_common_name_check\s*=\s*true|"
     r"CY_SOCKET_TLS_VERIFY_NONE|verify_peer\s*=\s*(0|false)|SSL_VERIFY_NONE|insecure\s*=\s*(1|true)", "any"),
    ("plaintext-proto", "security", "Plaintext protocol/port (MQTT 1883, http://, telnet)",
     r"(?i)\b1883\b|\"http://|telnet|MQTT_SECURE_CONNECTION\s*\(?\s*0", "any"),
    ("weak-crypto", "security", "Weak crypto primitive",
     r"(?i)\b(md5|sha1|des_|rc4|arc4|_ecb\b|AES_ECB|MBEDTLS_CIPHER_AES_128_ECB|ecb_encrypt)\w*", "src"),
    ("weak-rng", "security", "Non-cryptographic RNG / test entropy",
     r"\b(rand|srand|random)\s*\(|MBEDTLS_TEST_NULL_ENTROPY|CONFIG_TEST_RANDOM_GENERATOR\s*=\s*y|MBEDTLS_NO_PLATFORM_ENTROPY", "any"),
    ("non-ct-compare", "security", "memcmp/strcmp on secret-looking data (timing)",
     r"\b(memcmp|strcmp|strncmp)\s*\([^;]*(mac|hmac|tag|token|pass|pin|key|sig|auth|hash)", "src"),
    ("secret-logged", "security", "Logging of secret-looking value",
     r"(?i)\b(printf|LOG_\w+|ESP_LOG\w|cy_log_msg|DEBUG_PRINT\w*|Serial\.print\w*)\s*\([^;]*(passw|secret|key|token|psk|pin)", "src"),
    ("debug-shell", "security", "Debug shell / CLI / backdoor command",
     r"(?i)CONFIG_SHELL\s*=\s*y|SHELL_CMD|\"(factory|debug|dump|peek|poke|memrd|memwr|backdoor|root|unlock)\"", "any"),
    ("ble-fixed-passkey", "security", "Fixed BLE passkey / Just Works",
     r"(?i)CONFIG_BT_FIXED_PASSKEY\s*=\s*y|bt_passkey_set|fixed_passkey|IO_CAPABILITIES_NONE|BTM_IO_CAPABILITIES_NONE|NoInputNoOutput", "any"),
    ("sample-signing-key", "secure-boot-ota", "Sample / test signing key referenced",
     r"(?i)(root-(rsa|ec)[-_a-z0-9]*\.pem|cypress-test-[a-z0-9-]+\.pem|enc-(rsa|ec)[-_a-z0-9]*\.pem|SIGNATURE_KEY_FILE)", "any"),
    ("ota-validate-off", "secure-boot-ota", "Image validation / downgrade protection switched off",
     r"(?i)(MCUBOOT_VALIDATE_PRIMARY_SLOT|MCUBOOT_DOWNGRADE_PREVENTION|VALIDATE_IMAGE|SIGNATURE_CHECK|verify_signature)\w*\s*(=|\s)\s*(0|false|n)\b|#\s*undef\s+MCUBOOT_VALIDATE", "any"),

    ("assert-error", "robustness", "Assert used as error handling (compiled out in release?)",
     r"\b(CY_ASSERT|assert|configASSERT|__ASSERT|ASSERT|ESP_ERROR_CHECK)\s*\(\s*(0|false|[^)]*(!=|==)\s*(CY_RSLT_SUCCESS|ESP_OK|HAL_OK|0|NULL|pdPASS))", "src"),
    ("assert-side-effect", "robustness", "Assert wrapping a function call (side effect lost under NDEBUG)",
     r"\b(CY_ASSERT|assert)\s*\(\s*\w+\s*\([^;]*\)\s*(==|!=)", "src"),
    ("infinite-loop", "robustness", "Infinite loop error path / empty handler",
     r"while\s*\(\s*(1|true)\s*\)\s*(;|\{\s*\})|for\s*\(\s*;\s*;\s*\)\s*(;|\{\s*\})", "src"),
    ("fault-handler", "robustness", "Fault handler definition (check it records and resets)",
     r"\b(HardFault|MemManage|BusFault|UsageFault|NMI)_Handler\s*\(|Cy_SysLib_FaultHandler|k_sys_fatal_error_handler", "src"),
    ("watchdog", "robustness", "Watchdog usage (check where it is fed)",
     r"(?i)\b(cyhal_wdt_\w+|Cy_WDT_\w+|HAL_IWDG_\w+|wdt_feed|task_wdt_\w+|esp_task_wdt_\w+|IWDG|watchdog)\w*\s*\(", "src"),
    ("infinite-timeout", "robustness", "Infinite timeout",
     r"\b(portMAX_DELAY|K_FOREVER|HAL_MAX_DELAY|CY_RTOS_NEVER_TIMEOUT|osWaitForever|TX_WAIT_FOREVER|CYHAL_\w*NEVER_TIMEOUT)\b", "src"),
    ("tick-compare", "robustness", "Tick/time comparison (check wraparound safety)",
     r"\b(\w*(tick|time|millis|uptime|now)\w*)\s*(>=|>|<=|<)\s*\w*(deadline|timeout|expire|last|start|next)\w*|"
     r"\b(xTaskGetTickCount|HAL_GetTick|millis|k_uptime_get_32|cyhal_\w*_read)\s*\(\s*\)\s*(>=|>|<|<=)", "src"),
    ("ignored-result", "robustness", "Call result discarded with (void) or unchecked init",
     r"^\s*\(void\)\s*(cyhal_|Cy_|HAL_|xQueue|xSemaphore|k_|settings_|nvs_|esp_)\w+\s*\(|^\s*(cyhal_\w+_init|cybsp_init|Cy_\w+_Init|HAL_\w+_Init)\s*\(", "src"),
    ("todo", "code-quality", "TODO/FIXME/HACK/XXX comment",
     r"(?i)\b(TODO|FIXME|HACK|XXX|KLUDGE)\b", "src"),
    ("disabled-code", "code-quality", "#if 0 block", r"^\s*#\s*if\s+0\b", "src"),

    ("isr-blocking", "concurrency", "Possible blocking/non-ISR-safe call (check if in ISR/callback context)",
     r"\b(printf|puts|cy_log_msg|vTaskDelay|cyhal_system_delay_ms|xSemaphoreTake|xQueueReceive|k_sleep|k_msleep|k_mutex_lock|HAL_Delay|malloc|free)\s*\(", "src"),
    ("irq-disable", "concurrency", "Interrupt disable/enable (check nesting and duration)",
     r"__disable_irq\s*\(|__enable_irq\s*\(|taskENTER_CRITICAL|portDISABLE_INTERRUPTS|irq_lock\s*\(|Cy_SysLib_EnterCriticalSection", "src"),
    ("volatile", "concurrency", "volatile declaration (shared-state inventory)", r"\bvolatile\b", "src"),

    ("flash-write", "hardware-power", "Flash/NVM write (check frequency, atomicity, power-loss)",
     r"\b(cyhal_flash_(write|program|erase)|Cy_Flash_(Write|Program|Erase)\w*|Cy_Em_EEPROM_Write|mtb_kvstore_write|HAL_FLASH_Program|nvs_(write|set)\w*|settings_save\w*|flash_write|flash_erase|EEPROM\.(write|put)|fs_write|lfs_file_write)\s*\(", "src"),
    ("busy-delay", "hardware-power", "Busy-wait delay",
     r"\b(cyhal_system_delay_ms|Cy_SysLib_Delay\w*|HAL_Delay|delay|k_busy_wait|ets_delay_us|delayMicroseconds)\s*\(", "src"),

    ("debug-config", "field-readiness", "Debug build configuration in a release-relevant file",
     r"(?i)^\s*CONFIG\s*[?:]?=\s*Debug|-DDEBUG\b|CONFIG_LOG_DEFAULT_LEVEL\s*=\s*4|CONFIG_ESP_SYSTEM_PANIC_PRINT_HALT\s*=\s*y|CONFIG_RESET_ON_FATAL_ERROR\s*=\s*n", "cfg"),
    ("reset-reason", "field-readiness", "Reset-reason handling (presence check)",
     r"\b(cyhal_system_get_reset_reason|Cy_SysLib_GetResetReason|hwinfo_get_reset_cause|esp_reset_reason|__HAL_RCC_GET_FLAG)\s*\(", "src"),
    ("version", "field-readiness", "Firmware version definition (presence check)",
     r"(?i)#define\s+\w*(FW|FIRMWARE|APP|SW)_?VERSION\w*|APP_VERSION_(MAJOR|MINOR)", "any"),
]
PRESENCE_RULES = {"watchdog", "reset-reason", "version", "fault-handler"}


def excluded(parts, excludes, includes):
    for p in parts[:-1]:
        pl = p.lower()
        if pl in includes:
            return False
        if pl in excludes or pl.startswith("cmake-build"):
            return True
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--exclude", action="append", default=[], help="extra directory name or path prefix to skip")
    ap.add_argument("--include-vendor", action="append", default=[], help="directory name to force-include")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--max-per-rule", type=int, default=40)
    ap.add_argument("--out", help="write output to this file (UTF-8) instead of stdout")
    args = ap.parse_args()
    root = os.path.abspath(args.root)
    if args.out:
        sys.stdout = open(args.out, "w", encoding="utf-8")
    excludes = {e.strip("/").lower() for e in args.exclude if "/" not in e.strip("/")} | DEFAULT_EXCLUDES
    path_excludes = [e.strip("/") + "/" for e in args.exclude if "/" in e.strip("/")]
    includes = {i.strip("/").lower() for i in args.include_vendor}
    compiled = [(rid, cat, desc, re.compile(rx, re.M), kind) for rid, cat, desc, rx, kind in RULES]

    hits = defaultdict(list)
    counts = defaultdict(int)
    key_files = []
    files_scanned = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            parts = rel.split("/")
            if excluded(parts, excludes, includes) or any(rel.startswith(p) for p in path_excludes):
                continue
            ext = os.path.splitext(fn)[1]
            if ext in KEY_EXT:
                key_files.append(rel)
            if ext in SRC_EXT:
                kind = "src"
            elif ext in CFG_EXT or fn in ("Makefile", "prj.conf", "sdkconfig", "Kconfig"):
                kind = "cfg"
            elif ext in KEY_EXT:
                kind = "cfg"
            else:
                continue
            try:
                with open(full, "r", encoding="utf-8", errors="replace") as fh:
                    lines = fh.readlines()
            except OSError:
                continue
            files_scanned += 1
            text = "".join(lines)
            line_starts = [0]
            for ln in lines:
                line_starts.append(line_starts[-1] + len(ln))
            for rid, cat, desc, rx, rkind in compiled:
                if rkind != "any" and rkind != kind:
                    continue
                for m in rx.finditer(text):
                    # line number via bisect
                    lo, hi = 0, len(line_starts) - 1
                    while lo < hi:
                        mid = (lo + hi + 1) // 2
                        if line_starts[mid] <= m.start():
                            lo = mid
                        else:
                            hi = mid - 1
                    lineno = lo + 1
                    snippet = lines[lo].strip()[:160] if lo < len(lines) else ""
                    counts[rid] += 1
                    if len(hits[rid]) < args.max_per_rule:
                        hits[rid].append({"file": rel, "line": lineno, "code": snippet})

    meta = {rid: (cat, desc) for rid, cat, desc, _, _ in RULES}
    absent = [rid for rid in PRESENCE_RULES if counts[rid] == 0]

    if args.json:
        json.dump({
            "root": root, "files_scanned": files_scanned,
            "hits": {rid: {"category": meta[rid][0], "description": meta[rid][1], "count": counts[rid], "samples": hits[rid]} for rid in hits},
            "absent_presence_checks": absent, "key_files": key_files,
        }, sys.stdout, indent=2)
        print()
        return

    print(f"# Hotspot leads for {root}\n")
    print(f"First-party files scanned: {files_scanned}. **These are leads to read in context, not findings.**\n")
    if absent:
        print("## Absent (possible gaps — confirm by reading)\n")
        for rid in sorted(absent):
            print(f"- **{meta[rid][1]}** — no matches in first-party code")
        print()
    if key_files:
        print("## Key / certificate files in first-party tree\n")
        for k in key_files:
            print(f"- `{k}`")
        print()
    by_cat = defaultdict(list)
    for rid in hits:
        by_cat[meta[rid][0]].append(rid)
    for cat in ["memory-safety", "security", "secure-boot-ota", "robustness", "concurrency",
                "hardware-power", "field-readiness", "code-quality"]:
        if cat not in by_cat:
            continue
        print(f"## {cat}\n")
        for rid in sorted(by_cat[cat], key=lambda r: -counts[r]):
            more = counts[rid] - len(hits[rid])
            print(f"### {meta[rid][1]} (`{rid}`) — {counts[rid]} hit(s)\n")
            for h in hits[rid]:
                print(f"- `{h['file']}:{h['line']}` — `{h['code']}`")
            if more > 0:
                print(f"- … {more} more")
            print()


if __name__ == "__main__":
    main()
