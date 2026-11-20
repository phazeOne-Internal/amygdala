# Other platforms

Platform-specific pitfalls to add to the general checklist. Jump to the section that matches the detector output. If the platform isn't listed, apply the general checklist and the closest RTOS section, and say in the report that no platform-specific guidance was applied.

Contents: Zephyr / nRF Connect SDK · FreeRTOS (generic) · ESP-IDF · STM32 (Cube HAL) · NXP MCUXpresso · Bare metal / Arduino / PlatformIO · Mbed OS · Azure RTOS ThreadX

## Zephyr / nRF Connect SDK

- **Config is code**: `prj.conf`, `*.conf` overlays, `Kconfig`, devicetree `*.overlay`. Review them. Red flags in production config: `CONFIG_ASSERT=n` *and* error handling that relies on `__ASSERT`; `CONFIG_SHELL=y` with privileged shell commands; `CONFIG_LOG_DEFAULT_LEVEL=4` with secrets in logs; `CONFIG_BT_SMP_ALLOW_UNAUTH_OVERWRITE=y`; `CONFIG_BT_FIXED_PASSKEY=y`; `CONFIG_MCUBOOT_SIGNATURE_KEY_FILE` pointing at `root-*.pem` sample keys; `CONFIG_TEST_RANDOM_GENERATOR=y` / `CONFIG_ENTROPY_GENERATOR` missing (insecure RNG — Red); `CONFIG_WATCHDOG` absent; `CONFIG_HW_STACK_PROTECTION` / `CONFIG_STACK_SENTINEL` off; `CONFIG_RESET_ON_FATAL_ERROR=n` in release.
- Context rules: `k_mutex_lock`, `k_sleep`, `k_sem_take(..., K_FOREVER)`, `k_malloc`, blocking logging and flash/settings APIs must not be called from ISRs. Bluetooth callbacks (`connected`, GATT `write` handlers) run in the BT RX thread — blocking there stalls the stack. Work should be deferred with `k_work_submit`.
- GATT write handlers: check `len` and `offset` against the destination before `memcpy` — classic Red. Check attribute permissions (`BT_GATT_PERM_WRITE_ENCRYPT` / `_AUTHEN`) on sensitive characteristics.
- `settings_save_one`, `nvs_write`, `fs_write` return codes; write frequency (NVS has wear levelling but finite endurance).
- `k_uptime_get_32()` wraps at ~49.7 days; prefer `k_uptime_get()` (64-bit) or wrap-safe subtraction.
- MCUboot: image confirmation via `boot_write_img_confirmed()` after self-test; `CONFIG_BOOT_UPGRADE_ONLY`, downgrade prevention, `CONFIG_MCUBOOT_HARDWARE_DOWNGRADE_PREVENTION`.
- nRF specifics: APPROTECT (debug lock) enabled in production (`CONFIG_NRF_APPROTECT_LOCK`), TF-M / secure partition usage, KMU for keys.
- Dependencies: `west.yml` revisions for zephyr, nrf, mcuboot, mbedtls, tf-m.

## FreeRTOS (generic)

- `FreeRTOSConfig.h`: `configASSERT` behaviour in release, `configCHECK_FOR_STACK_OVERFLOW 2` + hook, `configUSE_MALLOC_FAILED_HOOK`, heap scheme, `configMAX_SYSCALL_INTERRUPT_PRIORITY` vs actual NVIC priorities, `configUSE_TIMERS` and timer task stack/priority (timer callbacks must not block).
- `...FromISR` variants in ISRs and `portYIELD_FROM_ISR(xHigherPriorityTaskWoken)`.
- `xQueueSend` / `xSemaphoreTake` return values ignored; `portMAX_DELAY` on paths depending on external peers.
- Software timers used as watchdog feeders.
- `uxTaskGetStackHighWaterMark` used anywhere (evidence of stack sizing)?
- Kernel version (`tskKERNEL_VERSION_NUMBER`), FreeRTOS+TCP version (several historical CVEs in old versions).

## ESP-IDF

- `sdkconfig` / `sdkconfig.defaults`: production should have `CONFIG_SECURE_BOOT=y` (V2), `CONFIG_SECURE_FLASH_ENC_ENABLED=y` in Release mode (not Development mode), JTAG disabled (`CONFIG_SECURE_BOOT_ALLOW_JTAG` not set), `CONFIG_ESP_TASK_WDT` and interrupt WDT enabled, `CONFIG_ESP_SYSTEM_PANIC` set to reboot not halt (`PRINT_HALT`/`GDBSTUB` in release is Red), `CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK`, `CONFIG_APP_ROLLBACK_ENABLE` with `esp_ota_mark_app_valid_cancel_rollback()` after self-test.
- NVS encryption for credentials (`CONFIG_NVS_ENCRYPTION`). Wi-Fi credentials in `menuconfig` defaults (`CONFIG_EXAMPLE_WIFI_PASSWORD`) — Red if shipped.
- `ESP_ERROR_CHECK()` aborts on error — acceptable in init with reboot-on-panic, a problem in runtime paths where failure is expected (network).
- `esp_http_client` / `esp_tls` with `skip_cert_common_name_check = true`, no `cert_pem`/`crt_bundle_attach` — Red.
- `esp_https_ota` vs plain `esp_ota_*` from HTTP.
- ISR rules: `IRAM_ATTR` for ISRs and anything they call; no flash access from ISRs while cache disabled.
- `esp_random()` is only cryptographically strong with RF/bootloader entropy enabled — check `bootloader_random_enable()` usage if used before Wi-Fi/BT start.

## STM32 (Cube HAL / LL)

- `HAL_StatusTypeDef` results ignored; `Error_Handler()` defaults to `__disable_irq(); while (1) {}` — with no IWDG this hangs the device forever (Red on unattended products).
- IWDG/WWDG enabled and fed correctly; IWDG often stopped in debug only (`DBGMCU` freeze) — fine.
- `HAL_GetTick()` wrap-safe comparisons.
- `HAL_UART_Receive` with `HAL_MAX_DELAY`; `HAL_UART_RxCpltCallback` doing heavy work (ISR context).
- Readout protection (RDP level 1/2), write protection on bootloader sectors, PCROP, option bytes set in production flow — Amber `needs-verification` if not evidenced.
- `.ioc` regenerated code: user code must be inside `USER CODE BEGIN/END` blocks or it is lost on regeneration.
- Secure boot: X-CUBE-SBSFU / TF-M / MCUboot keys.
- D-cache on M7 parts (H7, F7): DMA buffers need cache maintenance or MPU non-cacheable regions.

## NXP MCUXpresso

- `status_t` results; `fsl_*` drivers; `kStatus_Success`.
- Secure boot (HAB on i.MX RT, SB on LPC/MCX), debug lock via fuses, `MCUBOOT`.
- XIP from FlexSPI while writing flash.

## Bare metal / Arduino / PlatformIO

- `platformio.ini`: framework, platform version pinning (`platform = espressif32` without version = unpinned), `build_flags` with `-DDEBUG`.
- Arduino: `String` heavy use causes heap fragmentation; `delay()` in loops; `millis()` wrap-safe comparison (`millis() - start >= interval`); `WiFiClientSecure::setInsecure()` — Red.
- Superloop: any blocking call stalls everything; watchdog presence; ISR-shared flags `volatile`.
- Startup code / linker script: stack and heap sizes, `.noinit` sections, vector table.

## Mbed OS

- End-of-life (Arm ended Mbed OS maintenance in 2026) — dependency finding, Amber–Red depending on exposure.
- `mbed_app.json` config: `platform.stdio-baud-rate`, trace levels, `MBED_CONF_*` secrets.

## Azure RTOS ThreadX / Eclipse ThreadX

- `tx_*` return codes; `TX_WAIT_FOREVER`; NetX Duo TLS config; `tx_thread_stack_error_notify`.
