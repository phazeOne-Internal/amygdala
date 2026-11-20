# Infineon PSoC 6 / ModusToolbox

Read this when the detector reports PSoC 6, ModusToolbox (MTB), `cyhal`, `cy_pdl`, `cybsp`, or a `CY8C6...` part. Many points also apply to other ModusToolbox targets (XMC7000, PSoC Edge, AIROC CYW20xxx), but check each against the specific device.

Some details vary by device family (PSoC 61/62/63 vs PSoC 64 "Secure MCU") and by library version. When a point depends on the device, say which assumption you made and suggest the developer confirm it against the device TRM/datasheet.

## Recognising the project

- `Makefile` with `TARGET=`, `MTB_TYPE`, `CORE`, `TOOLCHAIN`, `CONFIG`; `deps/*.mtb` or `libs/*.mtb` manifest files; `bsps/TARGET_*`; `design.modus` (Device Configurator); `GeneratedSource/` (generated — don't review line by line, and don't recommend hand-editing it).
- `mtb_shared/` holds shared library checkouts — vendored, not first-party. Record versions from the `.mtb` files (they contain the git tag, e.g. `#release-v3.x.x#`).
- Multi-core layouts: `proj_cm0p/` and `proj_cm4/`, or a CM4-only app with a prebuilt CM0+ image (`psoc6cm0p` / `COMPONENT_CM0P_SLEEP`). Note which core runs what.
- `CONFIG=Debug` vs `CONFIG=Release` in the Makefile. The default from templates is often `Debug` — flag if the release pipeline doesn't override it.

## Error handling patterns specific to ModusToolbox

- Nearly every HAL/PDL/middleware call returns `cy_rslt_t`. Check results against `CY_RSLT_SUCCESS`.
- **The template pattern `if (result != CY_RSLT_SUCCESS) { CY_ASSERT(0); }` is a real defect in release builds.** `CY_ASSERT` compiles to nothing when `NDEBUG` is defined (Release config), so execution continues with an uninitialised BSP, peripheral or network stack. Code-example-derived products ship with this pattern very often. Rate Amber generally, Red where continuing leads to lock-up, corruption or a security bypass (e.g. TRNG or crypto init failure, `cybsp_init()` failure). Recommend a defined failure policy: log a reason code, then a controlled reset, or a safe state.
- `CY_ASSERT` used around calls with side effects, e.g. `CY_ASSERT(cyhal_..._init(...) == CY_RSLT_SUCCESS)`: in Release the init call itself is compiled out. Red.
- `__enable_irq()` straight after `cybsp_init()` is normal; check nothing before it relies on interrupts.

## Watchdog, faults and resets

- Watchdog APIs: `cyhal_wdt_init/kick/free` (HAL) or `Cy_WDT_*` (PDL); the MCWDT (`Cy_MCWDT_*`) is a different, multi-counter timer — a MCWDT used only as a periodic timer is not a watchdog.
- Check that the WDT is enabled in Release and kicked from a health-checking task (e.g. after confirming each critical task has checked in), not from a timer ISR or a `cyhal_timer` callback.
- Check WDT behaviour across DeepSleep and during long blocking operations (flash erase during OTA, Wi-Fi join). Confirm against the TRM which low-power modes the WDT counts in for this part; a device that sleeps longer than the WDT timeout without kicking it will reset in the field.
- Reset reason: `cyhal_system_get_reset_reason()` / `Cy_SysLib_GetResetReason()` — should be read at boot, cleared (`Cy_SysLib_ClearResetReason()`), and reported.
- Fault handling: the PDL provides `Cy_SysLib_FaultHandler` and the `cy_sysfault` driver; a weak default HardFault handler that just spins is common. Check for a crash record stored in a `.noinit`/`CY_SECTION(".cy_ramfunc")`-style retained region or backup registers and reported after reboot.

## FreeRTOS on PSoC 6 (via `freertos` + `abstraction-rtos`)

- `FreeRTOSConfig.h` is first-party (copied from the library template). Check: `configASSERT` defined (and what it does in Release), `configCHECK_FOR_STACK_OVERFLOW 2` with `vApplicationStackOverflowHook` implemented, `configUSE_MALLOC_FAILED_HOOK 1`, heap scheme (`heap_4`/`heap_5` vs newlib `malloc` — mixing two allocators silently is a defect), `configTOTAL_HEAP_SIZE` sanity, `configUSE_TICKLESS_IDLE` and the low-power hook.
- Interrupt priorities: on PSoC 6 CM4, ISRs that call `...FromISR` APIs must have a priority at or below `configMAX_SYSCALL_INTERRUPT_PRIORITY`. `cyhal_*_enable_event(..., intr_priority, ...)` sets the priority; check that values used are compatible. A violation causes rare, hard-to-reproduce crashes — Red.
- `cyhal` callbacks (GPIO, UART, timer, SPI, I2C events) run **in interrupt context**. Calling `printf`, `cy_log`, `xSemaphoreTake`, `vTaskDelay`, `cyhal_system_delay_ms`, `malloc`, or flash APIs from them is a defect. Recommend `xSemaphoreGiveFromISR` / `xTaskNotifyFromISR` and deferring work.
- `cy_rtos_*` wrappers from `abstraction-rtos` have the same context rules as the underlying RTOS.

## Low power

- `cyhal_syspm_register_callback` / `Cy_SysPm_RegisterCallback`: peripherals in use (UART, SPI, I2C, SMIF) must be able to refuse or prepare for DeepSleep. Missing callbacks lead to corrupted transfers or hangs around sleep transitions.
- `cyhal_syspm_deepsleep()` / tickless idle: check wake sources (GPIO, RTC, LPCOMP, Wi-Fi host-wake) are configured; otherwise the device never wakes.
- Battery products: look for `cyhal_system_delay_ms` busy loops, and polling in the idle loop that keeps the CPU active.

## Flash and storage

- Internal flash via `cyhal_flash_*` / `Cy_Flash_*`; emulated EEPROM via `cy_em_eeprom` (provides wear levelling and power-loss-safe writes — prefer it to raw row writes for frequently updated data). Raw `Cy_Flash_WriteRow` on every sensor sample is a wear finding — compute the lifetime from the flash endurance figure in the datasheet.
- Flash write/erase operations are blocking and interact with interrupts and code executing from flash; check the vendor's guidance for the part (e.g. whether the code runs from RAM during the write, and whether the other core is affected).
- External QSPI via SMIF (`serial-flash` library, `cy_smif`): XIP plus writes need care. kv-store (`kv-store` / `mtb-kvstore`) is often used for Wi-Fi credentials and config; check that it is used rather than raw flash, and whether sensitive values need encryption at rest.

## Security

- **PSoC 62/63 with MCUboot** (common for OTA via the `ota-update` / `anycloud-ota` library):
  - Look for MCUboot sample keys in the repo (`keys/cypress-test-ec-p256.pem`, `root-ec-p256.pem`, `cypress-test-rsa2k.pem`, etc.) and Makefile variables like `SIGN_KEY_FILE` pointing at them. Shipping with sample keys means anyone can sign firmware for your device — Red.
  - Private signing keys must not live in the application repo at all.
  - MCUboot config: `MCUBOOT_VALIDATE_PRIMARY_SLOT` enabled, `MCUBOOT_DOWNGRADE_PREVENTION` (needs overwrite-only or a security counter), `MCUBOOT_SWAP_USING_*` vs `MCUBOOT_OVERWRITE_ONLY` (overwrite-only has no rollback if the new image is bad), whether the application confirms the image (`boot_set_confirmed` or the OTA library's equivalent) only after a health check.
  - Check that the bootloader region is not writable by the application (flash map / protection).
- **PSoC 64 Secure MCU**: secure boot is enforced by the Cypress Bootloader and provisioning policy (`cysecuretools`, `policy/*.json`). Check the policy for debug access (`"m0p"`, `"m4"`, `"system"` access-port permissions — `"allowed"` in production is Red), `"rollback_counter"`, and which keys are provisioned. Test/dev provisioning packets checked into the repo are a finding.
- **Lifecycle / debug lock (all PSoC 6)**: production devices should move to the SECURE lifecycle (or equivalent eFuse programming) with debug access ports disabled or restricted. If nothing in the repo or docs mentions lifecycle transition / debug lock, raise an Amber `needs-verification` finding about the manufacturing flow.
- **Crypto and RNG**: `cyhal_trng` / `Cy_Crypto_Core_Trng` for entropy; check mbedTLS is wired to it (`cy-mbedtls-acceleration`, `MBEDTLS_ENTROPY_HARDWARE_ALT` with `mbedtls_hardware_poll`). `MBEDTLS_TEST_NULL_ENTROPY` or a `mbedtls_hardware_poll` returning constant/`rand()` data is Red.
- **Credentials in code examples**: ModusToolbox Wi-Fi/MQTT/AWS examples put `WIFI_SSID`, `WIFI_PASSWORD`, `MQTT_BROKER_ADDRESS`, `CLIENT_CERTIFICATE`, `CLIENT_PRIVATE_KEY`, `ROOT_CA_CERTIFICATE` in headers such as `wifi_config.h`, `mqtt_client_config.h`. Products derived from them often keep this. Hardcoded private keys or shared credentials — Red. Check also `MQTT_PORT 1883` / `MQTT_SECURE_CONNECTION 0`.
- **Secure sockets / TLS**: `cy_socket_setsockopt(..., CY_SOCKET_SO_TLS_AUTH_MODE, CY_SOCKET_TLS_VERIFY_NONE ...)` or `VERIFY_OPTIONAL` — Red. Check SNI/hostname is set (`CY_SOCKET_SO_SERVER_NAME_INDICATION`).
- **Debug output**: `cy_retarget_io` + `printf` everywhere is normal in examples; check what gets printed in Release (credentials, keys, tokens) and whether the debug UART accepts input commands.

## Wi-Fi / Bluetooth (AIROC, WHD, WCM, BTSTACK)

- `wifi-connection-manager` (`cy_wcm_*`): check reconnect handling (`cy_wcm_register_event_callback`, retry with back-off), and that `cy_wcm_connect_ap` results are handled. Security type should not be open/WEP/WPA-TKIP in production.
- Wi-Fi firmware/CLM blobs come from `wifi-host-driver` — record the version.
- BTSTACK (`btstack` library, `wiced_bt_*`): check pairing configuration (`wiced_bt_dev_..._io_capabilities`, LE Secure Connections, MITM protection), GATT permissions on sensitive attributes (`GATTDB_PERM_AUTH_WRITABLE`, etc.), and lengths in GATT write handlers (`p_req->len` copied into fixed buffers is a classic Red).

## Dependencies to record

From the `.mtb` files or `mtb_shared/` directory names: `mtb-pdl-cat1`, `mtb-hal-cat1`, BSP version, `freertos`, `abstraction-rtos`, `wifi-host-driver`, `wifi-connection-manager`, `secure-sockets`, `lwip`, `mbedtls` (also check `MBEDTLS_VERSION_STRING`), `mqtt` / `aws-iot-device-sdk-*`, `ota-update` / `anycloud-ota`, `mcuboot`, `btstack`, `kv-store`, `serial-flash`, `connectivity-utilities`. Old mbedTLS and lwIP versions are the most common sources of applicable CVEs.
