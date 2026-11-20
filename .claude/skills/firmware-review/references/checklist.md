# Firmware review checklist

The checks are grouped by the report categories (the `category` values in `findings.json`). Each item gives a **default RAG**. Adjust it using field impact and likelihood: a default-Red pattern that is provably unreachable drops, and a default-Amber one on an exposed network path rises.

Contents:
1. memory-safety
2. security
3. secure-boot-ota
4. robustness
5. concurrency
6. hardware-power
7. dependencies
8. field-readiness
9. regulatory (detail in regulatory.md)
10. code-quality

---

## 1. memory-safety

| Check | Default |
|---|---|
| Unbounded copies (`strcpy`, `strcat`, `sprintf`, `gets`, `scanf("%s")`, `vsprintf`) into fixed buffers from externally influenced data | Red |
| `memcpy`/`memmove`/array index using a length or offset taken from a packet, GATT write, UART frame, file or OTA header without bounds check against the destination | Red |
| Same as above, but the source is internal/trusted (e.g. a compile-time constant table) | Green–Amber |
| Off-by-one: `buf[sizeof buf]`, `<=` loop bounds, forgetting room for the NUL terminator, `strncpy` without forcing termination | Amber (Red on input path) |
| Integer overflow or truncation in length calculations (`uint8_t len = total`, `hdr_len + payload_len` wrapping, signed length compared against unsigned) | Red on input path, else Amber |
| Use-after-free, double free, returning a pointer to a stack buffer, dangling pointers stored in callbacks or queues | Red |
| Unchecked `malloc`/`pvPortMalloc`/`k_malloc` result | Amber |
| Dynamic allocation in steady-state (after init) on a long-running device — fragmentation over weeks of uptime | Amber |
| Large local arrays or recursion in tasks/ISRs with small stacks; task stack sizes with no evidence of measurement (no high-water-mark check) | Amber |
| Stack overflow detection disabled (e.g. `configCHECK_FOR_STACK_OVERFLOW 0`, no MPU guard, no `CONFIG_*_STACK_SENTINEL` / HW stack protection) | Amber |
| Format string vulnerabilities: `printf(user_string)` | Red if remote-influenced |
| Uninitialised variables used in decisions or sent off-device (information leak) | Amber |
| Unaligned access / type punning through pointer casts on packed protocol buffers (can HardFault on Cortex-M0/M0+) | Amber |
| `sizeof(pointer)` used where `sizeof(array)` was intended | Amber–Red |

## 2. security

| Check | Default |
|---|---|
| Hardcoded credentials: Wi-Fi passwords, cloud passwords, API keys, private keys, client certificates and keys, AES keys in source or headers | Red |
| Same credential/key shared across every unit (no per-device identity) | Red |
| Default or fixed passwords/PINs/BLE passkeys (`123456`, `admin`) for any user or service interface | Red (also a PSTI / EN 303 645 / CRA blocker) |
| TLS: certificate verification disabled (`MBEDTLS_SSL_VERIFY_NONE`, `VERIFY_OPTIONAL` without checking the result, `skip_cert_common_name_check`), hostname not checked, no root CA pinned or bundled | Red |
| Plaintext protocols carrying credentials or control commands (MQTT on 1883, HTTP, telnet) on a production path | Red |
| Weak or misused crypto: MD5/SHA-1 for integrity or signatures, DES/RC4, AES-ECB, static IVs/nonces, nonce reuse with CTR/GCM, home-grown crypto | Red–Amber |
| Insecure randomness: `rand()`/`srand(time)` or a counter used for keys, nonces, session IDs, or TLS entropy; mbedTLS null/test entropy | Red |
| Non-constant-time comparison of MACs, tokens, passwords (`memcmp`/`strcmp`) | Amber |
| Secrets written to logs or printed on a debug UART | Red |
| Debug interfaces left enabled in production: JTAG/SWD not locked, debug CLI/shell with privileged commands (factory reset, memory read/write, key dump), test backdoors, `#ifdef DEBUG` paths enabled by default in release builds | Red |
| Secrets kept in plain internal/external flash when a secure element, protected storage or encrypted store is available | Amber |
| Secrets not zeroised after use (keys left in RAM buffers), or zeroised with `memset` that the compiler can elide | Green–Amber |
| Commands from the cloud/app executed without authentication or authorisation (e.g. unlock, firmware update, config change) | Red |
| Replay: commands without nonce/sequence/timestamp protection where replay matters (locks, payments, actuators) | Red–Amber |
| BLE: Just Works pairing for sensitive functions, no bonding/encryption required on sensitive characteristics, legacy pairing | Red–Amber |
| Exposed network services/ports beyond what the product needs | Amber |
| Personal data collected or sent beyond need, or sent unencrypted (privacy — GDPR and similar) | Amber–Red |

## 3. secure-boot-ota

| Check | Default |
|---|---|
| No secure boot / image signature check at boot | Red for a connected product |
| Signing with vendor sample/development keys committed to the repo (e.g. MCUboot `root-rsa-2048.pem`, `root-ec-p256.pem`, `enc-*.pem`) | Red |
| Private signing key stored in the firmware repo at all | Red |
| OTA image accepted without signature verification, or verified only by CRC/hash with no signature | Red |
| Verification happens after the image is marked bootable, or the result is ignored | Red |
| No anti-rollback / downgrade prevention (attacker can install an older vulnerable signed image) | Amber |
| No A/B slot or fallback: a power loss or bad image during update bricks the device | Red |
| New image not confirmed after a health check (no test-boot then confirm; a crashing image keeps booting) | Amber–Red |
| OTA download not resumable, no timeout, no size limit check against the slot size | Amber |
| Update channel not authenticated (device downloads from any server, HTTP, no cert check) | Red |
| No way to update at all in the field | Red (CRA, EN 303 645 provision 5.3) |
| Bootloader itself not protected from being overwritten by the application | Amber |

## 4. robustness

| Check | Default |
|---|---|
| Return codes ignored from init, driver, network, flash and RTOS calls | Amber; Red if failure leads to corruption, lock-up or a security bypass |
| Error handling via `assert()`/`CY_ASSERT()`/`configASSERT()`/`__ASSERT()` only, where the assert is compiled out in release (`NDEBUG`) — execution silently continues in an invalid state | Amber–Red |
| Error path is `while(1);` / infinite loop with no watchdog to recover | Red |
| No hardware watchdog, or watchdog disabled in release | Red for unattended products |
| Watchdog fed from a timer ISR or a high-priority task regardless of system health (it never fires when the application hangs) | Amber–Red |
| Watchdog not compatible with sleep modes, OTA flash erase or long blocking operations (spurious resets in the field) | Amber |
| Fault handlers (HardFault, MemManage, BusFault, UsageFault) are empty or spin forever; no crash record kept across reset | Amber |
| Reset reason never read or reported | Amber (field readiness) |
| Blocking calls with infinite timeouts (`portMAX_DELAY`, `K_FOREVER`, `CYHAL_..._NEVER_TIMEOUT`) on network, peripheral or inter-task paths where the peer can fail | Amber |
| No reconnect/back-off for Wi-Fi/cellular/MQTT; tight reconnect loops that drain battery or hammer the cloud | Amber |
| Tick/time wraparound: `if (now > deadline)` instead of `(int32_t)(now - deadline) >= 0`; 32-bit ms counters wrap at ~49.7 days; 16-bit counters wrap much sooner | Amber–Red |
| Floating point equality, division by zero, sensor value ranges unchecked (NaN/garbage propagated to actuators or cloud) | Amber |
| Persistent config written non-atomically: power loss mid-write leaves corrupt config and the device fails to boot | Red |
| No CRC/version on stored config, no sane defaults if config is corrupt | Amber |
| Brown-out detection disabled or not handled around flash writes | Amber |
| Resource leaks: sockets, buffers, timers, semaphores not released on error paths | Amber |
| State machines with unhandled states/events, or `default:` cases that silently do nothing | Amber |

## 5. concurrency

| Check | Default |
|---|---|
| Data shared between ISR and task without `volatile` and without atomic access or a critical section | Amber–Red |
| Multi-byte or read-modify-write shared variables (counters, flags bitfields, 64-bit timestamps on 32-bit cores) updated from both ISR and task contexts unprotected | Amber–Red |
| Non-ISR-safe API called from ISR or from a vendor callback that runs in ISR context: blocking RTOS calls, mutexes, `printf`, `malloc`, logging, flash writes | Red (crash or lock-up) |
| FreeRTOS: ISR that calls `...FromISR` APIs has a priority above `configMAX_SYSCALL_INTERRUPT_PRIORITY` (numerically lower on Cortex-M) | Red |
| Long work inside ISRs (parsing, loops, delays) — latency and missed interrupts | Amber |
| Inconsistent lock ordering (deadlock), locks held across blocking I/O or network calls | Amber–Red |
| Priority inversion: mutex replaced by binary semaphore where a high-priority task waits on a low-priority one | Amber |
| Disabling interrupts for long periods; nested `__disable_irq()`/`__enable_irq()` that re-enables too early (use save/restore) | Amber |
| Check-then-act races (TOCTOU) on shared state or between cores | Amber |
| Multi-core (e.g. PSoC 6 CM0+/CM4): shared memory without IPC semaphore/locking, missing memory barriers, cache coherency on parts with cache | Red–Amber |
| Task priorities that starve the watchdog-feeding or network task | Amber |
| Unbounded queues or queue-full ignored (data silently dropped) | Amber |

## 6. hardware-power

| Check | Default |
|---|---|
| Flash/EEPROM writes on every sample or event; endurance budget not met over product life (e.g. 100k cycles ÷ writes per day) | Red if lifetime is under the warranty/support period, else Amber |
| Flash erase/write while executing from the same bank, or with interrupts executing from flash, without vendor-required precautions | Amber–Red |
| DMA buffers on the stack, not aligned, or shared with CPU without cache maintenance on cached parts | Amber–Red |
| Peripheral init order or clock config wrong; silicon errata for this part/revision not handled | Amber |
| Registers accessed without `volatile`, or read-modify-write on registers shared with other contexts | Amber |
| Low-power: peripherals not quiesced before sleep, not restored after wake; wake sources missing (device never wakes); sleep callbacks missing | Amber–Red |
| Busy-wait delays and polling loops that keep the CPU awake on a battery product | Amber |
| GPIO left floating or driven in sleep (leakage), unused pins not configured | Green–Amber |
| ADC/sensor readings without calibration, range or plausibility checks | Amber |
| Timing assumptions dependent on clock frequency hardcoded (delay loops) | Amber |
| Actuators (motors, relays, heaters, locks) without safe state on fault/reset/brown-out | Red if safety-relevant |

## 7. dependencies

| Check | Default |
|---|---|
| Third-party component with known exploitable CVEs in a used feature (TLS, TCP/IP, BLE stack, JSON/CBOR parser, bootloader). Check versions from manifests (`*.mtb`, `west.yml`, `idf_component.yml`, `library.json`, git submodules, version headers like `MBEDTLS_VERSION_STRING`, `tskKERNEL_VERSION_NUMBER`, `LWIP_VERSION`) | Red–Amber |
| End-of-life or unmaintained SDK/RTOS/library version | Amber |
| Dependencies not pinned (floating `latest`/branch refs) — builds not reproducible | Amber |
| No SBOM, or no way to produce one | Amber (CRA requires one) |
| Vendored libraries modified locally without record (patches lost on update) | Amber |
| License obligations (GPL code linked into proprietary firmware) | Amber — flag for legal |

When reporting CVEs, only cite IDs you are confident apply to the detected version; otherwise say "version X is old; check vendor advisories for CVEs affecting <feature>" and rate on age and exposure.

## 8. field-readiness

| Check | Default |
|---|---|
| No crash/fault record kept across reboot (noinit RAM, backup registers, flash log) and no way to retrieve it | Amber |
| No remote telemetry of health: reset reason, uptime, heap/stack high-water, connectivity stats | Amber |
| Firmware version, hardware revision, build ID not embedded or not readable remotely | Amber |
| Factory reset missing, or doesn't erase user data/credentials (privacy, resale) | Amber–Red |
| Provisioning: per-device credentials, unique IDs, secure injection in manufacturing | Red if absent on a connected product |
| Logging: no log levels, verbose debug logging in release, logs that can't be retrieved | Green–Amber |
| Manufacturing/test modes reachable in production units | Red |
| Graceful degradation: device still does its core local function when the cloud is unreachable | Amber |
| Time: no RTC/NTP strategy, certificate validity checks with no valid time | Amber |
| Configuration and calibration data survive firmware update | Amber |

## 9. regulatory

See `regulatory.md` for the mapping. In short, the items that most often block market access and should be Red when evidenced in code: universal default passwords, no security update mechanism, hardcoded shared secrets, insecure communications for sensitive data, debug backdoors. Process items (vulnerability disclosure policy, support period, SBOM, technical documentation) are usually `needs-verification` Amber unless the user tells you they are missing.

## 10. code-quality

Rate these mostly Green or Amber. Only raise to Red if the problem is itself producing a field defect (and then the defect is the finding).

| Check | Default |
|---|---|
| Builds with warnings, or warnings suppressed; no `-Wall -Wextra` (or equivalent) | Amber |
| Release build differs dangerously from debug (asserts removed with side effects inside them: `assert(init() == OK)`) | Red — the init call disappears in release |
| Very long/complex functions (many hundreds of lines, deep nesting) in critical paths | Amber |
| Magic numbers for timeouts, sizes, register values, protocol constants | Green |
| Duplicated logic that has already diverged (one copy fixed, the other not) | Amber |
| Dead code, `#if 0` blocks, commented-out code | Green |
| Mixed layers: application logic calling registers directly, HAL calls scattered through business logic | Green–Amber |
| Contradictory or untested `#ifdef` configurations | Amber |
| Units unclear (ms vs ticks, mV vs V); implicit conversions between them | Amber |
| No unit tests for parsers, state machines and protocol code; no CI build | Amber |
| Inconsistent naming/formatting; no `.clang-format` or style config | Green |
| Public APIs and ISR/thread-context contracts undocumented | Green |
| `TODO`/`FIXME`/`HACK` comments on security or reliability paths | Amber if the comment describes a known unfixed defect |

Style guidance without a formal standard: use CERT C and MISRA C:2012/2023 as the reference for *why* something is risky (cite rule IDs if helpful), but don't report a pure MISRA deviation that has no plausible defect behind it as anything above Green.
