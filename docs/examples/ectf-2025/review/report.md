# Firmware review — 2025 eCTF insecure example decoder (MITRE reference design)

**Date:** 2026-11-20 19:46 · **Generated:** 2026-11-24 21:43 GMT (UTC+0000) · **Version:** 2025 eCTF insecure example (reference design snapshot, Apache-2.0) · **Reviewer:** ./phazeOne amygdala:review  
**Platform:** Analog Devices MAX78000 (FTHR_RevA) · MSDK v2024_02 · bare-metal superloop, no RTOS · UART host link at 115200 baud · frames relayed from a TCP 'satellite' broadcast by host tooling (detection confidence: high)  
**Scope:** 22 first-party files, ~1,982 lines in `decoder/src/`, `decoder/inc/`, `decoder/startup_firmware.S`, `decoder/firmware.ld`, `decoder/Makefile`, `decoder/project.mk`, `decoder/Dockerfile`, `design/ectf25_design/`

## 🔴 Verdict: NOT READY FOR FIELD RELEASE

5 Red issue(s) must be fixed before this firmware ships.

| 🔴 Red | 🟠 Amber | 🟢 Green | Total |
|---|---|---|---|
| **5** | **13** | **4** | 22 |

## Summary

This is MITRE's deliberately insecure reference decoder for the 2025 eCTF: a MAX78000 firmware that receives subscription updates and broadcast TV frames from a host over UART and returns the frame contents for subscribed channels. As expected for an intentionally insecure example, it is not fit for field release: the UART packet parser lets a single oversized or undersized message corrupt or leak stack memory, and the content-protection model has no cryptography at all, so subscriptions can be forged, expired subscriptions never lapse, and frames are broadcast in cleartext. Robustness gaps (no watchdog, non-atomic flash updates, ignored host ACK failures, printf in an interrupt handler) would cause hangs and lost state in the field.

**Key risks**

- Any UART/broadcast message longer than 100 bytes overwrites the main loop's stack buffer (memory corruption, crash, possible code execution).
- A decode message shorter than 12 bytes makes the decoder stream ~64 KB of RAM beyond its buffer back to the host before faulting.
- Subscription updates are accepted from anyone, for any decoder ID, with no signature or MAC: subscriptions can be forged.
- Frames are cleartext and unauthenticated, and timestamps are ignored: anyone on the broadcast sees every channel, expired subscriptions keep working, and old or forged frames are accepted.
- No watchdog and spin-forever fault handlers: once the decoder faults it stays hung until power-cycled.

**What is working well**

- Wire structures are explicitly packed (#pragma pack) and match the host's struct.pack layouts, so the protocol layout itself is unambiguous.
- The emergency channel (0) cannot be overwritten by a subscription update, and list_channels() is bounded by MAX_CHANNEL_COUNT, so the list response cannot overflow.
- Persistent state lives in a dedicated flash page (second to last page) outside the application image, and a first-boot canary initialises it to a known state.
- The build is containerised (Dockerfile) with the MSDK pinned to the v2024_02 release tag, and -Wall is enabled.
- The wolfSSL crypto example, which uses an all-zero key, is compiled out of the default build.

## RAG scorecard

| Area | Rating | R | A | G | Coverage |
|---|---|---|---|---|---|
| Memory safety | 🔴 RED | 2 | 1 | 0 | Reviewed — All first-party C in decoder/src and decoder/inc read line by line; UART input traced from read_header() to every consumer. |
| Security | 🔴 RED | 3 | 2 | 2 | Reviewed — Subscription, frame and list paths reviewed together with the host-side encoder and subscription generator in design/. |
| Secure boot & OTA | 🟠 AMBER | 0 | 1 | 0 | Partial — The eCTF bootloader that verifies and installs images is not in this repository; only the application side (linker layout, tools/ectf25/utils/flash.py) was reviewed. |
| Robustness & recovery | 🟠 AMBER | 0 | 3 | 0 | Reviewed — Init, error paths, startup fault handlers and flash persistence reviewed. |
| Concurrency & real-time | 🟠 AMBER | 0 | 1 | 0 | Reviewed — Bare-metal superloop with one registered interrupt (flash controller); no RTOS. |
| Hardware, storage & power | 🟠 AMBER | 0 | 1 | 0 | Partial — Flash usage reviewed; MSDK flash controller driver internals and power/sleep behaviour not reviewed; no hardware testing performed. |
| Third-party dependencies | 🟠 AMBER | 0 | 1 | 0 | Partial — MSDK version taken from the Dockerfile; OSV.dev lookup skipped (no consent); wolfSSL not present and not compiled in. |
| Field readiness & diagnostics | 🟠 AMBER | 0 | 1 | 0 | Reviewed — Versioning, diagnostics, reset-reason handling and debug leftovers reviewed. |
| Regulatory compliance | 🟠 AMBER | 0 | 1 | 0 | Partial — Code-evidenced items mapped; process items (disclosure policy, support period, SBOM, provisioning) cannot be shown from code. Engineering guidance, not legal advice; the compliance owner should confirm applicability and dates. |
| Code quality & style | 🟠 AMBER | 0 | 1 | 2 | Reviewed — Build flags, string formatting and test/CI presence reviewed. tools/ got a light pass only. |

## 🔴 Must fix before release

| ID | Issue | Location | Effort |
|---|---|---|---|
| [FW-001](#fw-001) | UART packet length (up to 65,535) copied into 100-byte stack buffer without a bounds check | `decoder/src/host_messaging.c:197` | S |
| [FW-002](#fw-002) | frame_size underflows for decode messages shorter than 12 bytes, streaming ~64 KB of RAM to the host | `decoder/src/decoder.c:263` | S |
| [FW-003](#fw-003) | Subscription updates accepted without authentication, integrity check or decoder-ID match | `decoder/src/decoder.c:216` | L |
| [FW-004](#fw-004) | Broadcast frames are cleartext and unauthenticated; the decoder only echoes the payload | `design/ectf25_design/encoder.py:57` | L |
| [FW-005](#fw-005) | Frame timestamps ignored: subscription windows never expire and old or out-of-order frames are accepted | `decoder/src/decoder.c:266` | M |

## Findings

### 🔴 Red — Must fix before release / ASAP

#### FW-001

**🔴 RED · UART packet length (up to 65,535) copied into 100-byte stack buffer without a bounds check**

**Area:** Memory safety · **Location:** `decoder/src/host_messaging.c:197` · **Confidence:** confirmed · **Effort:** S

**References:** CWE-121, CWE-787, CWE-20, ETSI EN 303 645 5.13, EU CRA Annex I

**What's wrong.** read_packet() takes the 16-bit length straight from the message header and passes it to read_bytes(), which writes that many bytes into the caller's buffer. The only caller passes main()'s 100-byte stack array, and neither function knows or checks the buffer size. Frames reach this path verbatim from the satellite broadcast (tools/ectf25/tv forwards the received bytes unchanged), so the length is controlled by whoever can inject into the broadcast or talk to the UART.

**Field impact.** Any message with a body over 100 bytes overwrites main()'s other locals, saved registers and the top of the stack (the stack sits at the end of SRAM). The mild outcome is a crash that hangs the decoder until power-cycle (see FW-010); the severe one is attacker-influenced corruption of control data, giving code execution on the decoder and access to everything it holds. One malformed frame in the broadcast could take down every decoder listening.

```c
// decoder.c main()
uint8_t uart_buf[100];
result = read_packet(&cmd, uart_buf, &pkt_len);

// host_messaging.c read_packet()
if (header.len && buf != NULL) {
    if (read_bytes(buf, header.len) < 0) {   // header.len is a uint16_t from the wire

// read_bytes()
((uint8_t *)buf)[i] = result;              // i runs to len-1
```

**Also at:** `decoder/src/host_messaging.c:38`, `decoder/src/decoder.c:375`, `decoder/src/decoder.c:391`

**Recommendation.** Pass the destination capacity into read_packet() and reject (after draining) any header whose length exceeds it, before reading the body:

int read_packet(msg_type_t *cmd, void *buf, size_t cap, uint16_t *len);
...
if (header.len > cap) { drain(header.len); return -1; }

Also check per command that pkt_len equals the expected structure size (FW-002, FW-012). Test: send messages of 0, 99, 100, 101 and 65,535 bytes and confirm the decoder rejects the oversize ones and keeps running.

#### FW-002

**🔴 RED · frame_size underflows for decode messages shorter than 12 bytes, streaming ~64 KB of RAM to the host**

**Area:** Memory safety · **Location:** `decoder/src/decoder.c:263` · **Confidence:** confirmed · **Effort:** S

**References:** CWE-191, CWE-125, CWE-200, ETSI EN 303 645 5.13, EU CRA Annex I

**What's wrong.** decode() subtracts the 12-byte header (channel + timestamp) from pkt_len without first checking pkt_len >= 12, and stores the result in a uint16_t. A shorter packet wraps to 65,524-65,535. The value is then used as the length for write_packet(), which reads from new_frame->data (offset 12 into the 100-byte uart_buf). There is also no upper check: any pkt_len from 77 to 100 returns more than the 64-byte FRAME_SIZE, including stale bytes left from earlier messages. Because the channel field is read from stale buffer contents for a short packet, an emergency-channel (0) value left from a previous frame is enough to pass is_subscribed().

**Field impact.** A short decode message makes the decoder transmit the rest of the stack (other locals, saved registers, previously received message bytes) to the host, then run off the end of SRAM and fault, hanging until power-cycle. Anyone who can inject a frame into the broadcast or reach the UART can crash decoders on demand and read memory they should not see.

```c
uint16_t frame_size;
// Frame size is the size of the packet minus the size of non-frame elements
frame_size = pkt_len - (sizeof(new_frame->channel) + sizeof(new_frame->timestamp));
...
write_packet(DECODE_MSG, new_frame->data, frame_size);
```

**Also at:** `decoder/src/decoder.c:275`

**Recommendation.** Validate the length before doing arithmetic on it:

const size_t hdr = sizeof(new_frame->channel) + sizeof(new_frame->timestamp);
if (pkt_len < hdr || pkt_len > sizeof(frame_packet_t)) { print_error("bad frame length\n"); return -1; }
frame_size = pkt_len - hdr;

Test with pkt_len values 0, 11, 12, 76, 77 and 100 on hardware and confirm only 12..76 are accepted.

#### FW-003

**🔴 RED · Subscription updates accepted without authentication, integrity check or decoder-ID match**

**Area:** Security · **Location:** `decoder/src/decoder.c:216` · **Confidence:** confirmed · **Effort:** L

**References:** CWE-306, CWE-345, CWE-639, ETSI EN 303 645 5.5, ETSI EN 303 645 5.13, EU CRA Annex I

**What's wrong.** A subscription update is a plain 24-byte structure (decoder ID, start, end, channel). The host generator packs it without any signature or MAC, and the firmware writes it to flash after checking only that the channel is not 0. The decoder_id field is never compared with the DECODER_ID the Makefile compiles in (the macro is defined but unused), and start <= end is not checked.

**Field impact.** Anyone with access to the decoder's host interface can grant themselves any channel for any time window, and a subscription issued for one decoder works on every decoder. The core business control of the product, paid channel access, can be bypassed without any secret.

```c
int update_subscription(pkt_len_t pkt_len, subscription_update_packet_t *update) {
    if (update->channel == EMERGENCY_CHANNEL) { ... return -1; }
    for (i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (... == update->channel || !...active) {
            ...start_timestamp = update->start_timestamp;
            ...end_timestamp = update->end_timestamp;

# gen_subscription.py
return struct.pack("<IQQI", device_id, start, end, channel)
```

**Also at:** `decoder/src/decoder.c:427`, `design/ectf25_design/gen_subscription.py:46`, `decoder/Makefile:253`

**Recommendation.** Make subscriptions verifiable on the device: have the host sign or MAC each update (for example an AEAD or Ed25519 signature keyed per deployment or per decoder, with keys provisioned at build time from global.secrets), verify it on the decoder before parsing the fields, then require decoder_id == DECODER_ID and start <= end. Reject on any failure without touching flash. Test: a valid update applies; one with a modified field, a different decoder ID or no tag is rejected and flash is unchanged.

#### FW-004

**🔴 RED · Broadcast frames are cleartext and unauthenticated; the decoder only echoes the payload**

**Area:** Security · **Location:** `design/ectf25_design/encoder.py:57` · **Confidence:** confirmed · **Effort:** L

**References:** CWE-311, CWE-345, ETSI EN 303 645 5.5, EU CRA Annex I

**What's wrong.** The encoder prepends channel and timestamp to the raw frame; nothing is encrypted or authenticated, and the secrets file it loads is unused. The decoder's subscription check only gates whether this particular decoder repeats the frame; the content itself is already readable on the broadcast. There is no check that a frame came from the legitimate uplink.

**Field impact.** Anyone who receives the broadcast can watch every channel without a decoder or a subscription, and anyone who can inject into the broadcast can make every decoder display content of their choosing, including on the emergency channel that all decoders accept. Content protection, the purpose of the device, is absent.

```c
# encoder.py
return struct.pack("<IQ", channel, timestamp) + frame

// decoder.c decode()
if (is_subscribed(channel)) {
    /* The reference design doesn't need any extra work to decode ... */
    write_packet(DECODE_MSG, new_frame->data, frame_size);
```

**Also at:** `decoder/src/decoder.c:271`, `decoder/src/decoder.c:275`

**Recommendation.** Encrypt and authenticate each frame with per-channel keys (an AEAD such as AES-GCM or ChaCha20-Poly1305, with a unique nonce per frame derived from the timestamp), and give each decoder only the keys for the channels it is subscribed to, wrapped so that only that decoder can unwrap them. Verify the tag on the decoder before releasing any plaintext. Test: a tampered or replayed frame is rejected; a frame for an unsubscribed channel cannot be decrypted.

#### FW-005

**🔴 RED · Frame timestamps ignored: subscription windows never expire and old or out-of-order frames are accepted**

**Area:** Security · **Location:** `decoder/src/decoder.c:266` · **Confidence:** confirmed · **Effort:** M

**References:** CWE-294, CWE-613, ETSI EN 303 645 5.5, EU CRA Annex I

**What's wrong.** The frame timestamp is never read. is_subscribed() checks only that a channel slot is active, never that the frame's timestamp lies within [start_timestamp, end_timestamp]. The decoder also keeps no record of the last accepted timestamp, so there is no monotonic check even though the encoder guarantees strictly increasing timestamps. Subscriptions are never deactivated.

**Field impact.** Once a decoder has ever been subscribed to a channel it decodes that channel forever, so time-limited subscriptions cannot be sold or revoked. Recorded frames can be replayed later, or frames reordered, and the decoder will play them. Once frames are authenticated (FW-004) this becomes the replay gap.

```c
// The reference design doesn't use the timestamp, but you may want to in your design
// timestamp_t timestamp = new_frame->timestamp;
...
int is_subscribed(channel_id_t channel) {
    ...
    if (...id == channel && ...active) {
        return 1;
```

**Also at:** `decoder/src/decoder.c:143`

**Recommendation.** In decode(), after authenticating the frame: require start <= timestamp <= end for the matching subscription (skip the window for channel 0), and require timestamp > last_timestamp, keeping last_timestamp in RAM (persist it only if replay across reboots matters). Test: frames before start, after end, and with a repeated or decreasing timestamp are all rejected.

### 🟠 Amber — Fix before release, or EM formally accepts risk

#### FW-012

**🟠 AMBER · Subscription packet length never checked against the 24-byte structure**

**Area:** Memory safety · **Location:** `decoder/src/decoder.c:216` · **Confidence:** confirmed · **Effort:** S

**References:** CWE-130, CWE-20, ETSI EN 303 645 5.13

**What's wrong.** update_subscription() receives pkt_len but never uses it. A short subscribe message is interpreted using whatever bytes earlier messages left in uart_buf, and a long one is silently accepted (the long case also overflows the buffer, FW-001).

**Field impact.** A truncated subscribe message from the host (line noise, a host bug) installs a subscription built from stale frame data, with a random channel or time window, and persists it to flash. The reads stay inside uart_buf, so this is a correctness and integrity bug rather than a memory-disclosure one.

```c
int update_subscription(pkt_len_t pkt_len, subscription_update_packet_t *update) {
    // pkt_len is never used
...
update_subscription(pkt_len, (subscription_update_packet_t *)uart_buf);
```

**Also at:** `decoder/src/decoder.c:427`

**Recommendation.** Reject the message unless pkt_len == sizeof(subscription_update_packet_t) (or the authenticated message size once FW-003 is fixed), and clear uart_buf between messages. Apply the same exact-size rule to every command handler.

#### FW-011

**🟠 AMBER · Obfuscated embedded secret (boot reference flag) is deobfuscated and sent to any host on every List command**

**Area:** Security · **Location:** `decoder/src/decoder.c:161` · **Confidence:** confirmed · **Effort:** S

**References:** CWE-798, CWE-489, CWE-200, ETSI EN 303 645 5.4, ETSI EN 303 645 5.6

**What's wrong.** A secret is stored in the image as two obfuscated constant arrays, recovered at run time and printed as a debug message whenever the host sends a List command. The source marks it as a reference-design leftover to remove. Obfuscation is not protection: the value is in every image and is handed to any host that asks.

**Field impact.** Any secret handled this way is exposed to whoever can send a List command or read the firmware image. In the eCTF this is the intended boot check; in a product it is the pattern by which keys leak, and it should not survive into a release build.

```c
// TODO: remove this from your final design
typedef uint32_t aErjfkdfru;const aErjfkdfru aseiFuengleR[]={0x1f… [redacted]};...

void boot_flag(void) {
    ...
    sprintf(output_buf, "Boot Reference Flag: %s\n", flag);
    print_debug(output_buf);
}
...
case LIST_MSG:
    boot_flag();
```

**Also at:** `decoder/src/decoder.c:131`, `decoder/src/decoder.c:414`

**Recommendation.** Remove boot_flag() and the obfuscated arrays from release builds (or guard them with a debug-only build flag that the release target cannot set). Keep real secrets out of source entirely; provision them per device and keep them in protected storage.

#### FW-014

**🟠 AMBER · Debug port lock and flash read-out protection not evidenced**

**Area:** Security · **Location:** `decoder/src/decoder.c:289` · **Confidence:** needs-verification · **Effort:** M

**References:** CWE-1191, ETSI EN 303 645 5.4, ETSI EN 303 645 5.6, EU CRA Annex I

**What's wrong.** Nothing in the firmware or build disables SWD or enables read-out protection, and subscription state (and any future keys) is stored in plain on-chip flash. On the MAX78000 this is normally done in the bootloader or at manufacturing, which is outside this repository.

**Field impact.** With the debug port open, anyone with physical access can read the image and its flash state, extract keys once they exist (FW-003/FW-004 fixes), or rewrite subscriptions directly.

**Recommendation.** Confirm the production flow locks SWD and enables flash protection on the MAX78000, and record it in the provisioning procedure. Keep key material in the device's protected storage rather than in the application image.

#### FW-013

**🟠 AMBER · Secure boot and authenticity of firmware updates not evidenced in this repository**

**Area:** Secure boot & OTA · **Location:** `decoder/firmware.ld:4` · **Confidence:** needs-verification · **Effort:** L

**References:** CWE-494, CWE-345, ETSI EN 303 645 5.3, ETSI EN 303 645 5.7, EU CRA Annex I

**What's wrong.** The application is linked to run behind a separate bootloader that is not part of this repository. The build produces a raw .bin with no signing step, and the host update tool streams that image to the bootloader in blocks. Whether the bootloader verifies a signature, prevents rollback or protects itself cannot be judged from here.

**Field impact.** If the bootloader accepts unsigned images, anyone with UART access can replace the decoder firmware, which defeats every other control in this report. If it has no fallback, an interrupted update bricks the unit.

```c
BOOTLOADER  (rx) : ORIGIN = 0x10000000, LENGTH = 0x0000E000 /* Bootloader flash */
FLASH       (rx) : ORIGIN = 0x1000E000, LENGTH = 0x00038000 /* Location of team firmware */
```

**Also at:** `tools/ectf25/utils/flash.py:58`

**Recommendation.** Obtain and review the bootloader, or document its guarantees. For a product: sign release images in the build, verify the signature in the bootloader before boot and before install, enforce a monotonic version for anti-rollback, and keep a fallback image. This becomes Red if the bootloader is found to accept unsigned images.

#### FW-006

**🟠 AMBER · read_ack() returns uint8_t, so every 'read_ack() < 0' failure check is dead code**

**Area:** Robustness & recovery · **Location:** `decoder/src/host_messaging.c:63` · **Confidence:** confirmed · **Effort:** S

**References:** CWE-681, CWE-252, CWE-570

**What's wrong.** read_ack() is declared to return uint8_t, so -1 is returned as 255 and every caller's '< 0' test is always false (cppcheck unsignedLessThanZero, 5 sites). A non-ACK reply from the host is therefore treated as an ACK and the decoder carries on sending. read_ack() also reads only the 4-byte header of whatever arrived and never drains its body, and read_header() stores negative uart_readbyte() error codes into char fields unchecked.

**Field impact.** Flow control and error reporting on the host link do not work: if the host sends anything other than an ACK (a new command, an error, line noise), the decoder ignores the failure, keeps transmitting, and leaves the unread body in the UART stream, so the next read_packet() parses payload bytes as a header. In the field this shows up as intermittent protocol desynchronisation and lost or garbled frames that are hard to diagnose.

```c
uint8_t read_ack() {
    ...
    if (ack_buf.cmd == ACK_MSG) {
        return 0;
    } else {
        return -1;     // becomes 255
    }
}
...
if (type != DEBUG_MSG && read_ack() < 0) {   // never true
```

**Also at:** `decoder/src/host_messaging.c:86`, `decoder/src/host_messaging.c:115`, `decoder/src/host_messaging.c:122`, `decoder/src/host_messaging.c:155`, `decoder/src/host_messaging.c:162`, `decoder/src/host_messaging.c:49`

**Recommendation.** Return int from read_ack() (and update the prototype), check uart_readbyte() for negative values in read_header(), and on a non-ACK either drain the announced body or resynchronise explicitly. Build with -Wextra -Wsign-compare -Wtype-limits so the compiler flags this class. Test: have a host reply with an error message instead of an ACK mid-transfer and confirm write_packet() returns -1.

#### FW-008

**🟠 AMBER · Subscription store is erased then rewritten non-atomically with all flash return codes ignored**

**Area:** Robustness & recovery · **Location:** `decoder/src/decoder.c:243` · **Confidence:** confirmed · **Effort:** M

**References:** CWE-252, CWE-662, ETSI EN 303 645 5.9

**What's wrong.** Every subscription update erases the single status page and then writes the whole structure back. Both return codes are discarded and success is reported to the host regardless. There is no second copy, sequence number or CRC; the only integrity marker is the first-boot canary, which is itself erased in the window.

**Field impact.** A power loss between erase and write (seconds-scale risk on every subscribe) leaves the page blank, so the next boot treats the device as new and silently deletes every subscription the customer paid for. A failed write is reported to the host as a success, so the host and decoder disagree about subscriptions until the next reboot, when RAM and flash diverge.

```c
flash_simple_erase_page(FLASH_STATUS_ADDR);
flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
// Success message with an empty body
write_packet(SUBSCRIBE_MSG, NULL, 0);
```

**Also at:** `decoder/src/decoder.c:317`, `decoder/src/decoder.c:296`

**Recommendation.** Use two pages (A/B) with a sequence number and CRC: write the new record to the inactive page, verify it, then mark it current; at boot load the newest valid copy. Check every flash return code and report failure to the host with print_error(). Test by cutting power at random points during repeated subscribe operations and confirming the previous or new state always survives.

#### FW-010

**🟠 AMBER · No watchdog, and fault handlers and init failure spin forever**

**Area:** Robustness & recovery · **Location:** `decoder/src/decoder.c:326` · **Confidence:** likely · **Effort:** M

**References:** CWE-835, CWE-703, ETSI EN 303 645 5.9

**What's wrong.** No watchdog timer is configured anywhere in first-party code. HardFault, BusFault, MemManage and UsageFault are weak 'b .' loops in the startup file (unless the MSDK links a stronger definition; confirm in the build map), and a UART init failure parks the CPU in while(1). Nothing records why the device stopped.

**Field impact.** Any fault, including the ones FW-001 and FW-002 make trivially reachable, leaves the decoder hung with a frozen picture until someone power-cycles it, and nobody can tell afterwards what happened. For a set-top style device this is a support call per incident.

```c
// decoder.c init()
if (ret < 0) {
    STATUS_LED_ERROR();
    // if uart fails to initialize, do not continue to execute
    while (1);
}

// startup_firmware.S
.weak \handler_name
\handler_name :
    b    .
...
def_irq_handler HardFault_Handler
```

**Also at:** `decoder/startup_firmware.S:301`, `decoder/startup_firmware.S:306`

**Recommendation.** Enable the MAX78000 watchdog (MXC_WDT) early in init(), feed it from the main loop only after a full command has been handled, and implement fault handlers that save the fault registers and PC to a .noinit RAM record before calling NVIC_SystemReset(). Replace while(1) on init failure with a logged reset after a back-off.

#### FW-007

**🟠 AMBER · printf called inside the flash controller interrupt handler**

**Area:** Concurrency & real-time · **Location:** `decoder/src/simple_flash.c:39` · **Confidence:** confirmed · **Effort:** S

**References:** CWE-479, CWE-662

**What's wrong.** flash_simple_irq() is registered as the FLC0 interrupt handler and calls printf() when a flash access-failure interrupt fires. printf() is not interrupt-safe: newlib's stdio state is shared with the main loop (which itself uses printf in write_hex()), and the MSDK retargets output to blocking UART writes. Rated Amber rather than the checklist's default Red because this is a bare-metal superloop with no RTOS locks to deadlock on, and the trigger is a flash access failure rather than normal operation; it becomes Red if an RTOS or buffered/locked stdio is introduced.

**Field impact.** When a flash access fault occurs (for example a write to a protected address, or during a power dip), the ISR spends tens of characters' worth of UART time blocking with interrupts held, can corrupt stdio state if it interrupts a printf in the main loop, and injects raw text into the binary host protocol, which desynchronises the host. The original fault is then harder to diagnose, not easier.

```c
void flash_simple_irq(void) {
    ...
    if (temp & MXC_F_FLC_INTR_AF) {
        MXC_FLC0->intr &= ~MXC_F_FLC_INTR_AF;
        printf(" -> Interrupt! (Flash access failure)\n\n");
    }
}
...
MXC_NVIC_SetVector(FLC0_IRQn, flash_simple_irq);
```

**Also at:** `decoder/src/simple_flash.c:51`

**Recommendation.** In the ISR, only clear the flag and set a volatile status variable (for example volatile uint32_t flash_fault_count++); report it from the main loop through print_error(). Have flash_simple_write()/erase return that status so callers can act on it (see FW-008).

#### FW-009

**🟠 AMBER · Flash page erased on every subscription message with no rate limit or change check**

**Area:** Hardware, storage & power · **Location:** `decoder/src/decoder.c:243` · **Confidence:** likely · **Effort:** S

**References:** CWE-400, CWE-1246

**What's wrong.** Each accepted subscription update, including one identical to what is already stored, erases and rewrites the same flash page. Because updates are unauthenticated (FW-003), the host side can issue them as fast as the UART allows. On-chip flash is rated for a finite number of erase cycles per page (check the MAX78000 data sheet for the exact figure; it is in the order of ten thousand).

**Field impact.** A misbehaving or malicious host loop can wear out the status page within hours of continuous updates, after which subscriptions can no longer be stored reliably and the decoder may lose its configuration on every boot. Normal use is unlikely to reach the limit, which is why this is Amber.

```c
flash_simple_erase_page(FLASH_STATUS_ADDR);
flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
```

**Recommendation.** Skip the write when the record is unchanged, rate-limit updates, and spread writes across several pages with the A/B scheme from FW-008 (a simple log-structured record with a sequence number also levels wear).

#### FW-015

**🟠 AMBER · Build environment fetches MSDK and packages without checksum or version pinning; no SBOM**

**Area:** Third-party dependencies · **Location:** `decoder/Dockerfile:30` · **Confidence:** confirmed · **Effort:** S

**References:** CWE-494, CWE-1104, EU CRA Annex I Part II

**What's wrong.** The MSDK is pinned to a release tag but downloaded without verifying a checksum, the base image is a floating tag, and the compiler and all apt packages float with 'apt-get upgrade'. No SBOM is produced. MSDK v2024_02 is from early 2024; check ADI's release notes for later fixes to the drivers used (UART, FLC).

**Field impact.** Two builds of the same commit can use different compilers and SDK content, so a field issue may not be reproducible, and a tampered download would go unnoticed. Regulators under the CRA will expect an SBOM.

```c
FROM ubuntu:24.04
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    gcc-arm-none-eabi ...
    wget https://github.com/analogdevicesinc/msdk/archive/refs/tags/v2024_02.zip && \
```

**Also at:** `decoder/Dockerfile:5`, `decoder/Dockerfile:15`

**Recommendation.** Pin the base image by digest, pin gcc-arm-none-eabi and other packages to versions, verify the MSDK zip with a sha256sum, and generate an SBOM (for example with syft) as part of the release build.

#### FW-016

**🟠 AMBER · No firmware version, reset-reason reporting or crash record**

**Area:** Field readiness & diagnostics · **Location:** `decoder/src/decoder.c:373` · **Confidence:** confirmed · **Effort:** S

**References:** ETSI EN 303 645 5.10, NIST IR 8425, EU CRA Annex I

**What's wrong.** The image embeds no version or build ID and no command returns one; the reset reason is never read; there is no crash record across reboot (see FW-010). The hotspot scan found no version definition, reset-reason or fault-handler code in first-party sources.

**Field impact.** When decoders misbehave in the field, support cannot tell which firmware they run or why they rebooted, so fixes cannot be targeted or confirmed.

**Recommendation.** Embed a version string and git hash at build time, expose them through a host command, read and report the MAX78000 reset cause at boot, and add the .noinit crash record from FW-010.

#### FW-017

**🟠 AMBER · Regulatory process items not evidenced: disclosure policy, support period, SBOM, provisioning**

**Area:** Regulatory compliance · **Location:** `README.md` · **Confidence:** needs-verification · **Effort:** M

**References:** UK PSTI, ETSI EN 303 645 5.2, EU CRA Annex I Part II

**What's wrong.** The repository contains no SECURITY.md or vulnerability disclosure contact, no stated security support period, no SBOM step and no per-device provisioning procedure. These are required by the EU CRA, UK PSTI and ETSI EN 303 645 for consumer connected products. This is engineering guidance, not legal advice; the compliance owner should confirm which regimes apply to the product and their current dates.

**Field impact.** Without them the product cannot be placed on the EU or UK market once those obligations apply, regardless of code quality.

**Recommendation.** Publish a vulnerability disclosure policy and contact, state the support period, add SBOM generation to the release build (FW-015), and document per-device key provisioning and debug lock at manufacturing (FW-014). Close each item with a link to the evidence.

#### FW-018

**🟠 AMBER · No unit tests for the packet parser and only -Wall in the build**

**Area:** Code quality & style · **Location:** `decoder/Makefile:252` · **Confidence:** confirmed · **Effort:** M

**References:** CWE-1164

**What's wrong.** The UART parser and command handlers have no host-side unit or fuzz tests, and the build does not use -Wextra, -Wsign-compare or -Wconversion, which would have flagged FW-002 and FW-006. The tools/ testers exercise the happy path through hardware only.

**Field impact.** Length and signedness defects like FW-001, FW-002 and FW-006 go unnoticed until they fail in the field.

```c
PROJ_CFLAGS += -Wall # Enable warnings
```

**Recommendation.** Compile host_messaging.c and the decode/subscribe handlers on the host against a fake UART and fuzz read_packet() with libFuzzer or AFL; add -Wextra -Wconversion -Wsign-compare and run cppcheck/semgrep in CI.

### 🟢 Green — Improve when convenient

#### FW-020

**🟢 GREEN · Crypto example (compiled out) uses an all-zero AES key, raw ECB blocks and MD5**

**Area:** Security · **Location:** `decoder/src/simple_crypto.c:51` · **Confidence:** confirmed · **Effort:** S

**References:** CWE-327, CWE-328, CWE-1204

**What's wrong.** The optional wolfSSL example encrypts each 16-byte block independently (ECB), with no IV or authentication, demonstrates it with an all-zero key, and offers MD5 as the hash. It is disabled in the default build (CRYPTO_EXAMPLE=0), which is why this is Green.

**Field impact.** None in the shipped build. If a team enables it as the basis of FW-004's fix, frames would leak patterns and be forgeable, which would be Red.

```c
// decoder.c
bzero(key, BLOCK_SIZE);
encrypt_sym((uint8_t*)data, BLOCK_SIZE, key, ciphertext);

// simple_crypto.c
result = wc_AesEncryptDirect(&ctx, ciphertext + i, plaintext + i);   // per-block ECB
return wc_Md5Hash((uint8_t *)data, len, hash_out);
```

**Also at:** `decoder/src/decoder.c:348`, `decoder/src/simple_crypto.c:105`, `decoder/project.mk:38`

**Recommendation.** Do not build on this example: use an AEAD mode (AES-GCM or ChaCha20-Poly1305) with unique nonces, SHA-256 or better, and provisioned keys.

#### FW-022

**🟢 GREEN · Host secrets generator logs the full secrets file at debug level**

**Area:** Security · **Location:** `design/ectf25_design/gen_secrets.py:90` · **Confidence:** confirmed · **Effort:** S

**References:** CWE-532

**What's wrong.** Host-side code. The secrets are placeholders today, so nothing sensitive is exposed, but the line will log real keys to the console and any log sink once the design gains them.

**Field impact.** Once real keys exist, they would end up in build logs and CI output.

```c
logger.debug(f"Generated secrets: {secrets}")
```

**Recommendation.** Log only that secrets were generated, and their path, never their content.

#### FW-019

**🟢 GREEN · sprintf used for all formatted output instead of snprintf**

**Area:** Code quality & style · **Location:** `decoder/src/decoder.c:279` · **Confidence:** confirmed · **Effort:** S

**References:** CWE-120

**What's wrong.** Every sprintf currently formats a bounded value (a 32-bit integer, a character, a 27-character string) into a 128-byte buffer, so none of the flawfinder/semgrep leads can overflow today. The pattern is fragile once someone adds a longer field.

**Field impact.** No field impact today; a future edit could introduce an overflow.

```c
char output_buf[128] = {0};
sprintf(output_buf, "Receiving unsubscribed channel data.  %u\n", channel);
```

**Also at:** `decoder/src/decoder.c:169`, `decoder/src/decoder.c:364`, `decoder/src/decoder.c:433`

**Recommendation.** Use snprintf(output_buf, sizeof output_buf, ...) throughout.

#### FW-021

**🟢 GREEN · First-boot initialisation writes uninitialised channel IDs to flash**

**Area:** Code quality & style · **Location:** `decoder/src/decoder.c:306` · **Confidence:** confirmed · **Effort:** S

**References:** CWE-457

**What's wrong.** The id field (and struct padding) of each default slot is never set, so stack garbage is persisted to flash. Every reader also checks active, so the garbage is never acted on today.

**Field impact.** No current field impact; makes flash contents non-deterministic and could matter if a future change reads id without active.

```c
channel_status_t subscription[MAX_CHANNEL_COUNT];
for (int i = 0; i < MAX_CHANNEL_COUNT; i++){
    subscription[i].start_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
    subscription[i].end_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
    subscription[i].active = false;
}
```

**Recommendation.** Zero the array first (memset or = {0}) before setting the defaults.

## Maintainability (code health)

**GOOD** — Most functions are small and testable; keep it that way with a complexity gate in CI. 0 of 30 functions (0%) are over the size / complexity thresholds; worst complexity 9.

_How hard this code is to change safely, measured rather than judged: function size and cyclomatic complexity per directory, and whether the driver and application layers stay apart. It is independent of the findings above: tidy code can hide a Red, and messy code can be correct today, but messy code is where the next defect is written._

| Functions | Files | Lines of code | Avg complexity | Max complexity | Over thresholds |
|---|---|---|---|---|---|
| 30 | 5 | 361 | 3.4 | 9 | 0 (0.0%) |

Thresholds: complexity > 15, > 100 lines, > 5 parameters. Functions over a threshold are hard to test completely and hard to review; they are leads, not defects.

| Directory | Files | Functions | Lines | Avg complexity | Max complexity | Over thresholds |
|---|---|---|---|---|---|---|
| `decoder/src` | 5 | 30 | 361 | 3.4 | 9 | 0 |

**Largest and most complex functions**

| Function | Location | Lines | Complexity | Params | Over |
|---|---|---|---|---|---|
| `read_packet()` | `decoder/src/host_messaging.c:178` | 25 | 9 | 3 | — |
| `write_hex()` | `decoder/src/host_messaging.c:106` | 21 | 8 | 3 | — |
| `main()` | `decoder/src/decoder.c:373` | 40 | 7 | 0 | — |
| `write_packet()` | `decoder/src/host_messaging.c:141` | 21 | 7 | 3 | — |
| `update_subscription()` | `decoder/src/decoder.c:216` | 26 | 6 | 2 | — |
| `encrypt_sym()` | `decoder/src/simple_crypto.c:35` | 15 | 6 | 4 | — |
| `decrypt_sym()` | `decoder/src/simple_crypto.c:71` | 15 | 6 | 4 | — |
| `write_bytes()` | `decoder/src/host_messaging.c:83` | 12 | 6 | 3 | — |
| `init()` | `decoder/src/decoder.c:289` | 23 | 5 | 0 | — |
| `read_bytes()` | `decoder/src/host_messaging.c:26` | 15 | 5 | 2 | — |
| `is_subscribed()` | `decoder/src/decoder.c:143` | 11 | 5 | 1 | — |

**Layering.** layers not inferable: no driver/HAL/BSP and application directories (or file-name conventions) found; pass --layer lower=<path> --layer upper=<path> to set them.


## Recommended next steps

1. Fix the two parser Reds (FW-001, FW-002) first: they are small, local changes and make every other test meaningful.
2. Design the content-protection scheme as one piece of work: authenticated, encrypted frames with per-channel keys (FW-004), signed decoder-specific subscriptions (FW-003), and timestamp window and monotonic checks (FW-005).
3. Add a watchdog, real fault handlers with a crash record, and A/B flash storage (FW-010, FW-008).
4. Add host-side unit and fuzz tests for read_packet() and the command handlers, plus -Wextra and cppcheck/semgrep in CI (FW-018).
5. Obtain the bootloader and confirm image signing, rollback protection and debug lock (FW-013, FW-014); generate a compile_commands.json with 'bear -- make' so clang-tidy can run next time.

## Coverage and method

| Tool | Status | Notes |
|---|---|---|
| detect_platform.py | ran | MAX78000 / MSDK detected with high confidence; no vendored directories in tree |
| hotspots.py | ran | 14 pattern leads plus 4 absence checks, including 1 printf inside an identified ISR; 10 contributed to findings |
| cppcheck | ran | Cppcheck 2.22.0; 5 files; 11 leads (unsignedLessThanZero on read_ack() became FW-006; uninitvar on boot flag judged a false positive) |
| clang-tidy | skipped | Homebrew LLVM 23.1.6 installed, but no compile_commands.json; not generated because that needs an MSDK build (bear -- make), which was out of scope for this run |
| flawfinder | ran | 2.0.20; min level 2; 5 leads (sprintf / memcpy), all with bounded sources; folded into FW-019 |
| semgrep | ran | 1.186.0; bundled embedded-c rules, local only, metrics off; 6 leads (ISR printf became FW-007) |
| OSV.dev dependency lookup | skipped | skipped (no consent): no user was available to approve sending dependency URLs to api.osv.dev; the plan found no machine-readable dependency manifests in any case |
| lizard | ran | 30 functions measured; 0 over thresholds (complexity > 15, > 100 lines, > 5 parameters); see Maintainability |

Excluded (vendored / generated): `tools/ (host test and harness tooling, light review only)`, `MSDK v2024_02 (not vendored; fetched at build time in the Dockerfile)`, `eCTF bootloader (not in repository)`. Third-party code was assessed for versions and configuration, not line-by-line.

**RAG key:** 🔴 Red — Must fix before release / ASAP · 🟠 Amber — Fix before release, or EM formally accepts risk · 🟢 Green — Improve when convenient · 🟡 Partial — partly reviewed, nothing found · ⚪ Not assessed — not reviewed.

_This is a static review of source code. It does not replace on-target testing, fuzzing or penetration testing. Regulatory mappings are engineering guidance, not legal advice; confirm applicability with your compliance owner._

## Acknowledgements

- Analysis tools used for this report: Cppcheck, Flawfinder (David A. Wheeler), Semgrep, Lizard (Terry Yin) for function size and complexity metrics.
- Classification, checklists and regulatory mapping draw on MITRE CWE, SEI CERT C, MISRA C, ETSI EN 303 645, EN 18031, NIST IR 8425, the OWASP Agentic Skills Top 10, SPDX and CycloneDX.
- Typeface: IBM Plex Mono by IBM (SIL Open Font License 1.1).
- Produced with the ./phazeOne firmware review skill for Claude Code. Our thanks to the maintainers of every project above.

---
Prepared by **./phazeOne** — IoT, Firmware and Hardware Solutions. https://www.phazeone.com/ · Need help with these findings? [Get in touch](https://www.phazeone.com/contact) · +44 (0) 1280 811117 · hello@phazeone.com
