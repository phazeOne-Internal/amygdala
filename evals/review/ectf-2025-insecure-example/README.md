# Eval fixture: MITRE eCTF 2025 insecure example

`files/2025-ectf-insecure-example/` is an unmodified copy (minus `.git`) of
<https://github.com/mitre-cyber-academy/2025-ectf-insecure-example> at commit `7c26fc2`,
Copyright (c) 2025 The MITRE Corporation, licensed under the Apache License 2.0
(see `files/2025-ectf-insecure-example/LICENSE.txt`).

It is the deliberately insecure reference design for the 2025 Embedded Capture the Flag
satellite-TV decoder (Analog Devices MAX78000, bare-metal MSDK). MITRE publishes it so teams have
a working but unsafe starting point. That makes it a good third-party test for `amygdala:review`:
real code, an SDK the skill has no dedicated platform reference for, and known weaknesses that are
documented by the competition rather than planted by us.

Nothing in it is a real secret. The `boot_flag()` blob is a competition flag, not key material.
