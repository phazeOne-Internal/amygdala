---
type: llm
focus: trace
weight: 1
---

The GATT write_cmd handler copying an attacker-controlled code_len into the 16-byte code buffer (and/or reading p[1] without checking len) is rated Red / must-fix with a file:line location
