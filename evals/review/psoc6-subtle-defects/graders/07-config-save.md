---
type: llm
focus: trace
weight: 1
---

Either the non-atomic erase-then-program config save (power loss loses config, no CRC/redundancy) or the static cfg in protocol.c never being loaded so each save clobbers relay/schedule fields is flagged
