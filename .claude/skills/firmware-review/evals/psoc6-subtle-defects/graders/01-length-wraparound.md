---
type: llm
focus: trace
weight: 1
---

The uint16 total-length calculation in protocol_handle_frame (total = HDR_LEN + len + MAC_LEN) wrapping so a huge len passes the bounds check and causes an out-of-bounds read before the MAC is verified is flagged and rated Red
