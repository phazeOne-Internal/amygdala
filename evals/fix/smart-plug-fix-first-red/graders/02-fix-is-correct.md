---
type: llm
focus: trace
weight: 1
---

Read the final source/app/protocol.c (or the diff). PASS if, after the change, a frame with a very large len field (for example 0xFFFF with rx_len 40) is rejected as incomplete before mac_ok is called: either len is bounded (for example len > MAX_PAYLOAD) before the total is computed, or the total is computed in a type wider than 16 bits (uint32_t / size_t) and compared with rx_len, or equivalent. FAIL if the wraparound is still possible, or if the fix breaks valid frames (for example rejects every frame, or changes the frame format).
