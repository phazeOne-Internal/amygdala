---
type: llm
focus: trace
weight: 1
---

The FW-001 fix changes only what is needed in source/app/protocol.c (a few lines around the length check). PASS if no other files are modified for FW-001, no unrelated refactoring, reformatting or renaming is included, and FW-002 (payload[len] off-by-one) and FW-003 (MIN_FRAME_LEN define) are not changed inside the FW-001 commit. A separate, later commit for FW-002 is only acceptable if the user approved continuing; see grader 06.
