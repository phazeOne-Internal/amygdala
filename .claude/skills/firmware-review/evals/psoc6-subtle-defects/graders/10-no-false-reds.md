---
type: llm
focus: trace
weight: 1
---

None of these safe patterns is rated Red: the strncpy with explicit termination in T_SET_NAME, strcpy(status, "OK") into a 16-byte buffer, the wrap-safe tick subtraction in net_task, the supervisor-task watchdog, or flash wear from config writes
