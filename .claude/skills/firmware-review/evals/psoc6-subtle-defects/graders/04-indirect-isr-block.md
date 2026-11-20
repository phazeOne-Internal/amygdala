---
type: llm
focus: trace
weight: 1
---

zero_cross_isr calling relay_apply, which calls xSemaphoreTake(..., portMAX_DELAY) from interrupt context, is flagged and rated Red
