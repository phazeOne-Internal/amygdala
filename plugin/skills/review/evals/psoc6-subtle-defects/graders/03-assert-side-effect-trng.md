---
type: llm
focus: trace
weight: 1
---

CY_ASSERT(cyhal_trng_init(&trng) == CY_RSLT_SUCCESS) in main.c is flagged because the init call is compiled out in Release, leaving the TRNG uninitialised, and it is rated Red
