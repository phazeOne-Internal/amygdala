---
type: llm
focus: trace
weight: 1
---

door_changed (GPIO callback / ISR context) calling motor_lock, which takes a mutex with K_FOREVER and sleeps, is flagged
