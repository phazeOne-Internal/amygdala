---
type: llm
focus: trace
weight: 1
---

The report notes that decode() never checks the frame timestamp against the subscription start/end window or for monotonic ordering (replay and out-of-window frames are decoded), rated Red or Amber
