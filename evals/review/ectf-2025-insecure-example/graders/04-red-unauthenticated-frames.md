---
type: llm
focus: trace
weight: 1
---

The lack of integrity and confidentiality on broadcast frames (encoder.py packs channel, timestamp and frame in plaintext; decode() forwards new_frame->data with no verification) is rated Red
