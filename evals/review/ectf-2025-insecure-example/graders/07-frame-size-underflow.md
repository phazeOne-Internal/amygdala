---
type: llm
focus: trace
weight: 1
---

The report notes that frame_size = pkt_len - (sizeof channel + sizeof timestamp) underflows for packets shorter than 12 bytes, so write_packet sends data from beyond uart_buf (stack memory disclosure), rated Red or Amber
