---
type: llm
focus: trace
weight: 1
---

The host-controlled packet length (header.len, a uint16) being read into the 100-byte uart_buf in main() via read_packet / read_bytes is rated Red with a file:line location in decoder.c or host_messaging.c
