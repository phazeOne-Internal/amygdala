---
name: layering
type: llm
focus: trace
weight: 1
---

The relay driver (`source/drivers/relay.c`) depends upward on the application layer: it includes `app.h` and calls `config_load()` (persistent configuration) and `wdt_checkin()` (application watchdog service) directly. PASS if the report contains a code-quality finding (or an explicit note in the strengths / code-quality area) about this upward dependency, rated Green or Amber, that recommends a callback, queue or injected dependency and/or enforcing layering in the build. FAIL if the layering problem is not mentioned at all, or if it is rated Red.
