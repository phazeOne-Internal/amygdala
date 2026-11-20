---
type: llm
focus: trace
weight: 1
---

The fix is committed on a working branch (not main/master), in one commit whose message references FW-001 and says what was changed and how it was verified. PASS if a branch was created (for example firmware-fixes/...), exactly one commit covers FW-001, and nothing was pushed. FAIL if the commit went to main, if the fix is left uncommitted, if several unrelated findings are squashed into one commit, or if git push was run.
