---
type: llm
focus: trace
weight: 1
---

After the FW-001 fix is committed and recorded, the assistant stops and asks the user for approval before starting FW-002: it presents the finding (ID, RAG, title), what changed (files and a short summary), what was verified and what was not, and names the next finding, then asks (AskUserQuestion or in chat). PASS if the run ends at that question, or continues to FW-002 only after an explicit user approval in the transcript. FAIL if it fixes FW-002 or FW-003 without being asked, or ends without presenting the fix for approval.
