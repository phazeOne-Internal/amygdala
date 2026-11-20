# smart-plug-fix-first-red

Eval case for `amygdala:fix`. The workspace gets the PSoC 6 smart-plug fixture (the same files as the
`psoc6-subtle-defects` review case) with a hand-written `firmware-review/findings.json` holding three findings in
`source/app/protocol.c`: a Red 16-bit length wraparound, an Amber off-by-one and a Green naming nit. `place-files.sh`
turns the folder into a committed git repository, since the skill branches from a clean tree and commits one fix at a time.

The graders check the workflow the skill promises: first Red first, a small correct fix, one commit on a working branch,
status recorded with `fix_tracker.py`, honest about not building (no toolchain here), and a pause for approval before the
next finding.
