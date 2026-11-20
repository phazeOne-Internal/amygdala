#!/usr/bin/env bash
# Puts the smart-plug firmware and its review findings in the workspace as a committed git repository,
# because amygdala:fix needs a clean tree to branch from and commits one fix at a time.
set -eu
cp -R "$(dirname "$0")/files/." .
cd psoc6-smart-plug
git init -q
git config user.name "Eval User"
git config user.email "eval@example.com"
git add -A
git commit -q -m "Baseline before fixes"
