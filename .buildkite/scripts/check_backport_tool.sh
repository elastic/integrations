#!/bin/bash
# Run `mage check` for the standalone backport tool sub-module (cmd/backport/).
# Uses the Go version pinned in cmd/backport/.go-version, independent of the
# root .go-version, so this step works correctly on backport branches that may
# carry an older Go toolchain. After the check, verifies no files were left
# modified (format and tidy must be idempotent on a clean tree).

source .buildkite/scripts/common.sh

set -euo pipefail

# with_backport downloads gvm (if needed) and builds the binary inside a
# subshell so the Go version switch does not leak into the parent shell.
# with_mage (called below from cmd/backport/) then sets up Go and installs
# mage using the version pinned in cmd/backport/.go-version.
with_backport

cd cmd/backport

add_bin_path
with_mage

echo "--- Run mage check"
mage check

echo "--- Check for uncommitted changes"
check_git_diff
