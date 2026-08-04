#!/bin/bash
# Run unit tests for the standalone backport tool sub-module (cmd/backport/).
# Uses the Go version pinned in cmd/backport/.go-version, independent of the
# root .go-version, so this step works correctly on backport branches that may
# carry an older Go toolchain.

source .buildkite/scripts/common.sh

set -euo pipefail

# with_backport builds the binary in a subshell to avoid leaking its Go version
# into the parent shell. We then set up Go explicitly here so that `go test`
# uses the same version the binary was built with.
with_backport

eval "$("${BIN_FOLDER}/gvm" "$(cat "${WORKSPACE}/cmd/backport/.go-version")")"
PATH="${PATH}:$(go env GOPATH)/bin"
export PATH

echo "--- Run backport tool tests"
go test -C "${WORKSPACE}/cmd/backport" ./...
