#!/bin/bash

set -euo pipefail

go test -covermode=atomic -coverprofile=build/TEST-go-integrations-coverage.cov -v -race -coverprofile=build/coverage.out ./... | tee build/test-unit.out

# add_bin_path

# with_mage

# echo "Starting the unit tests..."
# RACE_DETECTOR=true TEST_COVERAGE=true mage unitTest
# TESTS_EXIT_STATUS=$?

# # Copy coverage file to build directory so it can be downloaded as an artifact
# cp build/TEST-go-unit.cov build/coverage.out
# exit $TESTS_EXIT_STATUS
