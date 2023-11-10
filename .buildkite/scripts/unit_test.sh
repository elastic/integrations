#!/bin/bash

set -euo pipefail

echo "Starting the unit tests..."
RACE_DETECTOR=true TEST_COVERAGE=true mage unitTest
TESTS_EXIT_STATUS=$?

# Copy coverage file to build directory so it can be downloaded as an artifact
cp build/TEST-go-unit.cov build/coverage.out
exit $TESTS_EXIT_STATUS
