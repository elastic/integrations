#!/bin/bash

set -euo pipefail

testsFileName="test-unit.out"

go test -covermode=atomic -v -coverprofile=coverage.out ./... | tee ${testsFileName}

go install github.com/jstemmer/go-junit-report@latest
go-junit-report > "${testsFileName}.xml" < ${testsFileName}
