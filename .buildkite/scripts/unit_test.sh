#!/bin/bash

set -euo pipefail

go test -covermode=atomic -coverprofile=TEST-go-integrations-coverage.cov -v -race -coverprofile=coverage.out ./... | tee test-unit.out

go install github.com/jstemmer/go-junit-report@latest

for file in *.out; do
  go-junit-report > "${file}.xml" < ${file}
done
