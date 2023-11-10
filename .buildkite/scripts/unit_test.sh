#!/bin/bash

set -euo pipefail

go test -covermode=atomic -coverprofile=TEST-go-integrations-coverage.cov -v -race -coverprofile=coverage.out ./...
