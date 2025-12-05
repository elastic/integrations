#!/bin/bash

set -euo pipefail

if [[ "${BUILDKITE_PULL_REQUEST}" == "false" ]]; then
  exit 0
fi

# Fetch active Kibana versions
ACTIVE_KIBANA_VERSIONS=$(curl -sL https://raw.githubusercontent.com/elastic/kibana/main/versions.json | yq '.versions[].version' | xargs)
echo "Active Kibana versions: $ACTIVE_KIBANA_VERSIONS"

# Extract version spec from the manifest
KIBANA_REQ=$(yq .conditions.kibana.version ./packages/security_detection_engine/manifest.yml)
echo "Kibana requirement from the security_detection_engine manifest: $KIBANA_REQ"

# Dump a trivial Go program to filter by semver constrains
TEMP_DIR=$(mktemp -d)
SEMVER_FILTER_PATH="$TEMP_DIR/semver.go"

cat <<'GO' > "$SEMVER_FILTER_PATH"
package main

import (
  "strings"
	"fmt"
	"os"
	"github.com/Masterminds/semver/v3"
)

func main() {
	c, err := semver.NewConstraint(os.Args[1])
  if err != nil {
		panic(err)
	}

	for _, s := range strings.Split(os.Args[2], " ") {
		if v, _ := semver.NewVersion(s); c.Check(v) {
			fmt.Println(s + "-SNAPSHOT")
		}
	}
}
GO

# Capture the "returned" array in STACK_VERSIONS
read -r -a STACK_VERSIONS <<< "$(go run "${SEMVER_FILTER_PATH}" "${KIBANA_REQ}" "${ACTIVE_KIBANA_VERSIONS}" | xargs)"

if [[ ! -n "${STACK_VERSIONS+x}" ]]; then
	echo "There are no active versions satisfying the constraint ${KIBANA_REQ}."
  exit 0
fi

# Trigger OOM testing pipeline for each stack version
for STACK_VERSION in "${STACK_VERSIONS[@]}"
do
  echo "--- [security_detection_engine] Trigger OOM testing pipeline against $STACK_VERSION ECH"

  cat <<YAML | buildkite-agent pipeline upload
steps:
  - key: 'run-oom-testing-$(echo "$STACK_VERSION" | sed 's/\./_/g')$BUILDKITE_BUILD_NUMBER'
    label: ":elastic-cloud::bar_chart: [security_detection_engine] Test for OOM issues against $STACK_VERSION ECH"
    trigger: "appex-qa-stateful-security-prebuilt-rules-ftr-oom-testing"
    async: false
    build:
      message: "Test security_detection_engine package against $STACK_VERSION ($GITHUB_PR_BASE_OWNER/$GITHUB_PR_BASE_REPO, branch: $GITHUB_PR_BRANCH, commit: $BUILDKITE_COMMIT)"
      env:
        STACK_VERSION: $STACK_VERSION
        ELASTIC_INTEGRATIONS_REPO_COMMIT: $BUILDKITE_COMMIT
YAML
done