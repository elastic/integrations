#!/bin/bash

set -euo pipefail

if [[ "${BUILDKITE_PULL_REQUEST}" == "false" ]]; then
  exit 0
fi

# Use Release API to get released and supported Elastic Stack versions
PAST_RELEASES_URL="https://ela.st/past-stack-releases"
PAST_VERSIONS=$(curl -sL $PAST_RELEASES_URL |  jq -r '
.releases
  | map(
      select(
        .is_end_of_support == false
        and .is_retired == false
        and (.version | test("^\\d+\\.\\d+\\.\\d+$"))
      )
    )
  | group_by(
      .version
      | capture("^(?<maj>\\d+)\\.(?<min>\\d+)")
      | "\(.maj).\(.min)"
    )
  | map(
      max_by(
        .version
        | split(".")
        | map(tonumber)
      )
    )
  | .[].version'
)

FUTURE_RELEASES_URL="https://ela.st/future-stack-releases"
FUTURE_VERSIONS=$(curl -sL $FUTURE_RELEASES_URL |  jq -r '
.releases[]
  | select(.active_release == true)
  | select(
      .snapshots
      | to_entries
      | any(.value.date_removed > (now | strftime("%Y-%m-%d %H:%M:%S")))
    )
  | "\(.version)-SNAPSHOT"
'
)

ACTIVE_VERSIONS="$(echo -e "${PAST_VERSIONS}\n${FUTURE_VERSIONS}" | sort -V | xargs)"

echo "Active Elastic Stack versions: $ACTIVE_VERSIONS"

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
		checkVersion := s

		if strings.HasSuffix(s, "-SNAPSHOT") {
			checkVersion = strings.TrimSuffix(s, "-SNAPSHOT")
		}

		v, err := semver.NewVersion(checkVersion)
		if err != nil {
			continue
		}

		if c.Check(v) {
			fmt.Println(s)
		}
	}
}
GO

# Capture the "returned" array in STACK_VERSIONS
read -r -a STACK_VERSIONS <<< "$(go run "${SEMVER_FILTER_PATH}" "${KIBANA_REQ}" "${ACTIVE_VERSIONS}" | xargs)"

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
