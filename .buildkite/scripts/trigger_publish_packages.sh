#!/usr/bin/env bash

source .buildkite/scripts/common.sh

set -euo pipefail

echo "--- Installing tools"
add_bin_path
with_jq

ARTIFACTS_FOLDER="${ARTIFACTS_FOLDER:-"packageArtifacts"}"
SIGNING_PIPELINE_SLUG="unified-release-gpg-signing"

echo "--- Downloading artifacts"
## Support main pipeline and downstream pipelines
build_id="${BUILDKITE_BUILD_ID}"

if [ -n "$BUILDKITE_TRIGGERED_FROM_BUILD_PIPELINE_SLUG" ] ; then
  build_id="${BUILDKITE_TRIGGERED_FROM_BUILD_ID}"
fi

## Fail if no token
if [ -z "$BUILDKITE_API_TOKEN" ] ; then
  echo "Token could not be loaded from vault. Please review .buildkite/hooks/pre-command"
  exit 1
fi

pipeline_api_url="https://api.buildkite.com/v2/organizations/elastic/pipelines"
query_url="${pipeline_api_url}/$SIGNING_PIPELINE_SLUG/builds?triggered_from_build=${build_id}"
echo "Query URL: ${query_url}"
build_json=$(curl -sH "Authorization: Bearer $BUILDKITE_API_TOKEN" "${query_url}")

number_signing_builds=$(echo "$build_json" | jq -r '.[] | length')
if [[ "${number_signing_builds}" != "1" ]]; then
  echo "Just one signing pipeline should be triggered from Build ID: ${build_id}"
  exit 1
fi

GPG_SIGN_BUILD_ID=$(echo "$build_json" | jq -r '.[0].id')

echo "Download signed artifacts"
mkdir -p "${ARTIFACTS_FOLDER}"
# GPG sign pipeline uploads the artifacts wihtout any folder
buildkite-agent artifact download --build "$GPG_SIGN_BUILD_ID" "*" "${ARTIFACTS_FOLDER}"

echo "--- Rename *.asc to *.sig"
pushd "${ARTIFACTS_FOLDER}" > /dev/null || exit 1

if [ "$(find . -maxdepth 1 -mindepth 1 -name "*.asc" | wc -l)" -gt 0 ] ; then
  for f in *.asc; do
      mv "$f" "${f%.asc}.sig"
  done
else
  # If this step runs, signatures files must be present
  echo "No signatures found"
  exit 1
fi
popd > /dev/null || exit 1

find "${ARTIFACTS_FOLDER}" -maxdepth 1 -mindepth 1 -name "*.zip"
find "${ARTIFACTS_FOLDER}" -maxdepth 1 -mindepth 1 -name "*.sig"

buildkite-agent artifact upload "${ARTIFACTS_FOLDER}/*.zip"
buildkite-agent artifact upload "${ARTIFACTS_FOLDER}/*.sig"

echo "--- Trigger publishing pipeline"
# for each package trigger a publish package
PIPELINE_FILE="packages_pipeline.yml"

cat << EOF > "${PIPELINE_FILE}"
steps:
  - label: "Trigger publish package pipeline"
    key: "trigger-publish-packages"
    trigger: "package-storage-infra-publishing"
    build:
      env:
        DRY_RUN: "true"
        LEGACY_PACKAGE: "false"
        PACKAGE_ARTIFACTS_FOLDER: "${ARTIFACTS_FOLDER}"
EOF

buildkite-agent pipeline upload "${PIPELINE_FILE}"
