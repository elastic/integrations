#!/usr/bin/env bash

source .buildkite/scripts/common.sh

set -euo pipefail

add_bin_path
with_jq

PACKAGES_SIGNED_FOLDER="${WORKSPACE}/packagesSigned/"
PACKAGES_BUILDKITE_ARTIFACT_FOLDER="packagesUnsigned"

mkdir -p "${PACKAGES_SIGNED_FOLDER}"

## Support main pipeline and downstream pipelines
pipeline_slug=${BUILDKITE_PIPELINE_SLUG}
pipeline_build_number=${BUILDKITE_BUILD_NUMBER}

if [ -n "$BUILDKITE_TRIGGERED_FROM_BUILD_PIPELINE_SLUG" ] ; then
  pipeline_slug=$BUILDKITE_TRIGGERED_FROM_BUILD_PIPELINE_SLUG
  pipeline_build_number=$BUILDKITE_TRIGGERED_FROM_BUILD_NUMBER
fi

## Fail if no token
if [ -z "$BUILDKITE_API_TOKEN" ] ; then
  echo "Token could not be loaded from vault. Please review .buildkite/hooks/pre-command"
  exit 1
fi

pipeline_api_url="https://api.buildkite.com/v2/organizations/elastic/pipelines"
query_url="${pipeline_api_url}/$pipeline_slug/builds/$pipeline_build_number"
build_json=$(curl -sH "Authorization: Bearer $BUILDKITE_API_TOKEN" "${query_url}")

GPG_SIGN_BUILD_ID=$(jq -r ".jobs[] | select(.step_key == \"${SIGNING_STEP_KEY}\").triggered_build.id" <<< "$build_json")

echo "--- Download signed artifacts"
buildkite-agent artifact download --build "$GPG_SIGN_BUILD_ID" "*" .

exit 0
# TODO: remove testing
# buildkite-agent artifact download "${PACKAGES_BUILDKITE_ARTIFACT_FOLDER}/*.zip" "${PACKAGES_SIGNED_FOLDER}/"

pushd "${PACKAGES_SIGNED_FOLDER}" > /dev/null || exit 1

while IFS= read -r -d '' file ; do
  cp "${file}" "${PACKAGES_SIGNED_FOLDER}"
  cp "${file}.asc" "${PACKAGES_SIGNED_FOLDER}" || true
done < <(find . -name "*.zip" -print0)

if ls ./*.asc 2> /dev/null ; then
  echo "Rename asc to sig"
  for f in *.asc; do
      mv "$f" "${f%.asc}.sig"
  done
else
  echo "No signatures found"
  # exit 1
fi
popd > /dev/null || exit 1

# TODO: upload the renamed files
# buildkite-agent artifact upload ${PACKAGES_SIGNED_FOLDER}/*.zip
# buildkite-agent artifact upload ${PACKAGES_SIGNED_FOLDER}/*.sig

find "${PACKAGES_SIGNED_FOLDER}"

exit 0
# for each package trigger a publish package
PIPELINE_FILE="packages_pipeline.yml"
touch packages_pipeline.yml

cat << EOF >> ${PIPELINE_FILE}
steps:
  - label: "Publish packages"
    key: "trigger-publish-packages"
    trigger: "package-storage-infra-publishing"
    build:
      env:
        DRY_RUN: "true"
        LEGACY_PACKAGE: "false"
EOF
