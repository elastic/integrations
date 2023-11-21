#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail

# default values
BENCHMARK_THRESHOLD=${BENCHMARK_THRESHOLD:-'15'}

if ! is_pr ; then
    echo "[benchmarks] Pull request build. Skip procesing benchmarks."
    exit 0
fi

echo "--- Installing tools"
add_bin_path
with_go
with_jq  # containers do not have jq installe# containers do not have jq installedd
with_github_cli # to post comments in Pull Requests
use_elastic_package

echo "--- Process Benchmarks"
# This variable does not exist in builds triggered automatically
GITHUB_PR_TRIGGER_COMMENT="${GITHUB_PR_TRIGGER_COMMENT:-""}"

benchmark_github_file="report.md"
benchmark_results="benchmark-results"
current_benchmark_results="build/${benchmark_results}"
buildkite_pattern="build/${benchmark_results}/*.json"
baseline="build/${BUILDKITE_PULL_REQUEST_BASE_BRANCH}/${benchmark_results}"
is_full_report="false"

if [[ "${GITHUB_PR_TRIGGER_COMMENT}" =~ benchmark\ fullreport ]]; then
    is_full_report="true"
fi

pushd "${WORKSPACE}" > /dev/null || exit 1

mkdir -p "${current_benchmark_results}"
mkdir -p "${baseline}"

echo "Download PR benchmarks"
mkdir -p build/benchmark-results
if ! buildkite-agent artifact download "${buildkite_pattern}" . ; then
  echo "[benchmarks] No benchmarks generated in the PR"
  exit 0
fi

echo "Debug: current benchmark"
find "${current_benchmark_results}"

echo "Download main benchmark if any"
mkdir -p build/benchmark-results
build_id=$(get_last_failed_or_successful_build integrations main)
build_id="018bf2bb-9795-48f2-881b-e2e85476c8fb"
echo "Buildkite Build ID: ${build_id}"

if ! buildkite-agent artifact download "${buildkite_pattern}" --build "${build_id}" "${baseline}" ; then
  echo "[benchmarks] Not found baseline benchmarks"
  exit 0
fi

echo "Debug: baseline benchmark"
find "${baseline}"

# required globbling
mv "${baseline}"/${buildkite_pattern} "${baseline}/"
rm -rf "${baseline}/build"

# download_benchmark_results \
#     "${JOB_GCS_BUCKET}" \
#     "$(get_benchmark_path_prefix)" \
#     "${current_benchmark_results}"
#
# # download main benchmark if any
# download_benchmark_results \
#     "${JOB_GCS_BUCKET}" \
#     "$(get_benchmark_path_prefix)" \
#     baseline

echo "Run benchmark report"
${ELASTIC_PACKAGE_BIN} report benchmark \
    --fail-on-missing=false \
    --new="${current_benchmark_results}" \
    --old="${baseline}" \
    --threshold="${BENCHMARK_THRESHOLD}" \
    --report-output-path="${benchmark_github_file}" \
    --full=${is_full_report}


if [ ! -f "${benchmark_github_file}" ]; then
    echo "[benchmark] No report file created"
    exit 0
fi

# TODO: write github comment in PR
# if ! gh pr comment \
#   "${BUILDKITE_PULL_REQUEST}" \
#   --body-file "${benchmark_github_file}" ; then
#   echo "[benchmark] It was not possible to send the message"
# fi
if ! add_or_edit_gh_pr_comment \
        "${BUILDKITE_ORGANIZATION_SLUG}" \
        "integrations" \
        "${BUILDKITE_PULL_REQUEST}" \
        "benchmark-report" \
        "${benchmark_github_file}" ; then
    echo "[benchmark] It was not possible to send the message."
else
    echo "[benchmark] Comment posted."
fi


popd > /dev/null || exit 1
