#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail

if ! is_pr ; then
    echo "[benchmarks] Pull request build. Skip procesing benchmarks."
    exit 0
fi

add_bin_path
with_go
use_elastic_package

echo "--- Process Benchmarks"
# This variable does not exist in builds triggered automatically
GITHUB_PR_TRIGGER_COMMENT="${GITHUB_PR_TRIGGER_COMMENT:-""}"

benchmark_github_file="report.md"
benchmark_results="benchmark-results"
current_benchmark_results="build/${benchmark_results}"
baseline="build/${BUILDKITE_PULL_REQUEST_BASE_BRANCH}/${benchmark_results}"
is_full_report="false"

if [[ "${GITHUB_PR_TRIGGER_COMMENT}" =~ benchmark\ fullreport ]]; then
    is_full_report="true"
fi

pushd "${WORKSPACE}" > /dev/null

mkdir -p "${current_benchmark_results}"
mkdir -p "${baseline}"

echo "Download PR benchmarks"
mkdir -p build/benchmark-results
if ! buildkite-agent artifact download "build/benchmark-results/*.json" . ; then
  echo "[benchmarks] No benchmarks generated in the PR"
  exit 0
fi

echo "Download main benchmark if any"
mkdir -p build/benchmark-results
build_id=$(get_latest_succesful_build integrations main)
echo "Buildkite Build ID: ${build_id}"

if ! buildkite-agent artifact download "build/benchmark-results/*.json" --build "${build_id}" "${baseline}" ; then
  echo "[benchmarks] Not found baseline benchmarks"
  exit 0
fi

mv "${baseline}"/build/benchmarks-results/*.json baseline/
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

echo "Debug: current benchmark"
ls -l "${current_benchmark_results}"

echo "Debug: baseline benchmark"
ls -l "${baseline}"

echo "Run benchmark report"
${ELASTIC_PACKAGE_BIN} report benchmark \
    --fail-on-missing=false \
    --new="${current_benchmark_results}" \
    --old="${baseline}" \
    --threshold="${BENCHMARK_THRESHOLD}" \
    --report-output-path="${benchmark_github_file}" \
    --full=${is_full_report}


if [ ! -f ${benchmark_github_file} ]; then
    echo "add_github_comment_benchmark: it was not possible to send the message"
    return
fi

# TODO: write github comment in PR
popd > /dev/null
