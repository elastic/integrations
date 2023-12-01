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
with_jq         # containers do not have jq installed
with_github_cli # to post comments in Pull Requests
use_elastic_package

echo "--- Process Benchmarks"
# This variable does not exist in builds triggered automatically
GITHUB_PR_TRIGGER_COMMENT="${GITHUB_PR_TRIGGER_COMMENT:-""}"

benchmark_github_folder="benchmark_reports"
benchmark_results="benchmark-results"
current_benchmark_results="build/${benchmark_results}"
buildkite_pattern="build/${benchmark_results}/*.json"
baseline="build/${BUILDKITE_PULL_REQUEST_BASE_BRANCH}/${benchmark_results}"
is_full_report="false"

if [[ "${GITHUB_PR_TRIGGER_COMMENT}" =~ benchmark\ fullreport ]]; then
    is_full_report="true"
fi

download_pr_benchmarks() {
    mkdir -p "${current_benchmark_results}"

    if ! buildkite-agent artifact download "${buildkite_pattern}" . ; then
      echo "[benchmarks] No benchmarks generated in the PR"
      return 1
    fi
    return 0
}

download_baseline_benchmarks() {
    mkdir -p "${baseline}"

    # FIXME: not all integrations builds in main branch are running benchmarks for all packages
    build_id=$(get_last_failed_or_successful_build integrations main)
    echo "Buildkite Build ID: ${build_id}"

    if ! buildkite-agent artifact download "${buildkite_pattern}" --build "${build_id}" "${baseline}" ; then
        echo "[benchmarks] Not found baseline benchmarks"
        return 1
    fi

    # required globbling
    mv "${baseline}"/${buildkite_pattern} "${baseline}/"
    rm -rf "${baseline}/build"
    return 0
}

get_report_file_path() {
    num_reports=$(find "${benchmark_github_folder}" -type f | wc -l)
    if [[ "$num_reports" != "1" ]]; then
        echo "[benchmarks] unexpected number of report files"
        buildkite-agent annotate "Benchmarks: unexpected number of report files" --context "ctx-warn-benchmark" --style "warning"
        return 1
    fi

    find "${benchmark_github_folder}" -type f
}

publish_benchmark_report_github() {
    local file_path="${1}"
    if ! add_or_edit_gh_pr_comment \
            "${BUILDKITE_ORGANIZATION_SLUG}" \
            "integrations" \
            "${BUILDKITE_PULL_REQUEST}" \
            "benchmark-report" \
            "${file_path}" ; then
        echo "[benchmark] It was not possible to send the message."
        buildkite-agent annotate "Benchmark report not posted to Github PR" --context "ctx-warn-benchmark" --style "warning"
        return 1
    fi

    echo "[benchmark] Comment posted."
    return 0
}

echo "Download PR benchmarks"
if ! download_pr_benchmarks ; then
    exit 0
fi

echo "Download main benchmark if any"
if ! download_baseline_benchmarks ; then
    exit 0
fi

${ELASTIC_PACKAGE_BIN} report benchmark \
    -v \
    --fail-on-missing=false \
    --new="${current_benchmark_results}" \
    --old="${baseline}" \
    --threshold="${BENCHMARK_THRESHOLD}" \
    --report-output-path="${benchmark_github_folder}" \
    --full=${is_full_report}

if [ ! -d "${benchmark_github_folder}" ]; then
    echo "[benchmark] No report file created"
    exit 0
fi

benchmark_github_file=$(get_report_file_path)
exit_code=$?
if [[ "${exit_code}" != 0 ]] ; then
    exit 0
fi
buildkite-agent artifact upload "${benchmark_github_file}"

create_collapsed_annotation "Benchmark results" "${benchmark_github_file}" "info" "ctx-benchmark"

if ! publish_benchmark_report_github "${benchmark_github_file}" ; then
    exit 0
fi
