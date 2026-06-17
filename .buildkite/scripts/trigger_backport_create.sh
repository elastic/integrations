#!/bin/bash
# Triggered from the main pipeline when .backports.yml changes on a push to main.
# For each entry that is new (absent from HEAD^), uploads a trigger step that
# runs the integrations-backport pipeline with DRY_RUN=false.

source .buildkite/scripts/common.sh
source .buildkite/scripts/trigger_backport_lib.sh

set -euo pipefail

main() {
    if [[ "${BUILDKITE_PULL_REQUEST}" != "false" ]]; then
        echo "Pull request build, skipping backport create trigger"
        exit 0
    fi

    if [[ "${BUILDKITE_BRANCH}" != "main" ]]; then
        echo "Not on main branch (branch: ${BUILDKITE_BRANCH}), skipping backport create trigger"
        exit 0
    fi

    add_bin_path
    with_yq
    with_mage
    with_github_cli

    if ! git diff --name-only HEAD^ HEAD | grep -qE '^\.backports\.yml$'; then
        echo ".backports.yml not changed, skipping backport create trigger"
        exit 0
    fi

    echo "--- .backports.yml changed — finding new entries"

    OLD_INVENTORY=""
    PIPELINE_FILE=""

    cleanup() {
        local exit_code=$?
        [[ -n "${OLD_INVENTORY}" ]] && rm -f "${OLD_INVENTORY}"
        [[ -n "${PIPELINE_FILE}" ]] && rm -f "${PIPELINE_FILE}"
        exit "${exit_code}"
    }
    trap cleanup EXIT

    PR_NUMBER=$(gh api "repos/elastic/integrations/commits/${BUILDKITE_COMMIT}/pulls" --jq '.[0].number' 2>/dev/null || true)
    if [[ -n "${PR_NUMBER}" ]]; then
        echo "Associated PR: #${PR_NUMBER}"
    else
        echo "Could not resolve PR number for commit ${BUILDKITE_COMMIT}, PR comments will be skipped"
    fi

    OLD_INVENTORY="$(mktemp)"
    NEW_INVENTORY=".backports.yml"

    if ! git show "HEAD^:.backports.yml" > "${OLD_INVENTORY}" 2>/dev/null; then
        echo ".backports.yml is new on main — skipping create for initial entries"
        echo "To create branches for these entries, trigger the integrations-backport pipeline manually."
        exit 0
    fi

    PIPELINE_FILE="$(mktemp --suffix=.yml)"

    generate_trigger_pipeline "${OLD_INVENTORY}" "${NEW_INVENTORY}" "false" "${PR_NUMBER}" "${PIPELINE_FILE}"

    rm -f "${OLD_INVENTORY}"

    if [[ ! -s "${PIPELINE_FILE}" ]]; then
        echo "No new non-archived entries found, skipping create trigger"
        rm -f "${PIPELINE_FILE}"
        exit 0
    fi

    echo "--- Uploading create trigger(s)"
    cat "${PIPELINE_FILE}"
    buildkite-agent pipeline upload "${PIPELINE_FILE}"
    rm -f "${PIPELINE_FILE}"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main
fi
