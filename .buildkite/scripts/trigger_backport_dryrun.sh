#!/bin/bash
# Triggered from the main pipeline when .backports.yml changes in a PR.
# For each entry that is new (absent from the base branch), uploads a trigger
# step that runs the integrations-backport pipeline in DRY_RUN mode.

source .buildkite/scripts/common.sh
source .buildkite/scripts/trigger_backport_lib.sh

set -euo pipefail

main() {
    if [[ "${BUILDKITE_PULL_REQUEST}" == "false" ]]; then
        echo "Not a pull request, skipping backport dry-run trigger"
        exit 0
    fi

    if [[ "${BUILDKITE_PULL_REQUEST_BASE_BRANCH}" != "main" ]]; then
        echo "Pull request does not target main (base branch: ${BUILDKITE_PULL_REQUEST_BASE_BRANCH}), skipping backport dry-run trigger"
        exit 0
    fi

    add_bin_path
    with_yq
    with_mage

    from="$(get_from_changeset)"
    to="$(get_to_changeset)"
    commit_merge="$(git merge-base "${from}" "${to}")"

    if ! backports_yml_changed "${commit_merge}" "${to}"; then
        echo ".backports.yml not changed, skipping backport dry-run trigger"
        exit 0
    fi

    echo "--- .backports.yml changed — finding new entries"

    BASE_BRANCH="${BUILDKITE_PULL_REQUEST_BASE_BRANCH}"
    OLD_INVENTORY=""
    PIPELINE_FILE=""

    cleanup() {
        local exit_code=$?
        [[ -n "${OLD_INVENTORY}" ]] && rm -f "${OLD_INVENTORY}"
        [[ -n "${PIPELINE_FILE}" ]] && rm -f "${PIPELINE_FILE}"
        exit "${exit_code}"
    }
    trap cleanup EXIT

    OLD_INVENTORY="$(mktemp)"
    NEW_INVENTORY=".backports.yml"

    if ! load_old_backports_inventory "origin/${BASE_BRANCH}" "${OLD_INVENTORY}"; then
        echo ".backports.yml is new on ${BASE_BRANCH} — skipping dry-runs for initial entries"
        echo "To validate new entries, add them in a follow-up PR after this one merges."
        exit 0
    fi

    PIPELINE_FILE="$(mktemp --suffix=.yml)"

    generate_trigger_pipeline "${OLD_INVENTORY}" "${NEW_INVENTORY}" "true" "" "${PIPELINE_FILE}"

    rm -f "${OLD_INVENTORY}"

    if [[ ! -s "${PIPELINE_FILE}" ]]; then
        echo "No new non-archived entries found, skipping dry-run trigger"
        rm -f "${PIPELINE_FILE}"
        exit 0
    fi

    echo "--- Uploading dry-run trigger(s)"
    cat "${PIPELINE_FILE}"
    buildkite-agent pipeline upload "${PIPELINE_FILE}"
    rm -f "${PIPELINE_FILE}"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main
fi
