#!/bin/bash
# Triggers the integrations-backport pipeline when .backports.yml changes.
# In PR builds: validates new entries via a dry run against the base branch.
# On push to main: creates backport branches for new entries.

source .buildkite/scripts/common.sh
source .buildkite/scripts/trigger_backport_lib.sh

set -euo pipefail

main() {
    add_bin_path
    with_yq
    with_mage

    local dry_run old_inventory_ref diff_from diff_to pr_number="" label
    local new_entry_msg new_entry_hint

    if [[ "${BUILDKITE_PULL_REQUEST}" != "false" ]]; then
        if [[ "${BUILDKITE_PULL_REQUEST_BASE_BRANCH}" != "main" ]]; then
            echo "Pull request does not target main (base branch: ${BUILDKITE_PULL_REQUEST_BASE_BRANCH}), skipping"
            exit 0
        fi
        dry_run="true"
        label="dry-run"
        local from to
        from="$(get_from_changeset)"
        to="$(get_to_changeset)"
        diff_from="$(git merge-base "${from}" "${to}")"
        diff_to="${to}"
        old_inventory_ref="origin/${BUILDKITE_PULL_REQUEST_BASE_BRANCH}"
        new_entry_msg="skipping dry-runs for initial entries"
        new_entry_hint="To validate new entries, add them in a follow-up PR after this one merges."
    else
        if [[ "${BUILDKITE_BRANCH}" != "main" ]]; then
            echo "Not on main branch (branch: ${BUILDKITE_BRANCH}), skipping"
            exit 0
        fi
        dry_run="false"
        label="create"
        diff_from="HEAD^"
        diff_to="HEAD"
        old_inventory_ref="HEAD^"
        new_entry_msg="skipping create for initial entries"
        new_entry_hint="To create branches for these entries, trigger the integrations-backport pipeline manually."
    fi

    backports_yml_changed_exit=0
    backports_yml_changed "${diff_from}" "${diff_to}" || backports_yml_changed_exit=$?
    if [[ "${backports_yml_changed_exit}" -eq 2 ]]; then
        exit 1
    fi
    if [[ "${backports_yml_changed_exit}" -ne 0 ]]; then
        echo ".backports.yml not changed, skipping backport ${label} trigger"
        exit 0
    fi

    echo "--- .backports.yml changed — finding new entries"

    if [[ "${BUILDKITE_PULL_REQUEST}" == "false" ]]; then
        with_github_cli
        pr_number="$(retry 3 resolve_pr_number "${BUILDKITE_COMMIT}")" || {
            echo "Warning: could not resolve PR number after retries, PR comments will be skipped" >&2
        }
    fi

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

    if ! load_old_backports_inventory "${old_inventory_ref}" "${OLD_INVENTORY}"; then
        echo ".backports.yml is new — ${new_entry_msg}"
        echo "${new_entry_hint}"
        exit 0
    fi

    PIPELINE_FILE="$(mktemp --suffix=.yml)"

    generate_trigger_pipeline "${OLD_INVENTORY}" "${NEW_INVENTORY}" "${dry_run}" "${pr_number}" "${PIPELINE_FILE}" "${BUILDKITE_PULL_REQUEST:-false}" "${BUILDKITE_COMMIT:-}"

    if [[ ! -s "${PIPELINE_FILE}" ]]; then
        echo "No new non-archived entries found, skipping ${label} trigger"
        exit 0
    fi

    echo "--- Uploading ${label} trigger(s)"
    cat "${PIPELINE_FILE}"
    buildkite-agent pipeline upload "${PIPELINE_FILE}"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main
fi
