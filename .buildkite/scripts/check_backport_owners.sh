#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

# BACKPORT_OWNERS_SOURCE_BRANCH is the ownership source of truth — main is
# always authoritative, so this isn't expected to change, but a variable
# keeps the value in one place rather than repeated through the script.
BACKPORT_OWNERS_SOURCE_BRANCH="${BACKPORT_OWNERS_SOURCE_BRANCH:-"main"}"

# Renders the PR comment body for mismatches_json, the JSON array emitted by
# `mage checkBackportOwners -asJSON` (an object per changed package that
# needs attention — a package fully in sync with main is simply absent).
# Each object is either {"package","teams"} (a real mismatch: teams is a
# pre-resolved, deduped, "@"-prefixed list) or {"package","error"} (the check
# itself couldn't run for that package — no team could be resolved, so none
# is mentioned).
# Usage: build_owner_check_comment <mismatches_json>
build_owner_check_comment() {
    local mismatches_json="$1"

    local count
    count=$(jq 'length' <<< "${mismatches_json}")

    if [[ "${count}" -eq 0 ]]; then
        echo ":white_check_mark: Package owners are in sync with \`main\`."
        return
    fi

    echo "**Package owners are out of sync with \`main\`:**"
    echo ""
    jq -r '.[] |
        if .error then
            "- `" + .package + "` — could not check ownership on `main`: " + .error
        else
            "- `" + .package + "` — should now be owned by " + (.teams | join(", "))
        end' <<< "${mismatches_json}"
}

main() {
    set -euo pipefail

    if [[ "${BUILDKITE_PULL_REQUEST:-"false"}" == "false" ]]; then
        echo "Not a pull request build, skipping backport owner check."
        exit 0
    fi

    if [[ ! "${BUILDKITE_PULL_REQUEST_BASE_BRANCH:-""}" =~ ^backport- ]]; then
        echo "Base branch '${BUILDKITE_PULL_REQUEST_BASE_BRANCH:-""}' is not a backport-* branch, skipping."
        exit 0
    fi

    if running_on_buildkite; then
        echo "--- Installing tools"
        add_bin_path
        with_jq         # containers do not have jq installed
        with_github_cli # to post comments in Pull Requests
    fi

    local remote="origin"
    local merge_base
    merge_base="$(git merge-base "${BUILDKITE_COMMIT}" "${remote}/${BUILDKITE_PULL_REQUEST_BASE_BRANCH}")"

    echo "--- Checking package owners for PR #${BUILDKITE_PULL_REQUEST}"
    echo "Base branch: ${BUILDKITE_PULL_REQUEST_BASE_BRANCH}, merge-base: ${merge_base}, head: ${BUILDKITE_COMMIT}"

    local mismatches_json
    mismatches_json="$(mage checkBackportOwners "${remote}" "${BACKPORT_OWNERS_SOURCE_BRANCH}" "${merge_base}" "${BUILDKITE_COMMIT}")"

    local comment
    comment="$(build_owner_check_comment "${mismatches_json}")"
    echo "${comment}"

    local mismatch_count
    mismatch_count="$(jq 'length' <<< "${mismatches_json}")"

    if running_on_buildkite; then
        echo "${comment}" > backport-owner-check.txt
        if ! delete_and_create_gh_pr_comment \
            "${BUILDKITE_ORGANIZATION_SLUG}" \
            "integrations" \
            "${BUILDKITE_PULL_REQUEST}" \
            "backport-owner-check" \
            "backport-owner-check.txt"; then
            echo "Failed to post GitHub PR comment"
        fi
    fi

    if [[ "${mismatch_count}" -gt 0 ]]; then
        echo ""
        echo "--- ${mismatch_count} package(s) have owner mismatches with \`main\`"
        exit 1
    fi
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
