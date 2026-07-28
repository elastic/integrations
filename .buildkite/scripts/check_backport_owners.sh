#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

# BACKPORT_OWNERS_SOURCE_BRANCH is the ownership source of truth — main is
# always authoritative. Not meant to be overridden via the environment (that
# would let this drift from apply.go's own hardcoded "main"); it's a plain
# variable purely so the value lives in one place, easy to tweak here for
# local debugging/testing.
BACKPORT_OWNERS_SOURCE_BRANCH="main"

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

# Renders the PR comment body for when the check itself failed to run
# entirely (e.g. `mage checkBackportOwners` exited non-zero — most likely its
# own `git fetch` of main, a genuinely new network dependency this script
# introduces rather than relying on a ref the pre-command hook already
# fetched) rather than completing and reporting per-package results. This is
# a distinct state from "no mismatches found" — build_owner_check_comment
# must never be called with data from a failed run, since an empty/absent
# result would then misrender as the in-sync confirmation.
# Usage: build_owner_check_failure_comment <build_url>
build_owner_check_failure_comment() {
    local build_url="${1:-""}"

    echo ":warning: The backport owner check failed to run — it could not determine whether package owners are in sync with \`main\`."
    if [[ -n "${build_url}" ]]; then
        echo ""
        echo "See the [build log](${build_url}) for details."
    fi
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
        with_mage       # to run the checkBackportOwners target
    fi

    local remote="origin"
    local merge_base=""
    local check_exit=0
    merge_base="$(git merge-base "${BUILDKITE_COMMIT}" "${remote}/${BUILDKITE_PULL_REQUEST_BASE_BRANCH}")" || check_exit=$?

    echo "--- Checking package owners for PR #${BUILDKITE_PULL_REQUEST}"
    echo "Base branch: ${BUILDKITE_PULL_REQUEST_BASE_BRANCH}, merge-base: ${merge_base}, head: ${BUILDKITE_COMMIT}"

    local mismatches_json=""
    if [[ "${check_exit}" -eq 0 ]]; then
        mismatches_json="$(mage checkBackportOwners "${remote}" "${BACKPORT_OWNERS_SOURCE_BRANCH}" "${merge_base}" "${BUILDKITE_COMMIT}")" || check_exit=$?
    fi

    local comment
    if [[ "${check_exit}" -ne 0 ]]; then
        comment="$(build_owner_check_failure_comment "${BUILDKITE_BUILD_URL:-""}")"
    else
        comment="$(build_owner_check_comment "${mismatches_json}")"
    fi
    echo "${comment}"

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

    if [[ "${check_exit}" -ne 0 ]]; then
        echo ""
        echo "--- backport owner check failed to run (exit ${check_exit})"
        exit "${check_exit}"
    fi

    local mismatch_count
    mismatch_count="$(jq 'length' <<< "${mismatches_json}")"

    if [[ "${mismatch_count}" -gt 0 ]]; then
        echo ""
        echo "--- ${mismatch_count} package(s) have owner mismatches with \`main\`"
        exit 1
    fi
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
