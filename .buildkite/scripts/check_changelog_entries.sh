#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

# Extracts the GitHub org/repo path from a remote URL.
# Handles SSH (git@github.com:org/repo.git) and HTTPS formats.
github_repo_path() {
    local repo_url="$1"
    echo "${repo_url}" | sed -E 's|.*github\.com[:/]||; s|\.git$||'
}

# Returns the link: values added in the diff of a changelog file.
# Usage: get_added_links <base_ref> <changelog_file>
get_added_links() {
    local base_ref="$1"
    local changelog_file="$2"
    git diff "${base_ref}" -- "${changelog_file}" \
        | grep -E '^\+[[:space:]]+link:' \
        | sed -E 's/^\+[[:space:]]+link:[[:space:]]*//' \
        || true
}

# Validates the link: entries added to a changelog file in this PR.
# Prints a result line per link (OK / SKIP / ERROR).
# Returns the number of invalid links found.
# Usage: check_changelog_file <base_ref> <changelog_file> <expected_pr_link>
check_changelog_file() {
    local base_ref="$1"
    local changelog_file="$2"
    local expected_pr_link="$3"
    local errors=0

    if [[ ! -f "${changelog_file}" ]]; then
        echo "[${changelog_file}] File deleted, skipping."
        return 0
    fi

    echo "--- [${changelog_file}]"

    local added_links
    added_links=$(get_added_links "${base_ref}" "${changelog_file}")

    if [[ -z "${added_links}" ]]; then
        echo "No new 'link:' entries found, skipping."
        return 0
    fi

    while IFS= read -r link; do
        [[ -z "${link}" ]] && continue
        if [[ "${link}" =~ /issues/[0-9]+$ ]]; then
            echo "SKIP: '${link}' (issue link, not required to match PR)"
        elif [[ "${link}" != "${expected_pr_link}" ]]; then
            echo "ERROR: unexpected link: '${link}'"
            echo "       expected:         '${expected_pr_link}'"
            errors=$((errors + 1))
        else
            echo "OK: '${link}'"
        fi
    done <<< "${added_links}"

    return "${errors}"
}

main() {
    set -euo pipefail

    if [[ "${BUILDKITE_PULL_REQUEST:-"false"}" == "false" ]]; then
        echo "Not a pull request build, skipping changelog link check."
        exit 0
    fi

    local repo_path
    repo_path=$(github_repo_path "${BUILDKITE_REPO}")
    local expected_pr_link="https://github.com/${repo_path}/pull/${BUILDKITE_PULL_REQUEST}"
    local base_ref="origin/${BUILDKITE_PULL_REQUEST_BASE_BRANCH}"

    echo "--- Checking changelog entries for PR #${BUILDKITE_PULL_REQUEST}"
    echo "Expected PR link: ${expected_pr_link}"

    local changed_changelogs
    changed_changelogs=$(git diff --name-only "${base_ref}" | grep 'changelog\.yml$' || true)

    if [[ -z "${changed_changelogs}" ]]; then
        echo "No changelog.yml files were modified in this PR."
        exit 0
    fi

    echo "Modified changelog files:"
    echo "${changed_changelogs}"
    echo ""

    local total_errors=0

    for changelog_file in ${changed_changelogs}; do
        local file_errors=0
        check_changelog_file "${base_ref}" "${changelog_file}" "${expected_pr_link}" || file_errors=$?

        if [[ "${file_errors}" -gt 0 ]]; then
            total_errors=$((total_errors + file_errors))
            if running_on_buildkite; then
                buildkite-agent annotate \
                    "**Changelog link mismatch** in \`${changelog_file}\`. Expected: \`${expected_pr_link}\`" \
                    --context "ctx-changelog-${changelog_file//\//-}" \
                    --style "error"
            fi
        fi
    done

    if [[ "${total_errors}" -gt 0 ]]; then
        echo ""
        echo "${total_errors} changelog link(s) do not match this PR. Update the 'link:' field(s) in the changelog entries above to point to ${expected_pr_link}."
        exit 1
    fi

    echo ""
    echo "All new changelog entries have the correct PR link."
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
