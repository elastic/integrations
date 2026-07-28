#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

CHANGELOG_SKIP_LABEL="${CHANGELOG_SKIP_LABEL:-"changelog-link-check:skip"}"

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

# Returns 0 (true) if the changelog link check should be skipped based on PR labels.
# Usage: should_skip_changelog_check <labels>
should_skip_changelog_check() {
    local labels="${1:-""}"
    [[ "${labels}" == *"${CHANGELOG_SKIP_LABEL}"* ]]
}

# Returns the @mention string for the given user, substituting elastic/ecosystem
# when the user is the github-actions[bot] automated user.
# Usage: get_pr_mention <user>
get_pr_mention() {
    local user="${1:-""}"
    if [[ -z "${user}" ]]; then
        echo ""
        return 0
    fi
    if [[ "${user}" == "github-actions[bot]" ]]; then
        user="elastic/ecosystem"
    fi
    echo $'\n'"@${user}"
}

# Posts a single Buildkite annotation and GitHub PR comment listing all files
# with changelog link mismatches.
# Usage: notify_changelog_mismatch <message> <pr_number>
notify_changelog_mismatch() {
    local message="$1"
    local pr_number="$2"

    echo "--- :bell: Sending mismatch notifications"

    buildkite-agent annotate \
        "${message}" \
        --context "ctx-changelog-link-mismatch" \
        --style "error"

    local mention
    mention="$(get_pr_mention "${GITHUB_PR_USER:-""}")"
    echo "${message}${mention}" > changelog-link-mismatch.txt
    if ! delete_and_create_gh_pr_comment \
        "${BUILDKITE_ORGANIZATION_SLUG}" \
        "integrations" \
        "${pr_number}" \
        "changelog-link-mismatch" \
        "changelog-link-mismatch.txt" ; then
        echo "Failed to post GitHub PR comment"
    fi
}

main() {
    set -euo pipefail

    if [[ "${BUILDKITE_PULL_REQUEST:-"false"}" == "false" ]]; then
        echo "Not a pull request build, skipping changelog link check."
        exit 0
    fi

    if should_skip_changelog_check "${GITHUB_PR_LABELS:-""}"; then
        echo "Skipping changelog link check: '${CHANGELOG_SKIP_LABEL}' label found."
        exit 0
    fi

    if running_on_buildkite; then
        # Install required tools to post comments in Pull Requests
        echo "--- Installing tools"
        add_bin_path
        with_jq         # containers do not have jq installed
        with_github_cli # to post comments in Pull Requests
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
    local failed_files=()

    while IFS= read -r changelog_file; do
        local file_errors=0
        check_changelog_file "${base_ref}" "${changelog_file}" "${expected_pr_link}" || file_errors=$?

        if [[ "${file_errors}" -gt 0 ]]; then
            total_errors=$((total_errors + file_errors))
            failed_files+=("${changelog_file}")
        fi
    done <<< "${changed_changelogs}"

    if [[ "${total_errors}" -gt 0 ]]; then
        echo ""
        echo "--- ${total_errors} changelog link(s) do not match this PR"
        local message="**Changelog link mismatch** — expected \`${expected_pr_link}\` in the following file(s):"$'\n'
        for f in "${failed_files[@]}"; do
            message+="- \`${f}\`"$'\n'
        done
        message+=$'\n'"> [!TIP]"$'\n'"> If expected, add the \`${CHANGELOG_SKIP_LABEL}\` label to skip this check. Or, if an issue link was intended, use \`.../issues/<n>\` instead."
        echo "${message}"
        if running_on_buildkite; then
            message+=$'\n\n'"[View Buildkite build](${BUILDKITE_BUILD_URL})"
            notify_changelog_mismatch "${message}" "${BUILDKITE_PULL_REQUEST}"
        fi
        exit 1
    fi

    echo ""
    echo "All new changelog entries have the correct PR link."
    if running_on_buildkite; then
        echo "--- :bell: Sending resolved notification"
        local resolved_message=":white_check_mark: All changelog entries have the correct PR link."
        echo "${resolved_message}" > changelog-link-resolved.txt
        if ! delete_and_create_gh_pr_comment \
            "${BUILDKITE_ORGANIZATION_SLUG}" \
            "integrations" \
            "${BUILDKITE_PULL_REQUEST}" \
            "changelog-link-mismatch" \
            "changelog-link-resolved.txt" ; then
            echo "Failed to update GitHub PR comment"
        fi
    fi
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
