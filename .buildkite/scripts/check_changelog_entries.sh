#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail

if [[ "${BUILDKITE_PULL_REQUEST:-"false"}" == "false" ]]; then
    echo "Not a pull request build, skipping changelog link check."
    exit 0
fi

# Derive the GitHub repo path from the Buildkite repo URL.
# Handles both SSH (git@github.com:org/repo.git) and HTTPS formats.
REPO_PATH=$(echo "${BUILDKITE_REPO}" | sed -E 's|.*github\.com[:/]([^/]+/[^/]+?)(\.git)?$|\1|')
EXPECTED_PR_LINK="https://github.com/${REPO_PATH}/pull/${BUILDKITE_PULL_REQUEST}"

echo "--- Checking changelog entries for PR #${BUILDKITE_PULL_REQUEST}"
echo "Expected PR link: ${EXPECTED_PR_LINK}"

BASE_REF="origin/${BUILDKITE_PULL_REQUEST_BASE_BRANCH}"

# Find all changelog.yml files that were added or modified in this PR,
# regardless of how deep they are nested inside packages/.
CHANGED_CHANGELOGS=$(git diff --name-only "${BASE_REF}" | grep 'changelog\.yml$' || true)

if [[ -z "${CHANGED_CHANGELOGS}" ]]; then
    echo "No changelog.yml files were modified in this PR."
    exit 0
fi

echo "Modified changelog files:"
echo "${CHANGED_CHANGELOGS}"
echo ""

errors=0

for changelog_file in ${CHANGED_CHANGELOGS}; do
    if [[ ! -f "${changelog_file}" ]]; then
        echo "[${changelog_file}] File deleted, skipping."
        continue
    fi

    echo "--- [${changelog_file}]"

    # Extract link values from lines that were added in the diff (+), ignoring context lines.
    added_links=$(git diff "${BASE_REF}" -- "${changelog_file}" \
        | grep -E '^\+[[:space:]]+link:' \
        | sed -E 's/^\+[[:space:]]+link:[[:space:]]*//' \
        || true)

    if [[ -z "${added_links}" ]]; then
        echo "No new 'link:' entries found, skipping."
        continue
    fi

    while IFS= read -r link; do
        [[ -z "${link}" ]] && continue
        if [[ "${link}" =~ /issues/[0-9]+$ ]]; then
            echo "SKIP: '${link}' (issue link, not required to match PR)"
        elif [[ "${link}" != "${EXPECTED_PR_LINK}" ]]; then
            echo "ERROR: unexpected link: '${link}'"
            echo "       expected:         '${EXPECTED_PR_LINK}'"
            errors=$((errors + 1))
            if running_on_buildkite; then
                buildkite-agent annotate \
                    "**Changelog link mismatch** in \`${changelog_file}\`:<br>Found: \`${link}\`<br>Expected: \`${EXPECTED_PR_LINK}\`" \
                    --context "ctx-changelog-${changelog_file//\//-}" \
                    --style "error"
            fi
        else
            echo "OK: '${link}'"
        fi
    done <<< "${added_links}"
done

if [[ "${errors}" -gt 0 ]]; then
    echo ""
    echo "${errors} changelog link(s) do not match this PR. Update the 'link:' field(s) in the changelog entries above to point to ${EXPECTED_PR_LINK}."
    exit 1
fi

echo ""
echo "All new changelog entries have the correct PR link."
