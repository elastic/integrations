#!/bin/bash
# Triggered from the main pipeline when .backports.yml changes on a push to main.
# For each entry that is new (absent from HEAD^), uploads a trigger step that
# runs the integrations-backport pipeline with DRY_RUN=false.

source .buildkite/scripts/common.sh

set -euo pipefail

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

if ! yq -e '.backports' "${OLD_INVENTORY}" > /dev/null; then
    echo "ERROR: old inventory is not valid YAML or missing 'backports' key: ${OLD_INVENTORY}"
    exit 1
fi

if ! yq -e '.backports' "${NEW_INVENTORY}" > /dev/null; then
    echo "ERROR: new inventory is not valid YAML or missing 'backports' key: ${NEW_INVENTORY}"
    exit 1
fi

PIPELINE_FILE="$(mktemp --suffix=.yml)"
entries_found=0

while IFS= read -r branch; do
    entry=".backports[] | select(.branch == \"${branch}\")"

    active_exit=0
    mage CheckBackportBranchActive "${branch}" || active_exit=$?
    if [[ "${active_exit}" -eq 2 ]]; then
        echo "ERROR: failed to check active status for branch '${branch}'"
        exit 1
    fi
    if [[ "${active_exit}" -ne 0 ]]; then
        echo "  Skipping inactive entry: ${branch}"
        continue
    fi

    # Only trigger for entries that are new (absent from the pre-merge state).
    # If the entry already existed, the branch is already created; nothing to provision.
    old_branch="$(yq "${entry} | .branch" "${OLD_INVENTORY}")"

    if [[ -n "${old_branch}" ]]; then
        echo "  Skipping existing entry: ${branch} (already present before merge)"
        continue
    fi

    pkg="$(yq "${entry} | .package" "${NEW_INVENTORY}")"
    base_version="$(yq "${entry} | .base_version" "${NEW_INVENTORY}")"
    base_commit="$(yq "${entry} | .base_commit" "${NEW_INVENTORY}")"

    echo "  Queuing create: ${branch} (package=${pkg} version=${base_version} base_commit=${base_commit})"

    if [[ "${entries_found}" -eq 0 ]]; then
        printf 'steps:\n' > "${PIPELINE_FILE}"
    fi

    cat >> "${PIPELINE_FILE}" <<EOF
  - label: ":git: Backport create: ${branch}"
    trigger: "integrations-backport"
    build:
      meta_data:
        DRY_RUN: "false"
        PACKAGE_NAME: "${pkg}"
        PACKAGE_VERSION: "${base_version}"
        BASE_COMMIT: "${base_commit}"
        BACKPORT_BRANCH_NAME: "${branch}"
EOF
    if [[ -n "${PR_NUMBER}" ]]; then
        cat >> "${PIPELINE_FILE}" <<EOF
        PR_NUMBER: "${PR_NUMBER}"
EOF
    fi

    entries_found=$(( entries_found + 1 ))

done < <(yq '.backports[].branch' "${NEW_INVENTORY}")

rm -f "${OLD_INVENTORY}"

if [[ "${entries_found}" -eq 0 ]]; then
    echo "No new non-archived entries found, skipping create trigger"
    rm -f "${PIPELINE_FILE}"
    exit 0
fi

echo "--- Uploading ${entries_found} create trigger(s)"
cat "${PIPELINE_FILE}"
buildkite-agent pipeline upload "${PIPELINE_FILE}"
rm -f "${PIPELINE_FILE}"
