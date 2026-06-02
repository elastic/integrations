#!/bin/bash
# Triggered from the main pipeline when .backports.yml changes in a PR.
# For each entry that is new or has a changed base_commit, uploads a trigger
# step that runs the integrations-backport pipeline in DRY_RUN mode.

source .buildkite/scripts/common.sh

set -euo pipefail

if [[ "${BUILDKITE_PULL_REQUEST}" == "false" ]]; then
    echo "Not a pull request, skipping backport dry-run trigger"
    exit 0
fi

add_bin_path
with_yq

from="$(get_from_changeset)"
to="$(get_to_changeset)"
commit_merge="$(git merge-base "${from}" "${to}")"

if ! git diff --name-only "${commit_merge}" "${to}" | grep -qE '^\.backports\.yml$'; then
    echo ".backports.yml not changed, skipping backport dry-run trigger"
    exit 0
fi

echo "--- .backports.yml changed — finding new or updated entries"

BASE_BRANCH="${BUILDKITE_PULL_REQUEST_BASE_BRANCH}"

OLD_INVENTORY=""
PIPELINE_FILE=""

cleanup() {
    [[ -n "${OLD_INVENTORY}" ]] && rm -f "${OLD_INVENTORY}"
    [[ -n "${PIPELINE_FILE}" ]] && rm -f "${PIPELINE_FILE}"
}
trap cleanup EXIT

OLD_INVENTORY="$(mktemp)"
NEW_INVENTORY=".backports.yml"

if ! git show "origin/${BASE_BRANCH}:.backports.yml" > "${OLD_INVENTORY}" 2>/dev/null; then
    echo "Old .backports.yml not found (file is new); treating all entries as new"
    echo "backports: []" > "${OLD_INVENTORY}"
fi

PIPELINE_FILE="$(mktemp --suffix=.yml)"
entries_found=0

while IFS= read -r branch; do
    entry=".backports[] | select(.branch == \"${branch}\")"

    archived="$(yq "${entry} | .archived" "${NEW_INVENTORY}")"
    if [[ "${archived}" == "true" ]]; then
        continue
    fi

    pkg="$(yq "${entry} | .package" "${NEW_INVENTORY}")"
    base_version="$(yq "${entry} | .base_version" "${NEW_INVENTORY}")"
    base_commit="$(yq "${entry} | .base_commit" "${NEW_INVENTORY}")"

    # Determine whether this entry is new or has a meaningful change worth re-validating.
    # base_commit is the key input to backport_branch.sh: it is the commit on main from
    # which the backport branch is (or would be) created.  If it is unchanged from the
    # previous version of the inventory the branch already exists with the right base, so
    # there is nothing new to validate.  If it differs (or the branch is absent in the old
    # inventory, in which case old_base_commit is empty) a dry-run is warranted.
    old_base_commit="$(yq ".backports[] | select(.branch == \"${branch}\") | .base_commit" \
        "${OLD_INVENTORY}" 2>/dev/null || true)"

    if [[ "${old_base_commit}" == "${base_commit}" ]]; then
        continue
    fi

    echo "  Queuing dry-run: ${branch} (package=${pkg} version=${base_version} base_commit=${base_commit})"

    if [[ "${entries_found}" -eq 0 ]]; then
        printf 'steps:\n' > "${PIPELINE_FILE}"
    fi

    cat >> "${PIPELINE_FILE}" <<EOF
  - label: ":git: Backport dry-run: ${branch}"
    trigger: "integrations-backport"
    build:
      env:
        DRY_RUN: "true"
        PACKAGE_NAME: "${pkg}"
        PACKAGE_VERSION: "${base_version}"
        BASE_COMMIT: "${base_commit}"
EOF

    entries_found=$(( entries_found + 1 ))

done < <(yq '.backports[].branch' "${NEW_INVENTORY}")

rm -f "${OLD_INVENTORY}"

if [[ "${entries_found}" -eq 0 ]]; then
    echo "No new or changed non-archived entries found, skipping dry-run trigger"
    rm -f "${PIPELINE_FILE}"
    exit 0
fi

echo "--- Uploading ${entries_found} dry-run trigger(s)"
cat "${PIPELINE_FILE}"
buildkite-agent pipeline upload "${PIPELINE_FILE}"
rm -f "${PIPELINE_FILE}"
