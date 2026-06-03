#!/bin/bash
# Triggered from the main pipeline when .backports.yml changes in a PR.
# For each entry that is new (absent from the base branch), uploads a trigger
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

if ! git show "origin/${BASE_BRANCH}:.backports.yml" > "${OLD_INVENTORY}" 2>/dev/null; then
    echo ".backports.yml is new on ${BASE_BRANCH} — skipping dry-runs for initial entries"
    echo "To validate new entries, add them in a follow-up PR after this one merges."
    # exit 0
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

    archived="$(yq "${entry} | .archived" "${NEW_INVENTORY}")"
    if [[ "${archived}" == "true" ]]; then
        echo "  Skipping archived entry: ${branch}"
        continue
    fi

    # Only trigger for entries that are new (absent from the old inventory).
    # If the entry already existed, the git branch is already created; there is
    # nothing to provision. This also covers re-activating a previously archived
    # entry (archived:true → false): the branch exists, so no dry-run is needed.
    old_branch="$(yq "${entry} | .branch" "${OLD_INVENTORY}")"

    if [[ -n "${old_branch}" ]]; then
        echo "  Skipping existing entry: ${branch} (already present in base branch)"
        continue
    fi

    pkg="$(yq "${entry} | .package" "${NEW_INVENTORY}")"
    base_version="$(yq "${entry} | .base_version" "${NEW_INVENTORY}")"
    base_commit="$(yq "${entry} | .base_commit" "${NEW_INVENTORY}")"

    if [[ "${pkg}" != "elastic_package_registry" ]]; then
        echo "  Skipping non-elastic_package_registry entry: ${branch}"
        continue
    fi
    if [[ "${base_version}" != "0.3.0" ]]; then
        echo "  Skipping non-0.3.0 version: ${branch}"
        continue
    fi
    if [[ "${base_commit}" != "65b2a04d98" ]]; then
        echo "  Skipping non-65b2a04d98 commit: ${branch}"
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
    echo "No new non-archived entries found, skipping dry-run trigger"
    rm -f "${PIPELINE_FILE}"
    exit 0
fi

echo "--- Uploading ${entries_found} dry-run trigger(s)"
cat "${PIPELINE_FILE}"
buildkite-agent pipeline upload "${PIPELINE_FILE}"
rm -f "${PIPELINE_FILE}"
