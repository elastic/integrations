#!/bin/bash
# Shared library for trigger_backport.sh.
# Source this file — do not execute directly.
#
# Provides resolve_pr_number(), backports_yml_changed(), load_old_backports_inventory(),
# and generate_trigger_pipeline().
# resolve_pr_number() looks up the PR that introduced a given commit via the GitHub API.
# backports_yml_changed() checks whether .backports.yml was modified between two git refs.
# load_old_backports_inventory() extracts .backports.yml at a given git ref into a file.
# generate_trigger_pipeline() validates the new inventory via mage ValidateBackportsInventory,
# iterates over a new .backports.yml, finds entries absent from the old inventory, and writes
# Buildkite trigger steps to a pipeline file. The caller decides whether to upload the result.

resolve_pr_number() {
    local commit="$1"
    local pr_number
    if ! pr_number="$(gh api "repos/elastic/integrations/commits/${commit}/pulls" \
            --jq '.[0].number // empty')"; then
        echo "Failed to call GitHub API for commit ${commit}" >&2
        return 1
    fi
    if [[ -n "${pr_number}" ]]; then
        echo "Associated PR: #${pr_number}" >&2
    else
        echo "No PR found for commit ${commit}" >&2
    fi
    echo "${pr_number}"
}

load_old_backports_inventory() {
    local git_ref="$1"
    local output_file="$2"
    if ! git show "${git_ref}:.backports.yml" > "${output_file}" 2>/dev/null; then
        echo "Note: .backports.yml not found at ref '${git_ref}'" >&2
        return 1
    fi
}

backports_yml_changed() {
    local from="$1"
    local to="$2"
    local changed
    if ! changed="$(git diff --name-only "${from}" "${to}" -- .backports.yml)"; then
        echo "ERROR: git diff failed for refs '${from}' '${to}'" >&2
        return 2
    fi
    [[ -n "${changed}" ]]
}

generate_trigger_pipeline() {
    local old_inventory="$1"    # path to the pre-change inventory
    local new_inventory="$2"    # path to the post-change inventory
    local dry_run="$3"          # "true" or "false" — passed to the triggered build
    local pr_number="$4"        # merged PR number, may be empty
    local pipeline_file="$5"    # output file; written only if new entries are found
    local buildkite_pr="${6:-}" # BUILDKITE_PULL_REQUEST value; empty or "false" means not a PR build
    local buildkite_commit="${7:-}" # BUILDKITE_COMMIT value; only used when buildkite_pr is set

    if ! yq -e '.backports' "${old_inventory}" > /dev/null 2>&1; then
        echo "ERROR: old inventory is not valid YAML or missing 'backports' key: ${old_inventory}" >&2
        return 1
    fi

    if ! yq -e '.backports' "${new_inventory}" > /dev/null 2>&1; then
        echo "ERROR: new inventory is not valid YAML or missing 'backports' key: ${new_inventory}" >&2
        return 1
    fi

    if ! mage ValidateBackportsInventory; then
        echo "ERROR: new inventory failed schema validation" >&2
        return 1
    fi

    local label_prefix="Backport create"
    if [[ "${dry_run}" == "true" ]]; then
        label_prefix="Backport dry-run"
    fi

    while IFS= read -r branch; do
        local entry=".backports[] | select(.branch == \"${branch}\")"

        # Only trigger for entries that are new (absent from the old inventory).
        # If the entry already existed, the branch is already created; nothing to provision.
        # This also covers re-activating a previously archived entry (archived:true → false):
        # the branch exists, so no trigger is needed.
        local old_branch
        old_branch="$(yq "${entry} | .branch" "${old_inventory}")"
        if [[ -n "${old_branch}" ]]; then
            echo "  Skipping existing entry: ${branch} (already present)"
            continue
        fi

        local active_exit=0
        mage CheckBackportBranchActive "${branch}" || active_exit=$?
        if [[ "${active_exit}" -eq 2 ]]; then
            echo "ERROR: failed to check active status for branch '${branch}'" >&2
            return 1
        fi
        if [[ "${active_exit}" -ne 0 ]]; then
            echo "  Skipping inactive entry: ${branch}"
            continue
        fi

        local pkg base_version base_commit remove_other_packages
        pkg="$(yq "${entry} | .package" "${new_inventory}")"
        base_version="$(yq "${entry} | .base_version" "${new_inventory}")"
        base_commit="$(yq "${entry} | .base_commit" "${new_inventory}")"
        remove_other_packages="$(yq "${entry} | .remove_other_packages" "${new_inventory}")"
        # Default to true if not set in the inventory entry
        if [[ -z "${remove_other_packages}" ]] || [[ "${remove_other_packages}" == "null" ]]; then
            remove_other_packages="true"
        fi

        echo "  Queuing ${label_prefix}: ${branch} (package=${pkg} version=${base_version} base_commit=${base_commit})"

        if [[ ! -s "${pipeline_file}" ]]; then
            printf 'steps:\n' > "${pipeline_file}"
        fi

        cat >> "${pipeline_file}" <<EOF
  - label: ":git: ${label_prefix}: ${branch}"
    key: "trigger-${branch//./-}"
    trigger: "integrations-backport"
    build:
      env:
        DRY_RUN: "${dry_run}"
        PACKAGE_NAME: "${pkg}"
        PACKAGE_VERSION: "${base_version}"
        BASE_COMMIT: "${base_commit}"
        BACKPORT_BRANCH_NAME: "${branch}"
        REMOVE_OTHER_PACKAGES: "${remove_other_packages}"
EOF
        # Only write PR-specific overrides when running inside a pull request build.
        # Uncommenting them lets backport_branch.sh run from the PR's HEAD instead of main.
        if [[ -n "${buildkite_pr}" ]] && [[ "${buildkite_pr}" != "false" ]]; then
            cat >> "${pipeline_file}" <<EOF
        # BUILDKITE_REFSPEC: "refs/pull/${buildkite_pr}/head"
        # BUILDKITE_COMMIT: "${buildkite_commit}"
EOF
        fi
        if [[ -n "${pr_number}" ]]; then
            cat >> "${pipeline_file}" <<EOF
        PR_NUMBER: "${pr_number}"
EOF
        fi

    done < <(yq '.backports[].branch' "${new_inventory}")
}
