#!/usr/bin/env bash
# backport_bootstrap_inventory.sh
#
# IMPORTANT: One-time bootstrap script kept for auditability.
# Run once to seed .backports.yml from existing backport-* branches.
# Do NOT use this script to maintain the inventory after the initial seed —
# update .backports.yml directly from that point on.
#
# See issue #19210 for context.
#
# After running, perform a manual review pass to:
#   - Fill in known maintained_until dates (e.g. stack EOL dates).
#   - Verify base_version entries marked with a WARN comment.
#
# Usage: ./dev/scripts/backport_bootstrap_inventory.sh [-r REMOTE] [-o OUTPUT] [-n]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "${SCRIPT_DIR}" rev-parse --show-toplevel)"

REMOTE="upstream"
OUTPUT="${REPO_ROOT}/.backports.yml"
FETCH="true"

usage() {
    cat >&2 <<'EOF'
Usage: backport_bootstrap_inventory.sh [-r REMOTE] [-o OUTPUT] [-n]

Seed .backports.yml from existing backport-* branches on a remote.

Options:
  -r REMOTE    Git remote name (default: upstream)
  -o OUTPUT    Output file path (default: <repo-root>/.backports.yml)
  -n           No-fetch: skip fetching remote refs (branches must already
               be locally cached as refs/remotes/<REMOTE>/backport-*)
  -h           Show this help

After running, manually review the output and fill in maintained_until dates.
EOF
    exit 1
}

while getopts ":r:o:nh" opt; do
    case "${opt}" in
        r) REMOTE="${OPTARG}" ;;
        o) OUTPUT="${OPTARG}" ;;
        n) FETCH="false" ;;
        h) usage; exit 0 ;;
        \?)
            echo "Invalid option: -${OPTARG}" >&2
            usage
            ;;
        :)
            echo "Missing argument for -${OPTARG}" >&2
            usage
            ;;
    esac
done

if [[ "${FETCH}" == "true" ]]; then
    echo "Fetching backport-* branches from ${REMOTE}..." >&2
    git fetch "${REMOTE}" \
        "refs/heads/backport-*:refs/remotes/${REMOTE}/backport-*" \
        --no-tags 2>&1 >&2
fi

ONE_YEAR_SECS=$(( 365 * 24 * 60 * 60 ))
NOW="$(date +%s)"

# Resolve the package name to a manifest.yml path at a given git object ref.
# Tries flat layout (packages/<pkg>/manifest.yml) first, then one level of nesting
# (packages/<folder>/<pkg>/manifest.yml), then falls back to scanning all manifests.
# Prints the path on success, nothing on failure.
find_manifest_path() {
    local ref="${1}"
    local pkg="${2}"

    # 1. Flat layout: packages/<pkg>/manifest.yml
    if git cat-file -e "${ref}:packages/${pkg}/manifest.yml" 2>/dev/null; then
        echo "packages/${pkg}/manifest.yml"
        return 0
    fi

    # 2. One-level nesting: packages/<folder>/<pkg>/manifest.yml
    local nested
    nested="$(git ls-tree --name-only "${ref}" packages/ 2>/dev/null | while IFS= read -r folder; do
        candidate="packages/${folder}/${pkg}/manifest.yml"
        if git cat-file -e "${ref}:${candidate}" 2>/dev/null; then
            echo "${candidate}"
            break
        fi
    done)"
    if [[ -n "${nested}" ]]; then
        echo "${nested}"
        return 0
    fi

    # 3. Full scan: match by name field (handles deeper or unusual layouts)
    local all_manifests
    while IFS= read -r candidate; do
        local name
        name="$(git show "${ref}:${candidate}" 2>/dev/null \
            | grep -m1 "^name:" \
            | sed "s/^name:[[:space:]]*//" \
            | tr -d "\"'")"
        if [[ "${name}" == "${pkg}" ]]; then
            echo "${candidate}"
            return 0
        fi
    done < <(git ls-tree -r --name-only "${ref}" packages/ 2>/dev/null \
        | grep '/manifest.yml$' \
        | grep -v '/data_stream/')

    return 1
}

# Read the version field from a manifest at a given git object ref + path.
get_version_at() {
    local ref="${1}"
    local manifest_path="${2}"
    git show "${ref}:${manifest_path}" 2>/dev/null \
        | grep -m1 "^version:" \
        | sed "s/^version:[[:space:]]*//" \
        | tr -d "\"'"
}

echo "Generating ${OUTPUT} from refs/remotes/${REMOTE}/backport-* ..." >&2

{
    cat <<'HEADER'
# Backport branch inventory — single source of truth.
# See issue #19210 for schema documentation.
#
# Active branch logic:
#   inactive if:  archived == true
#             OR  (maintained_until != null AND maintained_until < today)
#
# Fill in maintained_until for branches with known EOL dates (YYYY-MM-DD).
# Example: security_detection_engine-8.19 -> "2027-01-15" (8.19 EOL)
#
# This file was seeded by dev/scripts/backport_bootstrap_inventory.sh.
# Do not re-run the bootstrap — update this file directly.
HEADER

    echo "backports:"

    while IFS= read -r shortref; do
        branch="${shortref#"${REMOTE}/"}"
        ref="refs/remotes/${shortref}"

        # --- Parse package name and version suffix from branch name ---
        # Branch format: backport-<package>-<major>.<minor>[.<patch>]
        stripped="${branch#backport-}"

        pkg=""
        ver_suffix=""
        if echo "${stripped}" | grep -qE '^.+-[0-9]+\.[0-9]+(\.[0-9]+)?$'; then
            pkg="$(echo "${stripped}" | sed -E 's/-([0-9]+\.[0-9]+(\.[0-9]+)?)$//')"
            ver_suffix="$(echo "${stripped}" | sed -E 's/^.*-([0-9]+\.[0-9]+(\.[0-9]+)?)$/\1/')"
        fi

        if [[ -z "${pkg}" || -z "${ver_suffix}" ]]; then
            echo "  # WARNING: skipped — could not parse branch name: ${branch}" >&2
            printf '  # SKIPPED (unparseable): %s\n\n' "${branch}"
            continue
        fi

        echo "  Processing ${branch} ..." >&2

        # Major.minor from branch name (used to verify version family).
        ver_major_minor="$(echo "${ver_suffix}" | cut -d. -f1-2)"

        # --- base_commit resolution (three strategies, in order) ---
        #
        # 1. git merge-base: works when the original BASE_COMMIT is still reachable
        #    from upstream/main (i.e. main hasn't been rebased past it).
        #
        # 2. Parent-of-first-CI-sync: when the branch was created by backport_branch.sh,
        #    the script adds a "Update .buildkite folder from main" commit on top of
        #    BASE_COMMIT. The parent of that commit IS the BASE_COMMIT.  Reliable for
        #    semi-old branches that went through the backport script.
        #
        # 3. Branch tip: last resort when the above can't recover the right family.
        #    base_commit stays as the (stale) merge-base in this case.

        base_commit=""
        base_version=""
        version_warn=""

        # Strategy 1: merge-base
        merge_base_commit=""
        if merge_base_commit="$(git merge-base "refs/remotes/${REMOTE}/main" "${ref}" 2>/dev/null)"; then
            manifest_path="$(find_manifest_path "${merge_base_commit}" "${pkg}" 2>/dev/null)" || true
            if [[ -n "${manifest_path}" ]]; then
                candidate_ver="$(get_version_at "${merge_base_commit}" "${manifest_path}")"
                if echo "${candidate_ver}" | grep -qE "^${ver_major_minor//./\\.}(\.|\$)"; then
                    base_commit="${merge_base_commit}"
                    base_version="${candidate_ver}"
                    echo "    base_commit: merge-base (version ${base_version})" >&2
                fi
            fi
        fi

        # Strategy 2: parent of first CI-sync commit ("Update .buildkite folder from main")
        if [[ -z "${base_commit}" ]]; then
            first_ci="$(git log "${ref}" --format="%H %s" \
                | grep -iE "Update .buildkite (folder )?from main|Copy .buildkite from main|Add .buildkite.*to backport branch" \
                | tail -1 \
                | awk '{print $1}')" || true
            if [[ -n "${first_ci}" ]]; then
                ci_parent="${first_ci}^"
                manifest_path="$(find_manifest_path "${ci_parent}" "${pkg}" 2>/dev/null)" || true
                if [[ -n "${manifest_path}" ]]; then
                    candidate_ver="$(get_version_at "${ci_parent}" "${manifest_path}")"
                    if echo "${candidate_ver}" | grep -qE "^${ver_major_minor//./\\.}(\.|\$)"; then
                        base_commit="$(git rev-parse "${ci_parent}" 2>/dev/null)" || base_commit="${ci_parent}"
                        base_version="${candidate_ver}"
                        echo "    base_commit: CI-sync parent ${base_commit:0:10} (version ${base_version})" >&2
                    fi
                fi
            fi
        fi

        # Strategy 3: tip fallback (base_commit stays as stale merge-base if available)
        if [[ -z "${base_version}" ]]; then
            [[ -z "${base_commit}" ]] && base_commit="${merge_base_commit}"
            tip_manifest="$(find_manifest_path "${ref}" "${pkg}" 2>/dev/null)" || true
            if [[ -n "${tip_manifest}" ]]; then
                base_version="$(get_version_at "${ref}" "${tip_manifest}")"
                echo "    NOTE: base_version '${base_version}' read from branch tip — verify base_commit manually" >&2
            fi
        fi

        if [[ -z "${base_version}" ]]; then
            [[ -z "${base_commit}" ]] && base_commit="${merge_base_commit}"
            base_version="unknown"
            version_warn="  # WARN: could not determine base_version — fill in manually"
            echo "    WARNING: could not determine base_version for ${branch}" >&2
        fi

        base_commit_short="${base_commit:0:10}"

        # --- archived: true if last commit is older than one year ---
        archived="false"
        last_ts="$(git log -1 --format="%ct" "${ref}" 2>/dev/null)" || last_ts=0
        if (( NOW - last_ts > ONE_YEAR_SECS )); then
            archived="true"
        fi

        # --- Emit YAML entry ---
        if [[ -n "${version_warn}" ]]; then
            printf '%s\n' "${version_warn}"
        fi
        printf '  - package: %s\n'         "${pkg}"
        printf '    branch: %s\n'          "${branch}"
        printf '    base_version: "%s"\n'  "${base_version}"
        if [[ -n "${base_commit_short}" ]]; then
            printf '    base_commit: "%s"\n'  "${base_commit_short}"
        else
            printf '    base_commit: null  # WARN: could not determine\n'
        fi
        printf '    maintained_until: null\n'
        printf '    archived: %s\n'        "${archived}"
        printf '\n'

    done < <(git for-each-ref --format='%(refname:short)' \
        "refs/remotes/${REMOTE}/backport-*" \
        | sort)

} > "${OUTPUT}"

echo "" >&2
echo "Done. Written to ${OUTPUT}" >&2
echo "" >&2
echo "NEXT STEPS:" >&2
echo "  1. Review ${OUTPUT} for WARN entries and fix them." >&2
echo "  2. Fill in maintained_until for branches with known EOL dates." >&2
echo "     Format: \"YYYY-MM-DD\"  (e.g. Elastic 8.19 EOL = 2027-01-15)" >&2
echo "  3. Commit .backports.yml and this bootstrap script together." >&2
