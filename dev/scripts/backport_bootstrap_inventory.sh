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
        # Regex-safe major.minor for grep/sed matching.
        ver_family_regex="^${ver_major_minor//./\\.}(\.|\$)"

        # --- base_commit resolution ---
        #
        # The BASE_COMMIT is the commit on main from which the backport branch was
        # created.  Three fast strategies produce candidates; we then pick the
        # OLDEST (by commit timestamp) whose package version matches the branch's
        # major.minor family.  This correctly handles:
        #
        #   • Recent branches: merge-base is still in main (strategy A).
        #   • Old branches with CI-sync at creation time: parent of OLDEST CI-sync
        #     commit is the BASE_COMMIT (strategy C).
        #   • Old branches where CI-sync was RE-DONE after cherry-picks: the
        #     CI-sync parent is a cherry-pick, not the base.  Walking from HEAD
        #     skipping automation/backport commits finds the first "normal" commit
        #     (strategy B), and "oldest wins" picks the right one.
        #
        # If no candidate matches the version family, fall back to branch-tip version.

        base_commit=""
        base_version=""
        version_warn=""

        # Helper: check version family match.
        matches_family() { echo "${1}" | grep -qE "${ver_family_regex}"; }

        # Helper: get commit timestamp (unix seconds).
        commit_ts() { git log -1 --format="%ct" "${1}" 2>/dev/null; }

        # Collect candidate SHAs.
        cand_merge_base=""
        cand_walk=""
        cand_ci_parent=""

        # Strategy A: git merge-base
        cand_merge_base="$(git merge-base "refs/remotes/${REMOTE}/main" "${ref}" 2>/dev/null)" || true

        # Strategy B: walk from HEAD, skip CI-automation and explicit backport commits,
        # take the first "normal" commit (within the top 30).
        walk_count=0
        while IFS= read -r sha; do
            (( walk_count++ )) || true
            [[ "${walk_count}" -gt 30 ]] && break
            msg="$(git log -1 --format="%s" "${sha}" 2>/dev/null)"
            # Skip CI automation commits.
            echo "${msg}" | grep -qiE \
                "Update .buildkite (folder )?from main|Copy .buildkite from main|Add .buildkite.*to backport branch" \
                && continue
            # Skip explicit backport cherry-picks and double-PR cherry-picks.
            # Double-PR pattern "(#NNNNN) (#MMMMM)" at end of message is the standard
            # format for backport cherry-picks in this repo (first PR = original on main,
            # second PR = the backport PR targeting this branch).
            echo "${msg}" | grep -qiE "\[backport\]|\(backport\)|backporting |\(#[0-9]+\) \(#[0-9]+\)$" && continue
            cand_walk="${sha}"
            break
        done < <(git log "${ref}" --format="%H" 2>/dev/null)

        # Strategy C: parent of oldest (first) CI-sync commit.
        first_ci="$(git log "${ref}" --format="%H %s" 2>/dev/null \
            | grep -iE "Update .buildkite (folder )?from main|Copy .buildkite from main|Add .buildkite.*to backport branch" \
            | tail -1 | awk '{print $1}')" || true
        if [[ -n "${first_ci}" ]]; then
            cand_ci_parent="$(git rev-parse "${first_ci}^" 2>/dev/null)" || true
        fi

        # Among all candidates, pick the OLDEST whose version matches the version family.
        best_commit=""
        best_version=""
        best_ts=9999999999

        for candidate in "${cand_merge_base}" "${cand_walk}" "${cand_ci_parent}"; do
            [[ -z "${candidate}" ]] && continue
            m="$(find_manifest_path "${candidate}" "${pkg}" 2>/dev/null)" || true
            [[ -z "${m}" ]] && continue
            ver="$(get_version_at "${candidate}" "${m}")"
            matches_family "${ver}" || continue
            ts="$(commit_ts "${candidate}")"
            [[ -z "${ts}" ]] && continue
            if [[ -z "${best_commit}" || "${ts}" -lt "${best_ts}" ]]; then
                best_ts="${ts}"
                best_commit="${candidate}"
                best_version="${ver}"
            fi
        done

        if [[ -n "${best_commit}" ]]; then
            base_commit="${best_commit}"
            base_version="${best_version}"
            echo "    base_commit: ${base_commit:0:10} (version ${base_version})" >&2
        else
            # Fallback: use stale merge-base as commit, branch tip for version.
            base_commit="${cand_merge_base}"
            tip_manifest="$(find_manifest_path "${ref}" "${pkg}" 2>/dev/null)" || true
            if [[ -n "${tip_manifest}" ]]; then
                base_version="$(get_version_at "${ref}" "${tip_manifest}")"
                echo "    NOTE: using branch-tip version '${base_version}' — verify base_commit manually" >&2
            fi
        fi

        if [[ -z "${base_version}" ]]; then
            base_version="unknown"
            version_warn="  # WARN: could not determine base_version — fill in manually"
            echo "    WARNING: could not determine base_version for ${branch}" >&2
        fi

        base_commit_short="${base_commit:0:10}"

        # --- Check if base_commit is reachable from upstream/main ---
        # Old branches whose entire history diverged from main before a force-push
        # (or was never on main) produce a base_commit that is a valid branch ancestor
        # but not reachable from the current main lineage.
        base_commit_in_main="false"
        if [[ -n "${base_commit}" ]]; then
            if git merge-base --is-ancestor "${base_commit}" \
                    "refs/remotes/${REMOTE}/main" 2>/dev/null; then
                base_commit_in_main="true"
            else
                echo "    NOTE: base_commit ${base_commit_short} not reachable from ${REMOTE}/main" >&2
            fi
        fi

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
            if [[ "${base_commit_in_main}" == "false" ]]; then
                printf '    base_commit: "%s"  # not in upstream/main; next commit is branch-exclusive\n' \
                    "${base_commit_short}"
            else
                printf '    base_commit: "%s"\n'  "${base_commit_short}"
            fi
        else
            printf '    base_commit: null  # WARN: could not determine\n'
        fi
        printf '    maintained_until: null\n'
        printf '    archived: %s\n'        "${archived}"
        printf '\n'

    done < <(git for-each-ref --format='%(refname:short)' \
        "refs/remotes/${REMOTE}/backport-*" \
        | sed -E 's|^[^/]+/backport-([a-z_]+)-([0-9]+\.[0-9]+(\.[0-9]+)?)$|\1 \2 &|' \
        | sort -k1,1 -k2,2Vr \
        | awk '{print $NF}')

} > "${OUTPUT}"

echo "" >&2
echo "Done. Written to ${OUTPUT}" >&2
echo "" >&2
echo "NEXT STEPS:" >&2
echo "  1. Review ${OUTPUT} for WARN entries and fix them." >&2
echo "  2. Fill in maintained_until for branches with known EOL dates." >&2
echo "     Format: \"YYYY-MM-DD\"  (e.g. Elastic 8.19 EOL = 2027-01-15)" >&2
echo "  3. Commit .backports.yml and this bootstrap script together." >&2
