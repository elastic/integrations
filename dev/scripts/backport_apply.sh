#!/usr/bin/env bash
# backport_apply.sh — thin CLI wrapper around `mage ApplyBackport`.
#
# Usage:
#   dev/scripts/backport_apply.sh --sha <sha> --package <pkg> --target <target> \
#     [--open-pr] [--json] [--dry-run] \
#     [--repository <org/repo>] [--packages-dir <path>]
#
# Required:
#   --sha        Commit SHA to cherry-pick (min 8 chars).
#   --package    Package name as it appears in manifest.yml.
#   --target     Version series ("6.14") or full branch name ("backport-aws-6.14").
#
# Optional flags passed as mage *bool params:
#   --open-pr    Create a GitHub PR after pushing the working branch.
#   --json       Emit JSON output (success/conflict schemas per issue spec).
#   --dry-run    Commit locally but skip push and PR creation for local review.
#
# Optional strings passed as mage *string params:
#   --remote       Git remote to fetch from and push to (default: origin).
#   --repository   GitHub repository (org/repo) used in PR body and links.
#   --packages-dir Path to packages directory (default: packages).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "${SCRIPT_DIR}" rev-parse --show-toplevel)"

sha=""
pkg=""
target=""
open_pr="false"
as_json="false"
dry_run="false"
remote=""
repository=""
packages_dir=""

usage() {
    grep '^#' "$0" | grep -v '#!/' | sed 's/^# \?//' >&2
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --sha)           sha="$2";           shift 2 ;;
        --package)       pkg="$2";           shift 2 ;;
        --target)        target="$2";        shift 2 ;;
        --open-pr)       open_pr="true";     shift   ;;
        --json)          as_json="true";     shift   ;;
        --dry-run)       dry_run="true";     shift   ;;
        --remote)        remote="$2";        shift 2 ;;
        --repository)    repository="$2";    shift 2 ;;
        --packages-dir)  packages_dir="$2";  shift 2 ;;
        -h|--help)       usage ;;
        *) echo "Unknown option: $1" >&2; usage ;;
    esac
done

if [[ -z "$sha" || -z "$pkg" || -z "$target" ]]; then
    echo "error: --sha, --package, and --target are required" >&2
    usage
fi

cd "${REPO_ROOT}"

# *bool params are passed as -flagname; *string params are positional.
# All optional strings must be passed in declaration order; empty string = nil in mage.
bool_flags=()
[[ "$open_pr" == "true" ]] && bool_flags+=("-openPR")
[[ "$as_json"  == "true" ]] && bool_flags+=("-asJSON")
[[ "$dry_run"  == "true" ]] && bool_flags+=("-dryRun")

exec mage ApplyBackport \
    "$sha" "$pkg" "$target" \
    "${bool_flags[@]+"${bool_flags[@]}"}" \
    "$remote" "$repository" "$packages_dir"
