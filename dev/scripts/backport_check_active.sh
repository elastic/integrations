#!/usr/bin/env bash
# Evaluates whether a backport branch is active according to .backports.yml.
#
# Active branch logic (mirrors the schema in .backports.yml):
#   inactive if:  archived == true
#             OR  (maintained_until != null AND maintained_until < today)
#
# Usage: backport_check_active.sh --branch <branch-name> [--json]
# Exit codes: 0 = active, 1 = inactive, 2 = error (missing args, not found, etc.)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "${SCRIPT_DIR}" rev-parse --show-toplevel)"

# Allow tests to override the inventory path via env var.
INVENTORY="${BACKPORTS_INVENTORY:-${REPO_ROOT}/.backports.yml}"

BRANCH=""
JSON="false"

usage() {
    cat >&2 <<'EOF'
Usage: backport_check_active.sh --branch <branch-name> [--json]

Evaluates whether a backport branch is active per .backports.yml.

Exit codes: 0 = active, 1 = inactive, 2 = error

Options:
  --branch <name>   Branch name to evaluate (required)
  --json            Emit machine-readable JSON instead of plain text
  -h, --help        Show this help
EOF
    exit 2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --branch)
            [[ $# -lt 2 ]] && { echo "Error: --branch requires an argument" >&2; usage; }
            BRANCH="$2"
            shift 2
            ;;
        --json)
            JSON="true"
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Error: unknown option: $1" >&2
            usage
            ;;
    esac
done

if [[ -z "${BRANCH}" ]]; then
    echo "Error: --branch is required" >&2
    usage
fi

if [[ ! -f "${INVENTORY}" ]]; then
    echo "Error: inventory not found: ${INVENTORY}" >&2
    exit 2
fi

# Parse .backports.yml with awk and extract the fields for the target branch.
# The file has a predictable structure: each entry starts with "  - " at the
# top level and has 4-space-indented fields beneath it.
parse_entry() {
    local inventory="$1"
    local target="$2"
    awk -v target="${target}" '
        /^  - / {
            if (found) {
                print "archived=" archived
                print "maintained_until=" maintained_until
                found = 0
            }
            in_entry = 1; found = 0; archived = ""; maintained_until = ""
        }
        in_entry && /^    branch: / {
            val = $0
            sub(/^[ ]*branch:[ ]*/, "", val)
            gsub(/^"|"$/, "", val)
            if (val == target) found = 1
        }
        found && /^    archived: /        { archived = $2 }
        found && /^    maintained_until: / {
            val = $2
            gsub(/"/, "", val)
            maintained_until = val
        }
        END {
            if (found) {
                print "archived=" archived
                print "maintained_until=" maintained_until
            }
        }
    ' "${inventory}"
}

archived=""
maintained_until=""
while IFS='=' read -r key val; do
    case "${key}" in
        archived)         archived="${val}" ;;
        maintained_until) maintained_until="${val}" ;;
    esac
done < <(parse_entry "${INVENTORY}" "${BRANCH}")

if [[ -z "${archived}" ]]; then
    echo "Error: branch '${BRANCH}' not found in ${INVENTORY}" >&2
    exit 2
fi

# Apply active logic.
active="true"
reason=""

if [[ "${archived}" == "true" ]]; then
    active="false"
    reason="archived"
elif [[ "${maintained_until}" != "null" ]]; then
    today="$(date -u +%Y-%m-%d)"
    if [[ "${maintained_until}" < "${today}" ]]; then
        active="false"
        reason="maintained_until=${maintained_until} is past (today is ${today})"
    fi
fi

# Output result.
if [[ "${JSON}" == "true" ]]; then
    if [[ "${maintained_until}" == "null" ]]; then
        mu_json="null"
    else
        mu_json="\"${maintained_until}\""
    fi
    printf '{"branch":"%s","active":%s,"archived":%s,"maintained_until":%s}\n' \
        "${BRANCH}" "${active}" "${archived}" "${mu_json}"
else
    if [[ "${active}" == "true" ]]; then
        printf '%s: active\n' "${BRANCH}"
    else
        printf '%s: inactive (%s)\n' "${BRANCH}" "${reason}"
    fi
fi

[[ "${active}" == "true" ]]
