#!/usr/bin/env bash
# Evaluates whether a backport branch is active according to .backports.yml.
#
# Active branch logic (mirrors the schema in .backports.yml):
#   inactive if:  archived == true
#             OR  (maintained_until != null AND maintained_until < today)
#
# Requires: yq (https://github.com/mikefarah/yq)
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

entry=".backports[] | select(.branch == \"${BRANCH}\")"

if [[ "$(yq "[${entry}] | length" "${INVENTORY}")" -eq 0 ]]; then
    echo "Error: branch '${BRANCH}' not found in ${INVENTORY}" >&2
    exit 2
fi

archived="$(yq "${entry} | .archived" "${INVENTORY}")"
maintained_until="$(yq "${entry} | .maintained_until" "${INVENTORY}")"

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
