#!/bin/bash
# Posts a comment on the PR that triggered the backport branch creation,
# reporting success or failure of the branch creation step.
# Expects env vars: PR_NUMBER, NOTIFY_STATUS (success|failure),
#                   BACKPORT_BRANCH_NAME, PACKAGE_NAME, PACKAGE_VERSION,
#                   BUILDKITE_BUILD_URL

source .buildkite/scripts/common.sh

set -euo pipefail

BACKPORT_BRANCH_NAME="$(buildkite-agent meta-data get BACKPORT_BRANCH_NAME --default "${BACKPORT_BRANCH_NAME:-""}")"
PACKAGE_NAME="$(buildkite-agent meta-data get PACKAGE_NAME --default "${PACKAGE_NAME:-""}")"
PACKAGE_VERSION="$(buildkite-agent meta-data get PACKAGE_VERSION --default "${PACKAGE_VERSION:-""}")"
PR_NUMBER="$(buildkite-agent meta-data get PR_NUMBER --default "${PR_NUMBER:-""}")"

if [[ -z "${PR_NUMBER}" ]]; then
    echo "PR_NUMBER not set, skipping PR notification"
    exit 0
fi

add_bin_path
with_github_cli

BODY_FILE="$(mktemp)"
trap 'rm -f "${BODY_FILE}"' EXIT

if [[ "${NOTIFY_STATUS}" == "success" ]]; then
    cat > "${BODY_FILE}" <<EOF
:white_check_mark: Backport branch \`${BACKPORT_BRANCH_NAME}\` created successfully for package \`${PACKAGE_NAME}\` \`${PACKAGE_VERSION}\`.

[Buildkite build](${BUILDKITE_BUILD_URL})
EOF
else
    cat > "${BODY_FILE}" <<EOF
:x: Failed to create backport branch \`${BACKPORT_BRANCH_NAME}\` for package \`${PACKAGE_NAME}\` \`${PACKAGE_VERSION}\`.

Check the [Buildkite build](${BUILDKITE_BUILD_URL}) for details.
EOF
fi

RUN_ID="backport-${BACKPORT_BRANCH_NAME}-${BUILDKITE_BUILD_NUMBER:-0}-${BUILDKITE_RETRY_COUNT:-0}"
retry 3 create_new_gh_pr_comment "elastic" "integrations" "${PR_NUMBER}" "${RUN_ID}" "${BODY_FILE}"
