#!/bin/bash
# Posts a comment on the PR that triggered the backport branch creation,
# reporting success or failure of the branch creation step.
# Expects env vars: PR_NUMBER, NOTIFY_STATUS (success|failure),
#                   BACKPORT_BRANCH_NAME, PACKAGE_NAME, PACKAGE_VERSION,
#                   BUILDKITE_BUILD_URL

source .buildkite/scripts/common.sh

set -euo pipefail

if [[ -z "${PR_NUMBER:-}" ]]; then
    echo "PR_NUMBER not set, skipping PR notification"
    exit 0
fi

add_bin_path
with_github_cli

REPO="elastic/integrations"
BRANCH="${BACKPORT_BRANCH_NAME}"
PKG="${PACKAGE_NAME}"
VERSION="${PACKAGE_VERSION}"

BODY_FILE="$(mktemp)"
trap 'rm -f "${BODY_FILE}"' EXIT

if [[ "${NOTIFY_STATUS}" == "success" ]]; then
    cat > "${BODY_FILE}" <<EOF
:white_check_mark: Backport branch \`${BRANCH}\` created successfully for package \`${PKG}\` \`${VERSION}\`.

[Buildkite build](${BUILDKITE_BUILD_URL})
EOF
else
    cat > "${BODY_FILE}" <<EOF
:x: Failed to create backport branch \`${BRANCH}\` for package \`${PKG}\` \`${VERSION}\`.

Check the [Buildkite build](${BUILDKITE_BUILD_URL}) for details.
EOF
fi

retry 3 gh pr comment "${PR_NUMBER}" --repo "${REPO}" --body-file "${BODY_FILE}"
