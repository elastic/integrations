#!/usr/bin/env bash
# Unit tests for check_backport_owners.sh.
# Run directly or via .buildkite/scripts/run_buildkite_scripts_tests.sh.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"

# Source the script without executing main so its functions are available.
source "${REPO_ROOT}/.buildkite/scripts/check_backport_owners.sh"
source "${REPO_ROOT}/.buildkite/scripts/test_helpers.sh"

pass=0
fail=0

# ---------------------------------------------------------------------------
# Tests: build_owner_check_comment
#
# Input is the JSON array emitted by `mage CheckBackportOwners -asJSON`: one
# object per changed package that either needs an owner sync (with a
# pre-resolved, deduped "teams" list) or couldn't be checked (with an
# "error" string instead). A package fully in sync with main is simply
# absent from the array — it never appears here.
# ---------------------------------------------------------------------------
echo "--- build_owner_check_comment tests"

assert_equals "empty array renders the in-sync confirmation" \
    ":white_check_mark: Package owners are in sync with \`main\`." \
    "$(build_owner_check_comment '[]')"

assert_equals "single mismatch mentions the resolved team" \
    "**Package owners are out of sync with \`main\`:**"$'\n\n'"- \`aws\` — should now be owned by @elastic/team-b" \
    "$(build_owner_check_comment '[{"package":"aws","teams":["@elastic/team-b"]}]')"

assert_equals "multiple teams for one package are joined with a comma" \
    "**Package owners are out of sync with \`main\`:**"$'\n\n'"- \`aws\` — should now be owned by @elastic/team-a, @elastic/team-b" \
    "$(build_owner_check_comment '[{"package":"aws","teams":["@elastic/team-a","@elastic/team-b"]}]')"

assert_equals "an error entry is reported without a team mention" \
    "**Package owners are out of sync with \`main\`:**"$'\n\n'"- \`nginx\` — could not check ownership on \`main\`: reading main manifest.yml: network error" \
    "$(build_owner_check_comment '[{"package":"nginx","error":"reading main manifest.yml: network error"}]')"

assert_equals "multiple packages render one line each, in order" \
    "**Package owners are out of sync with \`main\`:**"$'\n\n'"- \`aws\` — should now be owned by @elastic/team-b"$'\n'"- \`nginx\` — could not check ownership on \`main\`: network error" \
    "$(build_owner_check_comment '[{"package":"aws","teams":["@elastic/team-b"]},{"package":"nginx","error":"network error"}]')"

# ---------------------------------------------------------------------------
# Tests: build_owner_check_failure_comment
#
# Rendered instead of build_owner_check_comment when the check itself failed
# to run entirely (e.g. mage checkBackportOwners exited non-zero) — a
# distinct state from "no mismatches found", so it must never look like the
# in-sync confirmation.
# ---------------------------------------------------------------------------
echo ""
echo "--- build_owner_check_failure_comment tests"

assert_equals "with a build URL, includes a link to it" \
    ":warning: The backport owner check failed to run — it could not determine whether package owners are in sync with \`main\`."$'\n\n'"See the [build log](https://buildkite.example/builds/123) for details." \
    "$(build_owner_check_failure_comment "https://buildkite.example/builds/123")"

assert_equals "with no build URL, omits the link section" \
    ":warning: The backport owner check failed to run — it could not determine whether package owners are in sync with \`main\`." \
    "$(build_owner_check_failure_comment "")"

assert_equals "with no argument at all, omits the link section" \
    ":warning: The backport owner check failed to run — it could not determine whether package owners are in sync with \`main\`." \
    "$(build_owner_check_failure_comment)"

echo ""
echo "--- Results: ${pass} passed, ${fail} failed"
if [[ "${fail}" -gt 0 ]]; then
    exit 1
fi
