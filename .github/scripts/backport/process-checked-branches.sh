#!/usr/bin/env bash
# Process checked branches from a backport checklist comment.
#
# For each checklist item that is checked but not yet processed, this script:
#   1. Skips branches that already have an open or merged PR (dedup guard).
#   2. Runs backport_apply.sh to cherry-pick the merge commit and open a PR.
#   3. Recovers gracefully when a concurrent run (e.g. a simultaneous push
#      event) already opened the PR — posts ✅ instead of a false ⚠️.
#   4. Updates the checklist comment with the outcome (✅ #PR or ⚠️ conflict).
#
# Required environment variables (set by the workflow step's env: block):
#   GH_TOKEN     GitHub token with contents:write and pull-requests:write.
#   REPOSITORY   GitHub repository in org/repo form.
#   MERGE_SHA    Full SHA of the merge commit to cherry-pick.
#   PR_AUTHOR    Login of the PR author (used in conflict messages).
#   COMMENT_ID   ID of the checklist comment to patch.
#   BODY_FILE    Path to a file containing the current checklist comment body.

set -euo pipefail

# Reuse the binary already built in the workflow's "Build backport tool" step.
export BACKPORT_BIN="$GITHUB_WORKSPACE/build/backport"

ITEMS=$("$GITHUB_WORKSPACE/build/backport" parse-checklist "$BODY_FILE")
SHORT_SHA="${MERGE_SHA:0:8}"

echo "$ITEMS" | jq -c '.[]' | while IFS= read -r item; do
  PKG=$(jq -r     '.Package'   <<< "$item")
  BRANCH=$(jq -r  '.Branch'    <<< "$item")
  CHECKED=$(jq -r '.Checked'   <<< "$item")
  PROCESSED=$(jq -r '.Processed' <<< "$item")

  if [[ "$CHECKED" != "true" || "$PROCESSED" != "false" ]]; then
    continue
  fi

  # Derive the version suffix from the branch name, mirroring workingBranchName in apply.go:
  #   strings.TrimPrefix(branchName, "backport-"+pkg+"-")
  # e.g. backport-aws-6.14 → "6.14", backport-kubernetes-1.x → "1.x"
  VERSION_SUFFIX="${BRANCH#backport-${PKG}-}"

  # Dedup: skip if a working branch for this exact (package, version, sha) already has a PR
  WORKING_BRANCH="auto-backport/${PKG}-${VERSION_SUFFIX}-${SHORT_SHA}"
  EXISTING=$(gh pr list --repo "$REPOSITORY" --head "$WORKING_BRANCH" --state all --json number --jq 'length')
  if [[ "${EXISTING:-0}" -gt 0 ]]; then
    echo "PR already exists for $WORKING_BRANCH — skipping"
    continue
  fi

  # Run the backport; --json ensures structured output even on conflict
  RESULT=$("$GITHUB_WORKSPACE/dev/scripts/backport_apply.sh" \
    --sha        "$MERGE_SHA" \
    --package    "$PKG" \
    --target     "$BRANCH" \
    --open-pr \
    --json \
    --repository "$REPOSITORY" || true)

  STATUS_VAL=$(jq -r '.status // empty' <<< "$RESULT" 2>/dev/null || true)
  if [[ "$STATUS_VAL" == "success" ]]; then
    PR_URL=$(jq -r '.pr_url' <<< "$RESULT")
    PR_NUM=$(echo "$PR_URL" | grep -oP '\d+$')
    STATUS="✅ #${PR_NUM}"
  else
    # Before reporting a conflict, check if a concurrent run (e.g. a push
    # event racing with this issue_comment event) already opened a PR for
    # this working branch. A push rejection is not a real cherry-pick conflict.
    CONCURRENT_PR=$(gh pr list --repo "$REPOSITORY" --head "$WORKING_BRANCH" \
      --state all --json number --jq 'first.number // empty')
    if [[ -n "$CONCURRENT_PR" ]]; then
      STATUS="✅ #${CONCURRENT_PR}"
    else
      SUGGESTED=$(jq -r '.suggested_command // empty' <<< "$RESULT" 2>/dev/null || true)
      STATUS="⚠️ conflict: @${PR_AUTHOR} please resolve manually${SUGGESTED:+: \`${SUGGESTED}\`}"
    fi
  fi

  # Update the in-memory checklist body and patch the GitHub comment
  NEW_BODY=$("$GITHUB_WORKSPACE/build/backport" update-checklist-status "$BODY_FILE" "$BRANCH" "$STATUS")
  printf '%s' "$NEW_BODY" > "$BODY_FILE"

  echo "Updating checklist comment for $BRANCH → $STATUS"
  gh api --method PATCH \
    "repos/$REPOSITORY/issues/comments/$COMMENT_ID" \
    --field body=@"$BODY_FILE" \
    --silent

  echo "Processed $BRANCH → $STATUS"
done
