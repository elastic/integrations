#!/usr/bin/env bash
# Bring the elastic/integrations checkout to the latest elastic main before a triage, without touching your work.
# Usage: sync.sh            (run from the checkout root)
#   on branch main    fetch, then fast-forward only (stops if main diverged or local changes would be overwritten)
#   detached HEAD     (a dedicated triage worktree) check out the latest <remote>/main if the tree is clean
#   other branch      stop: switch to main, or run the triage from a dedicated worktree (see README)
# Exit 0 = synced; non-zero = not synced, with the reason on stderr. Never stashes, resets or discards changes.
set -euo pipefail
fail() { echo "SYNC FAILED: $*" >&2; exit 1; }

git rev-parse --show-toplevel >/dev/null 2>&1 || fail "not inside a git checkout"
REMOTE=$(git remote -v | awk '$2 ~ /github\.com[:\/]elastic\/integrations(\.git)?$/ && $3=="(fetch)" {print $1; exit}')
[ -n "$REMOTE" ] || fail "no remote points to github.com/elastic/integrations (add one: git remote add elastic git@github.com:elastic/integrations.git)"

git fetch -q "$REMOTE" main || fail "git fetch $REMOTE main failed (network or auth)"
TARGET="$REMOTE/main"
BRANCH=$(git branch --show-current)
BEFORE=$(git rev-parse --short HEAD)

if [ "$BRANCH" = main ]; then
  git merge -q --ff-only "$TARGET" 2>/dev/null ||
    fail "main can't fast-forward to $TARGET: it has local commits, or uncommitted changes touch files that changed upstream. Resolve it by hand"
elif [ -z "$BRANCH" ]; then
  if [ "$(git rev-parse HEAD)" != "$(git rev-parse "$TARGET")" ]; then
    git diff --quiet && git diff --cached --quiet || fail "detached worktree has uncommitted changes; clean it before syncing"
    git checkout -q --detach "$TARGET"
  fi
else
  fail "checkout is on branch '$BRANCH', not main. Run 'git switch main', or schedule the triage from a dedicated worktree: git worktree add --detach ../integrations-triage-run $TARGET"
fi

AFTER=$(git rev-parse --short HEAD)
n=$( [ "$BEFORE" = "$AFTER" ] && echo 0 || git rev-list --count "$BEFORE..$AFTER")
echo "synced: ${BRANCH:-detached} at $AFTER = $TARGET ($n new commits) — $(git log -1 --format='%cd %s' --date=short | cut -c1-90)"
dirty=$(git status --porcelain --untracked-files=no | awk '{print $2}')
if [ -n "$dirty" ]; then
  echo "uncommitted changes ($(wc -l <<<"$dirty" | tr -d ' ')): these files differ from $TARGET; don't treat them as upstream state:"
  sed 's/^/  /' <<<"$dirty" | head -10
fi
