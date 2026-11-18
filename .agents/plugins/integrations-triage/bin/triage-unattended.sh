#!/usr/bin/env bash
# Unattended, draft-only triage.
# Usage: triage-unattended.sh [daily [YYYY-MM-DD] | <issue-number>] [integrations-repo-path (default: current directory)]
#   no argument / daily   the whole daily run: builds -> issues -> backlog sweep (/integrations-triage:triage-daily)
#   <issue-number>        one daily-job issue, "Too many" or per-package (/integrations-triage:triage-nightly)
# Run after the last scheduler run has reported (~06:30 UTC; the basic-subscription run starts at 04:30).
# Before triaging, scripts/sync.sh brings the checkout to the latest elastic/main (fast-forward only; it stops,
# without touching your work, if local changes conflict). On another branch it uses the triage worktree instead
# (../integrations-triage-run, or $TRIAGE_WORKTREE), and the run happens there.
# Env: TRIAGE_MAX_BUDGET_USD caps spend per run (optional).
# Never posts: the plugin guard hook blocks writes, private logs and local stack runs when TRIAGE_UNATTENDED=1.
set -euo pipefail
# launchd/cron don't load your shell profile: make gh, bk, jq, yq and claude findable
export PATH="/opt/homebrew/bin:/home/linuxbrew/.linuxbrew/bin:/usr/local/bin:/snap/bin:$HOME/.local/bin:$HOME/go/bin:$HOME/.claude/local:$PATH"
DEFAULT_REPO=$PWD
MODE=${1:-daily}
if [ "$MODE" = daily ]; then
  D=$(date -u +%F); REPO=$DEFAULT_REPO
  for a in "${@:2}"; do
    if [[ $a =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then D=$a; else REPO=$a; fi
  done
  CMD="/integrations-triage:triage-daily $D"; LOGDIR=build/triage/daily/$D/runs; TITLE="Daily triage $D"
else
  N=$MODE; REPO=${2:-$DEFAULT_REPO}
  CMD="/integrations-triage:triage-nightly $N"; LOGDIR=build/triage/issue-$N/runs; TITLE="Triage #$N"
fi
cd "$REPO"
git remote -v | grep -q 'elastic/integrations' || { echo "not an elastic/integrations checkout: $REPO" >&2; exit 1; }
SETUP_LOG=$(mktemp "${TMPDIR:-/tmp}/triage-setup.XXXXXX")
notify() {
  if command -v osascript >/dev/null; then osascript -e "display notification \"$1\" with title \"$TITLE\"" || true
  elif command -v notify-send >/dev/null; then notify-send "$TITLE" "$1" 2>/dev/null || true; fi
}
SCRIPTS="$(cd "$(dirname "$0")/.." && pwd)/skills/integrations-build-triage/scripts"
# Fail fast (no tokens spent) if gh/bk/jq/yq aren't ready, or the checkout can't be brought to the latest elastic/main
"$SCRIPTS/doctor.sh" --unattended > "$SETUP_LOG.doctor" 2>&1 || { cat "$SETUP_LOG.doctor"; notify "setup needed: see $SETUP_LOG.doctor"; exit 3; }
"$SCRIPTS/sync.sh" > "$SETUP_LOG.sync" 2>&1 || { cat "$SETUP_LOG.sync"; notify "not synced to elastic/main: see $SETUP_LOG.sync"; exit 4; }
cat "$SETUP_LOG.sync"
# sync.sh may have switched to the triage worktree: run (and log) from the root it reports
cd "$(sed -n 's/^root: //p' "$SETUP_LOG.sync" | tail -1)"
mkdir -p "$LOGDIR"; LOG=$LOGDIR/$(date -u +%Y%m%dT%H%MZ).log
mv "$SETUP_LOG.doctor" "$LOG.doctor"; mv "$SETUP_LOG.sync" "$LOG.sync"; rm -f "$SETUP_LOG"
export TRIAGE_UNATTENDED=1; rc=0
PLUGIN_ARGS=()
claude plugin list 2>/dev/null | grep -q integrations-triage || PLUGIN_ARGS=(--plugin-dir "$(cd "$(dirname "$0")/.." && pwd)")
claude -p "$CMD" ${PLUGIN_ARGS[@]+"${PLUGIN_ARGS[@]}"} \
  --permission-mode acceptEdits --permission-prompts none \
  ${TRIAGE_MAX_BUDGET_USD:+--max-budget-usd "$TRIAGE_MAX_BUDGET_USD"} \
  --allowedTools "Bash" "Read" "Grep" "Glob" "Write" "Edit" "Agent" "Skill" \
  --disallowedTools "Bash(gcloud:*)" "Bash(gsutil:*)" \
  > "$LOG" 2>&1 || rc=$?
tail -5 "$LOG"
TITLE="$TITLE (rc=$rc)" notify "$(tail -1 "$LOG" | tr -d '"' | cut -c1-120)"
exit $rc
