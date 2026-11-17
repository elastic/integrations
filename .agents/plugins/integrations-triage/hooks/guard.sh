#!/usr/bin/env bash
# PreToolUse guard for the integrations triage plugin. Exit 2 blocks the call; stderr goes back to Claude.
# Active only inside an elastic/integrations checkout, or when TRIAGE_UNATTENDED=1 / TRIAGE_GUARD=1.
#   always:      GitHub writes (gh CLI + MCP), Buildkite retries/rebuilds/cancels
#   unattended:  also private CI logs (gcloud/gsutil) and local stack runs (elastic-package stack/test, docker run)
set -uo pipefail
in=$(cat)
tool=$(jq -r '.tool_name // ""' <<<"$in")
cwd=$(jq -r '.cwd // ""' <<<"$in")
unattended=${TRIAGE_UNATTENDED:-0}

active=0
[ "$unattended" = 1 ] || [ "${TRIAGE_GUARD:-0}" = 1 ] && active=1
if [ $active = 0 ] && [ -n "$cwd" ]; then
  git -C "$cwd" remote -v 2>/dev/null | grep -q 'elastic/integrations\(\.git\)\? ' && active=1
fi
[ $active = 1 ] || exit 0

block() { echo "BLOCKED by integrations-triage guard: $1. Write a draft under build/triage/ and list it under \"Proposed actions (needs human)\" instead." >&2; exit 2; }

if [[ "$tool" == mcp__* ]]; then
  echo "$tool" | grep -Eiq '(create|add_.*comment|comment|issue_write|update_(issue|pull)|merge|review_write|push_files|delete|sub_issue|assign|retry|rebuild|cancel|unblock|create_build|create_pipeline|update_pipeline)' &&
    block "MCP write tool $tool"
  exit 0
fi
[ "$tool" = Bash ] || exit 0
cmd=$(jq -r '.tool_input.command // ""' <<<"$in")

# GitHub CLI writes
grep -Eq '(^|[;&|( ]|/)gh +(issue|pr) +(create|comment|edit|close|reopen|delete|transfer|pin|unpin|lock|unlock|review|merge|ready|develop)\b' <<<"$cmd" && block "gh write command"
grep -Eq '(^|[;&|( ]|/)gh +(release|label|repo|gist|workflow|run) +(create|edit|delete|upload|run|rerun|cancel|fork|clone)\b' <<<"$cmd" &&
  ! grep -Eq 'gh +repo +(view|clone)' <<<"$cmd" && block "gh write command"
if grep -Eq '(^|[;&|( ]|/)gh +api\b' <<<"$cmd"; then
  grep -Eiq -- '(-X|--method)[ =]*(POST|PATCH|PUT|DELETE)' <<<"$cmd" && block "gh api write method"
  if grep -Eq 'gh +api +graphql' <<<"$cmd"; then
    grep -q 'mutation' <<<"$cmd" && block "GraphQL mutation"
  elif grep -Eq -- '(^| )(-f|-F|--field|--raw-field|--input)( |=)' <<<"$cmd" && ! grep -Eiq -- '(-X|--method)[ =]*GET' <<<"$cmd"; then
    block "gh api with fields defaults to POST (add -X GET for reads)"
  fi
fi
# sweep.sh writes CLOSE_COMMANDS.sh for the human; running it would close issues
grep -Eq '((^|[;&|( ])(bash|sh|zsh|source|\.) +[^ ]*CLOSE_COMMANDS|(^|[;&|(]) *[^ ]*/CLOSE_COMMANDS[^ ]*\.sh)' <<<"$cmd" && block "running CLOSE_COMMANDS.sh closes issues; only the human runs it"
# Buildkite writes
grep -Eq '(^|[;&|( ]|/)bk +(job +(retry|cancel|unblock|reprioritize)|build +(create|new|rebuild|cancel|unblock))\b' <<<"$cmd" && block "Buildkite write command"

if [ "$unattended" = 1 ]; then
  grep -Eq '(^|[;&|( ]|/)(gcloud|gsutil)\b' <<<"$cmd" && block "private CI logs need human approval (unattended run)"
  grep -Eq '(^|[;&|( ]|/)elastic-package +(stack|test|service|benchmark)\b' <<<"$cmd" && block "local stack/test runs are interactive-only"
  grep -Eq '(^|[;&|( ]|/)docker +(run|compose|start)\b' <<<"$cmd" && block "docker runs are interactive-only"
fi
exit 0
