#!/usr/bin/env bash
# Check whether the private CI logs can be read, and tell the user what to install or configure.
# Usage:
#   gcs-preflight.sh                  local checks only (no bucket access): run BEFORE asking permission
#   gcs-preflight.sh <B> [pkg]        also list the build/package prefix: run only AFTER the user said yes
set -uo pipefail
ok=1
say() { printf '%s %s\n' "$1" "$2"; }

if ! command -v gcloud >/dev/null 2>&1; then
  say "✗" "gcloud not installed. Install: brew install --cask google-cloud-sdk (or https://cloud.google.com/sdk/docs/install), then: gcloud auth login"
  exit 2
fi
say "✓" "gcloud $(gcloud version 2>/dev/null | sed -n 's/^Google Cloud SDK //p')"

acct=$(gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null | head -1)
if [ -z "$acct" ]; then
  say "✗" "no active gcloud account. Run: ! gcloud auth login"; ok=0
else
  say "✓" "active account: ${acct%%@*}@…"
  if ! gcloud auth print-access-token >/dev/null 2>&1; then
    say "✗" "credentials expired. Run: ! gcloud auth login"; ok=0
  fi
fi
[ "$ok" = 1 ] || exit 3

if [ $# -eq 0 ]; then
  say "→" "local checks passed. Ask the user for permission before reading the bucket."
  exit 0
fi

B=$1; PKG=${2:-}
L="gs://ecosystem-ci-internal/buildkite/integrations/main-integrations-$B/insecure-logs${PKG:+/$PKG/container-logs}/"
if out=$(gcloud storage ls -l "$L" 2>&1); then
  say "✓" "access to $L"
  echo "$out" | grep -v '^TOTAL' | awk '{printf "  %8.0f KB  %s\n", $1/1024, $NF}' | sed 's|.*/||; s|^|  |' | head -30
else
  case "$out" in
    *403*|*AccessDenied*|*"does not have"*) say "✗" "no permission on gs://ecosystem-ci-internal. The account needs read access to that bucket (ask the team that owns the integrations CI);" ;;
    *404*|*"matched no objects"*|*"One or more URLs matched no objects"*) say "✗" "nothing under $L (logs expired, wrong build/package, or the job uploaded none)" ;;
    *) say "✗" "listing failed: $(echo "$out" | head -2)" ;;
  esac
  exit 4
fi
