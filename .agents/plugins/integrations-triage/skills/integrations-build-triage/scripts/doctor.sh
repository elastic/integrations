#!/usr/bin/env bash
# Check what the integrations-triage plugin needs, and print how to install/configure what's missing.
# Usage: doctor.sh [--unattended]    exit 0 = required pieces OK, 1 = something required is missing
# Required (scripts + unattended): bash, jq, yq, gh (authenticated), bk (authenticated for org elastic), git checkout of elastic/integrations
# Optional (interactive only): gcloud (private logs, user-approved), elastic-package + docker (local repro), MCP servers (fallback)
set -uo pipefail
UN=0; [ "${1:-}" = --unattended ] && UN=1
fail=0
ok()   { printf '  ✓ %s\n' "$*"; }
bad()  { printf '  ✗ %s\n' "$*"; fail=1; }
warn() { printf '  ! %s\n' "$*"; }
has()  { command -v "$1" >/dev/null 2>&1; }

echo "Required"
has jq && ok "jq $(jq --version)" || bad "jq missing: brew install jq | sudo apt install jq"
if has yq && yq --version 2>/dev/null | grep -q mikefarah; then ok "yq $(yq --version | grep -o 'v[0-9][0-9.]*' | tail -1)"
else bad "yq (mikefarah v4) missing: brew install yq | sudo snap install yq (apt's yq is a different tool)"; fi

if has gh; then
  if gh auth status >/dev/null 2>&1; then
    scopes=$(gh auth status 2>&1 | sed -n "s/.*Token scopes: //p" | head -1)
    ok "gh $(gh --version | head -1 | awk '{print $3}') authenticated (scopes: ${scopes:-?})"
    gh api repos/elastic/integrations --jq .full_name >/dev/null 2>&1 && ok "gh can read elastic/integrations" || bad "gh can't read elastic/integrations: check SSO authorization of the token (gh auth refresh -s repo,read:org)"
  else bad "gh not authenticated: ! gh auth login   (scopes: repo, read:org)"; fi
else bad "gh missing: brew install gh | Linux: https://github.com/cli/cli/blob/trunk/docs/install_linux.md, then: ! gh auth login"; fi

if has bk; then
  if bk build list -p elastic/integrations --limit 1 -o json >/dev/null 2>&1; then ok "bk $(bk --version | awk '{print $3}') authenticated for elastic/integrations"
  else bad "bk can't read elastic/integrations: ! bk configure --force   (org: elastic; Buildkite API token with read_builds, read_build_logs, read_artifacts)"; fi
else bad "bk (Buildkite CLI) missing: brew install buildkite/buildkite/bk | Linux: https://buildkite.com/docs/platform/cli/installation, then: ! bk configure"; fi

if git remote -v 2>/dev/null | grep -q 'elastic/integrations'; then ok "in an elastic/integrations checkout ($(git rev-parse --show-toplevel))"
else bad "not in an elastic/integrations checkout: cd to the repo root"; fi

if [ $UN = 0 ]; then
  echo "Optional (interactive only)"
  if has gcloud; then
    acct=$(gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null | head -1)
    [ -n "$acct" ] && ok "gcloud logged in (private logs: still asks for approval each time)" || warn "gcloud not logged in: ! gcloud auth login (only needed if you approve private-log reads)"
  else warn "gcloud missing (only for user-approved private logs): brew install --cask google-cloud-sdk | Linux: https://cloud.google.com/sdk/docs/install"; fi
  has elastic-package && ok "elastic-package $(elastic-package version 2>/dev/null | grep -o 'v[0-9.]*' | head -1) (local repro)" || warn "elastic-package missing (local repro): go install github.com/elastic/elastic-package@latest"
  if has docker && docker info >/dev/null 2>&1; then ok "docker running (local repro)"; else warn "docker not running (local repro, Docker MCP gateway)"; fi
  if has claude; then
    mcp=$(claude mcp list 2>/dev/null | grep -E '^MCP_DOCKER:' || true)
    if [ -n "$mcp" ] && has docker && docker mcp profile server ls 2>/dev/null | grep -qE 'github-official|buildkite'; then
      ok "MCP fallback: $(docker mcp profile server ls 2>/dev/null | awk '/github-official|buildkite/{printf "%s ", $NF}')via MCP_DOCKER (separate tokens from gh/bk; not used by the scripts)"
    else warn "no GitHub/Buildkite MCP: fine, the plugin uses the gh/bk CLIs. Optional: Docker MCP Toolkit with github-official + buildkite servers"; fi
  fi
fi

[ $fail = 0 ] && echo "OK: required pieces are ready" || echo "MISSING: fix the ✗ items above before running the triage"
exit $fail
