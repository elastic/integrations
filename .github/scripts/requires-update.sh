#!/usr/bin/env bash
set -euo pipefail

# --preview: print what would be created (PRs and issues) without touching git or GitHub.
# Usage: bash requires-update.sh --preview <json-file>
#        bash requires-update.sh <json-file>
PREVIEW=false
if [[ "${1:-}" == "--preview" ]]; then
  PREVIEW=true
  shift
fi

JSON_FILE="${1:?Usage: $0 [--preview] <requires-update-json>}"

if [ ! -f "$JSON_FILE" ]; then
  echo "No changes found (JSON report not written) — exiting."
  exit 0
fi

team_count=$(jq 'length' "$JSON_FILE")
if [ "$team_count" -eq 0 ]; then
  echo "No changes to commit — exiting."
  exit 0
fi

generate_pr_body() {
  local team_entry="$1"
  echo "## Packages updated"
  echo ""
  echo "$team_entry" | jq -r '
    .packages[] |
    "### `" + .name + "`\n" +
    (if (.applied | length) > 0 then
      ([.applied[] | "- **" + .package + "** (`" + .kind + "`): `" + .current + "` → `" + .proposed + "`"] | join("\n"))
    else "" end) +
    (if (.skipped | length) > 0 then
      "\n" + ([.skipped[] | "- ⚠️ **" + .package + "** skipped: " + .warning] | join("\n"))
    else "" end) +
    "\n"
  '
}

generate_issue_body() {
  local team_entry="$1"
  local slug="$2"
  echo "The following packages have dependency updates available but could not be applied automatically."
  echo ""
  echo "$team_entry" | jq -r '
    .packages[] | select((.skipped | length) > 0) |
    "### `" + .name + "`\n" +
    ([.skipped[] | "- **" + .package + "**: " + .warning] | join("\n")) +
    "\n"
  '
  echo "/cc @elastic/${slug}"
}

while IFS= read -r team_entry; do
  slug=$(echo "$team_entry" | jq -r '.slug')
  files=$(echo "$team_entry" | jq -r '.packages[].files[]' | sort -u)

  # No files written: all proposals were skipped — open an issue instead of a PR.
  if [ -z "$files" ]; then
    issue_title="[automation] Package version updates blocked for @elastic/${slug}"

    if $PREVIEW; then
      echo "======================================== ISSUE"
      echo "Team:  @elastic/${slug}"
      echo ""
      echo "Issue title: ${issue_title}"
      echo ""
      echo "Issue body:"
      generate_issue_body "$team_entry" "$slug"
      echo "========================================"
      echo ""
      continue
    fi

    # Update the existing open issue if one exists, otherwise create it.
    existing_issue=$(gh issue list \
      --state open \
      --search "${issue_title} in:title" \
      --json number,title \
      --jq ".[] | select(.title == \"${issue_title}\") | .number" \
      2>/dev/null | head -1)

    if [ -n "$existing_issue" ]; then
      gh issue edit "$existing_issue" --body "$(generate_issue_body "$team_entry" "$slug")"
      echo "Updated existing issue #${existing_issue} for team ${slug}."
    else
      gh issue create \
        --title "$issue_title" \
        --body "$(generate_issue_body "$team_entry" "$slug")"
      echo "Created issue for team ${slug}."
    fi
    continue
  fi

  branch="automated/requires-update-${slug}"

  if $PREVIEW; then
    echo "======================================== PR"
    echo "Team:   @elastic/${slug}"
    echo "Branch: ${branch}"
    echo "Files:"
    echo "$files" | sed 's/^/  /'
    echo ""
    echo "PR title: [automation] Update required package versions for @elastic/${slug}"
    echo ""
    echo "PR body:"
    generate_pr_body "$team_entry"
    echo "========================================"
    echo ""
    continue
  fi

  # Reset HEAD to main without discarding the dirty working tree.
  # "checkout -B" moves HEAD but does not touch untracked/modified files,
  # so all other teams' dirty files survive subsequent iterations.
  git checkout -B "$branch" origin/main

  echo "$files" | xargs git add --
  git commit -m "[automation] Update required package versions"
  git push --force-with-lease origin "$branch"

  # Get or create PR; capture PR number for changelog link fixup.
  pr_url=$(gh pr list --head "$branch" --state open --json url -q '.[0].url' 2>/dev/null)
  if [ -z "$pr_url" ]; then
    pr_url=$(gh pr create \
      --base main \
      --head "$branch" \
      --title "[automation] Update required package versions for @elastic/${slug}" \
      --body "$(generate_pr_body "$team_entry")")
  fi
  pr_number=$(echo "$pr_url" | grep -oE '[0-9]+$')

  # Fixup pull/0 placeholder in this team's changelog files.
  changelog_files=$(echo "$team_entry" | jq -r '.packages[].files[] | select(endswith("changelog.yml"))')
  if [ -n "$changelog_files" ] && [ -n "$pr_number" ]; then
    echo "$changelog_files" | xargs sed -i "s|pull/0|pull/${pr_number}|g"
    echo "$changelog_files" | xargs git add --
    git diff --cached --quiet || {
      git commit -m "Fix changelog PR links"
      git push origin "$branch"
    }
  fi
done < <(jq -c '.[]' "$JSON_FILE")
