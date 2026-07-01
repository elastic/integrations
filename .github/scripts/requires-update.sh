#!/usr/bin/env bash
set -euo pipefail

# One PR (or, if every proposal was skipped, one issue) per package — kept
# deliberately simple while adoption of `requires:` is low. Revisit batching
# by codeowner once weekly volume per team justifies the added complexity.
#
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

pkg_count=$(jq 'length' "$JSON_FILE")
if [ "$pkg_count" -eq 0 ]; then
  echo "No changes to commit — exiting."
  exit 0
fi

generate_pr_body() {
  local pkg_entry="$1"
  jq -r '
    (if (.applied | length) > 0 then
      "## Applied\n\n" + ([.applied[] | "- **\(.package)** (`\(.kind)`): `\(.current)` → `\(.proposed)`"] | join("\n"))
    else "" end) +
    (if (.skipped | length) > 0 then
      "\n\n## Skipped\n\n" + ([.skipped[] | "- ⚠️ **\(.package)**: \(.warning)"] | join("\n"))
    else "" end) +
    "\n"
  ' <<< "$pkg_entry"
}

generate_issue_body() {
  local pkg_entry="$1"
  local slug="$2"
  echo "The following dependency updates are available but could not be applied automatically."
  echo ""
  jq -r '[.skipped[] | "- **\(.package)**: \(.warning)"] | join("\n")' <<< "$pkg_entry"
  echo ""
  echo "/cc @elastic/${slug}"
}

while IFS= read -r pkg_entry; do
  pkg_name=$(jq -r '.name' <<< "$pkg_entry")
  codeowner=$(jq -r '.codeowner' <<< "$pkg_entry")
  slug="${codeowner#@elastic/}"
  files=$(jq -r '.files[]' <<< "$pkg_entry")

  # No files written: all proposals were skipped — open an issue instead of a PR.
  if [ -z "$files" ]; then
    issue_title="[automation] Package version updates blocked for \`${pkg_name}\`"

    if $PREVIEW; then
      echo "======================================== ISSUE"
      echo "Package: ${pkg_name}"
      echo "Owner:   @elastic/${slug}"
      echo ""
      echo "Issue title: ${issue_title}"
      echo ""
      echo "Issue body:"
      generate_issue_body "$pkg_entry" "$slug"
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
      gh issue edit "$existing_issue" --body "$(generate_issue_body "$pkg_entry" "$slug")"
      echo "Updated existing issue #${existing_issue} for ${pkg_name}."
    else
      gh issue create \
        --title "$issue_title" \
        --label "automation" \
        --body "$(generate_issue_body "$pkg_entry" "$slug")"
      echo "Created issue for ${pkg_name}."
    fi
    continue
  fi

  branch="automated/requires-update-${pkg_name}"

  if $PREVIEW; then
    echo "======================================== PR"
    echo "Package: ${pkg_name}"
    echo "Owner:   @elastic/${slug}"
    echo "Branch:  ${branch}"
    echo "Files:"
    echo "$files" | sed 's/^/  /'
    echo ""
    echo "PR title: [automation] Update required package versions for \`${pkg_name}\`"
    echo ""
    echo "PR body:"
    generate_pr_body "$pkg_entry"
    echo "========================================"
    echo ""
    continue
  fi

  # Reset HEAD to main without discarding the dirty working tree.
  # "checkout -B" moves HEAD but does not touch untracked/modified files,
  # so other packages' dirty files survive subsequent iterations.
  git checkout -B "$branch" origin/main

  echo "$files" | xargs git add --
  git commit -m "[automation] Update required package versions for ${pkg_name}"
  git push --force-with-lease origin "$branch"

  # Get or create PR; capture PR number for changelog link fixup.
  pr_url=$(gh pr list --head "$branch" --state open --json url -q '.[0].url' 2>/dev/null)
  if [ -z "$pr_url" ]; then
    pr_url=$(gh pr create \
      --base main \
      --head "$branch" \
      --title "[automation] Update required package versions for \`${pkg_name}\`" \
      --label "automation" \
      --reviewer "@elastic/${slug}" \
      --body "$(generate_pr_body "$pkg_entry")")
  else
    gh pr edit "$pr_url" --body "$(generate_pr_body "$pkg_entry")"
  fi
  pr_number="${pr_url##*/}"

  # Fixup pull/REPLACE_ME placeholder in this package's changelog file.
  changelog_files=$(jq -r '.files[] | select(endswith("changelog.yml"))' <<< "$pkg_entry")
  if [ -n "$changelog_files" ] && [ -n "$pr_number" ]; then
    echo "$changelog_files" | xargs sed -i'' "s|pull/REPLACE_ME|pull/${pr_number}|g"
    echo "$changelog_files" | xargs git add --
    git diff --cached --quiet || {
      git commit -m "Fix changelog PR links"
      git push origin "$branch"
    }
  fi
done < <(jq -c '.[]' "$JSON_FILE")
