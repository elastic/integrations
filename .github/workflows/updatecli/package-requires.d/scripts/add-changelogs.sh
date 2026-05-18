#!/bin/bash
set -euo pipefail

BUMPS_JSON="${BUMPS_JSON:-/tmp/bumps.json}"

if [ ! -s "$BUMPS_JSON" ]; then
  echo "No bumps recorded; skipping changelog step."
  exit 0
fi

if [ -z "${PR_URL:-}" ]; then
  BRANCH="updatecli_main_bump-package-requires-versions"
  PR_URL=$(gh pr list --head "$BRANCH" --state open --json url --jq '.[0].url' 2>/dev/null || true)
  if [ -z "$PR_URL" ]; then
    echo "No open PR found for branch $BRANCH; skipping changelog step."
    exit 0
  fi
fi

# Returns "0" if the bumps array is empty.
entry_count=$(jq 'length' "$BUMPS_JSON")
if [ "$entry_count" -eq 0 ]; then
  echo "Bumps JSON is empty; skipping changelog step."
  exit 0
fi

pkg_names=$(jq -r '.[].pkg' "$BUMPS_JSON" | sort -u)

for pkg_name in $pkg_names; do
  manifest="packages/$pkg_name/manifest.yml"
  if [ ! -f "$manifest" ]; then
    echo "WARN: $manifest not found, skipping $pkg_name"
    continue
  fi

  pkg_version=$(yq '.version' "$manifest")

  # Compute max bump level across all deps for this package.
  has_major=$(jq "[.[] | select(.pkg == \"$pkg_name\" and .level == \"major\")] | length" "$BUMPS_JSON")
  has_minor=$(jq "[.[] | select(.pkg == \"$pkg_name\" and .level == \"minor\")] | length" "$BUMPS_JSON")

  if [ "$has_major" -gt 0 ]; then
    max_level="major"
  elif [ "$has_minor" -gt 0 ]; then
    max_level="minor"
  else
    max_level="patch"
  fi

  # Cap at minor for packages still at 0.1.0: a dep major bump should not
  # produce a 1.0.0 entry before the package has had its first release.
  if [ "$pkg_version" = "0.1.0" ] && [ "$max_level" = "major" ]; then
    max_level="minor"
  fi

  echo "Processing $pkg_name (max bump level: $max_level)"

  # Process each bumped dep for this package.
  first=1
  while IFS='|' read -r dep to; do
    desc="Update required version of ${dep} to ${to}"
    if [ "$first" = "1" ]; then
      first=0
      elastic-package changelog add \
        -C "packages/$pkg_name" \
        --next "$max_level" \
        --type enhancement \
        --description "$desc" \
        --link "$PR_URL"
    else
      # Append an additional change entry to the version elastic-package just created.
      export ENTRY_DESC="$desc"
      export ENTRY_LINK="$PR_URL"
      yq -i '.[0].changes += [{"description": env(ENTRY_DESC), "type": "enhancement", "link": env(ENTRY_LINK)}]' \
        "packages/$pkg_name/changelog.yml"
    fi
  done < <(jq -r ".[] | select(.pkg == \"$pkg_name\") | \"\(.dep)|\(.to)\"" "$BUMPS_JSON")
done

git diff --name-only HEAD
