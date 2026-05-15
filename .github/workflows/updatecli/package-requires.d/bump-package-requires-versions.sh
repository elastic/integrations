#!/bin/sh
set -eu

# Fetch input and content packages from EPR (two targeted calls).
# type= filters reduce the payload from ~457 to ~86 entries combined.
# all=false returns one entry per package (the latest version).
# prerelease=true includes RC/beta releases.
epr_input=$(curl -fsSL "https://epr.elastic.co/search?prerelease=true&all=false&type=input")
epr_content=$(curl -fsSL "https://epr.elastic.co/search?prerelease=true&all=false&type=content")

# Look up the latest EPR version for a given package name.
# Two separate lookups avoid multi-document parsing ambiguity when
# concatenating the two JSON arrays without a YAML --- separator.
epr_latest() {
  result=$(printf '%s' "$epr_input" | yq ".[] | select(.name == \"$1\") | .version" | head -n1)
  if [ -z "$result" ] || [ "$result" = "null" ]; then
    result=$(printf '%s' "$epr_content" | yq ".[] | select(.name == \"$1\") | .version" | head -n1)
  fi
  printf '%s' "$result"
}

# Discover integration package manifests that have a top-level requires: block.
manifests=$(grep -l '^requires:' packages/*/manifest.yml 2>/dev/null || true)

for manifest in $manifests; do
  for kind in input content; do
    count=$(yq ".requires.${kind} | length // 0" "$manifest")
    i=0
    while [ "$i" -lt "$count" ]; do
      pkg=$(yq ".requires.${kind}[$i].package" "$manifest")
      current=$(yq ".requires.${kind}[$i].version" "$manifest")
      latest=$(epr_latest "$pkg")

      if [ -z "$latest" ] || [ "$latest" = "null" ]; then
        echo "WARN: ${pkg} not found on EPR" >&2
      elif [ "$current" != "$latest" ]; then
        echo "Bump ${pkg} in ${manifest}: ${current} -> ${latest}"
        # Use sed instead of yq -i to avoid yq reformatting the whole file
        # (yq normalises block scalars like >- description fields).
        # Match "package: <pkg>" line then replace version on the next line.
        sed -i.bak "/package: ${pkg}[[:space:]]*$/{n; s/version: \"[^\"]*\"/version: \"${latest}\"/;}" "$manifest"
        rm -f "${manifest}.bak"
      fi
      i=$((i + 1))
    done
  done
done

git diff --name-only HEAD
