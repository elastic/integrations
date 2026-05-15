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

# Returns the semver bump level (major|minor|patch|none) between two version strings.
# Strips leading non-numeric prefix (^, ~, v) before comparing.
semver_level() {
  from=$(printf '%s' "$1" | sed 's/^[^0-9]*//')
  to=$(printf '%s' "$2" | sed 's/^[^0-9]*//')
  from_major=$(printf '%s' "$from" | cut -d. -f1)
  from_minor=$(printf '%s' "$from" | cut -d. -f2)
  from_patch=$(printf '%s' "$from" | cut -d. -f3 | cut -d- -f1)
  to_major=$(printf '%s' "$to" | cut -d. -f1)
  to_minor=$(printf '%s' "$to" | cut -d. -f2)
  to_patch=$(printf '%s' "$to" | cut -d. -f3 | cut -d- -f1)
  if [ "$from_major" != "$to_major" ]; then
    printf 'major'
  elif [ "$from_minor" != "$to_minor" ]; then
    printf 'minor'
  elif [ "$from_patch" != "$to_patch" ]; then
    printf 'patch'
  else
    printf 'none'
  fi
}

# Discover integration package manifests that have a top-level requires: block.
manifests=$(grep -l '^requires:' packages/*/manifest.yml 2>/dev/null || true)

bumps_tmp=$(mktemp)
bumps_first=1

for manifest in $manifests; do
  pkg_name=$(basename "$(dirname "$manifest")")
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
        level=$(semver_level "$current" "$latest")
        if [ "$bumps_first" = "1" ]; then
          bumps_first=0
          printf '[\n  {"pkg":"%s","dep":"%s","kind":"%s","from":"%s","to":"%s","level":"%s"}' \
            "$pkg_name" "$pkg" "$kind" "$current" "$latest" "$level" > "$bumps_tmp"
        else
          printf ',\n  {"pkg":"%s","dep":"%s","kind":"%s","from":"%s","to":"%s","level":"%s"}' \
            "$pkg_name" "$pkg" "$kind" "$current" "$latest" "$level" >> "$bumps_tmp"
        fi
      fi
      i=$((i + 1))
    done
  done
done

output="${BUMPS_OUTPUT:-/tmp/bumps.json}"
if [ -s "$bumps_tmp" ]; then
  printf '\n]\n' >> "$bumps_tmp"
  cp "$bumps_tmp" "$output"
else
  printf '[]\n' > "$output"
fi
rm -f "$bumps_tmp"

git diff --name-only HEAD
