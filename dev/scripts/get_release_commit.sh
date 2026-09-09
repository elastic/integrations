#!/usr/bin/env bash
# Finds the commit on main where a package version was released.
# Usage: ./get_release_commit.sh <package_name> <version>

set -euo pipefail

usage() {
    echo "Usage: $0 -p <package_name> -v <version>" >&2
    exit 1
}

PACKAGE_NAME=""
VERSION=""

while getopts ":p:v:h" opt; do
    case "${opt}" in
        p) PACKAGE_NAME="${OPTARG}" ;;
        v) VERSION="${OPTARG}" ;;
        h)
            usage
            exit 0
            ;;
        \?)
            echo "Invalid option ${OPTARG}"
            usage
            exit 1
            ;;
        :)
            echo "Missing argument for -${OPTARG}"
            usage
            exit 1
            ;;
    esac
done

if [[ -z "${PACKAGE_NAME}" || -z "${VERSION}" ]]; then
    usage
fi

# Find the manifest.yml that declares the given package name.
# Packages live at packages/<p>/ or packages/<folder>/<p>/ (one level of nesting).
MANIFEST=""
while IFS= read -r candidate; do
    # name field must match exactly (allow optional quotes and trailing whitespace)
    if grep -E "^name: ['\"]?${PACKAGE_NAME}['\"]?[[:space:]]*$" "$candidate" > /dev/null; then
        MANIFEST="$candidate"
        break
    fi
done < <(find packages -mindepth 2 -maxdepth 3 -name "manifest.yml")

if [[ -z "$MANIFEST" ]]; then
    echo "Error: package '${PACKAGE_NAME}' not found." >&2
    exit 1
fi

# Use -G with an anchored regex so that versions like "9.3.8" are not confused
# with "9.3.8-beta.2" (which -S would treat as the same string occurrence count).
ESCAPED_VERSION="${VERSION//./\\.}"
# mapfile requires bash 4+; macOS ships bash 3.2, so use a while-read loop instead.
COMMITS=()
while IFS= read -r line; do
    [[ -n "$line" ]] && COMMITS+=("$line")
done < <(
    git log --oneline \
        -G "^version: ['\"]?${ESCAPED_VERSION}['\"]?[[:space:]]*$" \
        -- "$MANIFEST" \
        | awk 'NF {print $1}' | sort -u
)

# Among matching commits, keep only those that *added* (not removed) the version.
FOUND=""
for COMMIT in "${COMMITS[@]}"; do
    if git show "$COMMIT" -- "$MANIFEST" \
            | grep -E "^\+version: ['\"]?${VERSION}['\"]?[[:space:]]*$" > /dev/null; then
        FOUND="$COMMIT"
        break
    fi
done

if [[ -z "$FOUND" ]]; then
    echo "Error: no commit found that released version '${VERSION}' of package '${PACKAGE_NAME}'." >&2
    exit 1
fi

echo "$FOUND"
