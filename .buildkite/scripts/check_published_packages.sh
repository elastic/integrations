#!/bin/bash

set -euo pipefail

WORKSPACE="$(pwd)"
EPR_BASE_URL="https://epr.elastic.co/epr"

published_count=0
not_published_count=0
total_count=0

is_published_in_epr() {
    local name="$1"
    local version="$2"
    local http_code

    http_code=$(curl -s -o /dev/null -w "%{http_code}" "${EPR_BASE_URL}/${name}/${name}-${version}.zip")
    [[ "${http_code}" == "200" ]]
}

check_packages() {
    local packages
    packages=$(mage -d "${WORKSPACE}" listPackages)

    while IFS= read -r package_path; do
        [[ -z "${package_path}" ]] && continue

        local manifest="${package_path}/manifest.yml"
        if [[ ! -f "${manifest}" ]]; then
            echo "[SKIP] ${package_path}: manifest.yml not found"
            continue
        fi

        local name version package_zip
        name=$(yq -r '.name' "${manifest}")
        version=$(yq -r '.version' "${manifest}")
        package_zip="${name}-${version}.zip"

        total_count=$((total_count + 1))

        if is_published_in_epr "${name}" "${version}"; then
            echo "[PUBLISHED]     ${package_zip}"
            published_count=$((published_count + 1))
        else
            echo "[NOT PUBLISHED] ${package_zip}"
            not_published_count=$((not_published_count + 1))
        fi
    done <<< "${packages}"
}

check_packages

echo ""
echo "Summary: ${published_count} published, ${not_published_count} not published (${total_count} total)"
