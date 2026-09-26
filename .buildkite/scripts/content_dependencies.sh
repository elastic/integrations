#!/usr/bin/env bash
# Helpers for content packages required by the package under test.
# Source this file; do not execute it directly.

# find_local_package_dir prints the checkout path of the package whose
# manifest name is $1. Searches packages/<name> and packages/<technology>/<name>.
# Returns 1 when the package is not in this checkout.
find_local_package_dir() {
    local want="$1"
    local manifest name

    if [[ ! -d "${WORKSPACE}/packages" ]]; then
        return 1
    fi

    while IFS= read -r manifest; do
        name="$(yq -r '.name' "${manifest}")"
        if [[ "${name}" == "${want}" ]]; then
            dirname "${manifest}"
            return 0
        fi
    done < <(find "${WORKSPACE}/packages" -mindepth 2 -maxdepth 3 -name manifest.yml -print)

    return 1
}

# build_local_content_dependencies builds requires.content packages that live
# in this checkout at the pinned version.
#
# elastic-package stack up serves build/packages from the local package
# registry and proxies everything else to production EPR. Fleet install of the
# package under test resolves requires.content from that registry. A same-PR
# pin to a content version that is not published yet fails with
# "No compatible version found" unless that content package was built first.
#
# Must be called with the package under test as the working directory, after
# that package has been built (so repo-root build/ exists) and before stack up.
# No-op when requires.content is absent, the dependency is not in this
# checkout, or the local version is not the pinned version.
build_local_content_dependencies() {
    if [[ ! -f manifest.yml ]]; then
        return 0
    fi

    local deps
    deps="$(yq -r '.requires.content[] | [.package, .version] | @tsv' manifest.yml 2>/dev/null || true)"
    if [[ -z "${deps}" ]]; then
        return 0
    fi

    local name version pkg_dir local_version pkg_dir_resolved cwd_resolved
    while IFS=$'\t' read -r name version; do
        if [[ -z "${name}" || "${name}" == "null" || -z "${version}" || "${version}" == "null" ]]; then
            continue
        fi

        pkg_dir="$(find_local_package_dir "${name}" || true)"
        if [[ -z "${pkg_dir}" ]]; then
            echo "Content dependency ${name} ${version} is not in this checkout; the package registry will resolve it"
            continue
        fi

        local_version="$(yq -r '.version' "${pkg_dir}/manifest.yml")"
        if [[ "${local_version}" != "${version}" ]]; then
            echo "Content dependency ${name} requires ${version}; local package is ${local_version}. Leaving resolution to the package registry."
            continue
        fi

        pkg_dir_resolved="$(cd "${pkg_dir}" && pwd)"
        cwd_resolved="$(pwd)"
        if [[ "${pkg_dir_resolved}" == "${cwd_resolved}" ]]; then
            continue
        fi

        echo "--- Build local content dependency ${name} (${version})"
        if ! (cd "${pkg_dir}" && "${ELASTIC_PACKAGE_BIN}" build); then
            echo "Failed to build required content package ${name} ${version}"
            return 1
        fi
    done <<< "${deps}"
}
