#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail

PACKAGES_UNSIGNED_FOLDER=${PACKAGES_UNSIGNED_FOLDER:"packagesUnsigned"}
BUILD_PACKAGES_FOLDER="build/packages"

check_and_build_package() {
    local package=$1
    if ! check_package "${package}" ; then
        return 1
    fi

    if ! build_zip_package "${package}" ; then
        return 1
    fi

    return 0
}

report_build_failure() {
    local package="${1}"
    echo "[${package}] Skipped. Build package failed"

    # if running in Buildkite , add an annotation
    if [ -n "${BUILDKITE_BRANCH+x}" ]; then
        buildkite-agent annotate "Build package ${package} failed, not published." --ctx "ctx-build-${package}" --style "warning"
    fi
}

build_packages() {
    pushd packages > /dev/null

    for it in $(find . -maxdepth 1 -mindepth 1 -type d); do
        local package
        local version
        local name
        package=$(basename "${it}")
        echo "Package ${package}: check"

        pushd "${package}" > /dev/null

        version=$(cat manifest.yml | yq .version)
        name=$(cat manifest.yml | yq .name)

        local package_zip="${name}-${version}.zip"

        if [[ ! "${package_zip}" == "elastic_package_registry-0.1.0.zip" ]]; then
        if is_already_published "${package_zip}" ; then
            echo "Skipping. ${package_zip} already published"
            popd > /dev/null
            continue
        fi
        fi

        echo "Build package as zip: ${package}"
        if check_and_build_package "${package}" ; then
            unpublished="true"
        else
            report_build_failure "${package}"
        fi
        popd > /dev/null
    done
    popd > /dev/null
}

add_bin_path

with_yq
with_go
use_elastic_package

unpublished=false
echo "--- Build packages"
build_packages

if [[ "${unpublished}" == "false" ]]; then
    exit 0
fi

cd "${WORKSPACE}" || exit 1
mkdir -p "${PACKAGES_UNSIGNED_FOLDER}"
cp "${BUILD_PACKAGES_FOLDER}"/*.zip "${PACKAGES_UNSIGNED_FOLDER}"