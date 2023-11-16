#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail

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

mkdir -p packages-to-sign/
cp build/packages/*.zip packages-to-sign