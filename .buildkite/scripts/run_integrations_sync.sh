#!/bin/bash

source .buildkite/scripts/common.sh

if [ ! -d packages ]; then
    buildkite-agent annotate "Missing packages folder" --style "error"
    exit 1
fi

use_elastic_package() {
    echo "Installing elastic-package"
    mkdir -p build
    go build -o build/elastic-package github.com/elastic/elastic-package
}

prepare_stack() {
    echo "Prepare stack"
}

is_pr_affected() {
    echo "1"
}

is_pr() {
    if [ "${BUILDKITE_PULL_REQUEST}" == "false" ]; then
        return 0
    fi
    return 1
}


add_bin_path

with_mage
with_docker_compose
with_kubernetes

use_elastic_package

cd packages
for it in $(find . -maxdepth 1 -mindepth 1 -type d); do
    integration=$(basename ${it})
    echo "Package ${integration}: check"

    pushd ${integration} 2> /dev/null

    echo "Links file path: ${ELASTIC_PACKAGE_LINKS_FILE_PATH}"
    directory=$(dirname ${ELASTIC_PACKAGE_LINKS_FILE_PATH})
    echo "Folder links file path: $directory"
    ls -l  $directory

    echo "Check integration: ${integration}"
    ../../build/elastic-package check -v

    popd 2> /dev/null
done

