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


cd packages
for it in $(find . -maxdepth 1 -mindepth 1 -type d); do
    integration=$(basename ${it})
    echo "Package ${integration}"

done

