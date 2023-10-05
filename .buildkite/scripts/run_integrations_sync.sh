#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail

if [ ! -d packages ]; then
    buildkite-agent annotate "Missing packages folder" --style "error"
    exit 1
fi

kibana_version() {
    kibana_version=$(cat manifest.yml | yq ".conditions.kibana.version")
    if [ $kibana_version != "null" ]; then
        echo $kibana_version
        return
    fi

    kibana_version=$(cat manifest.yml | yq ".conditions.\"kibana.version\"")
    if [ $kibana_version != "null" ]; then
        echo $kibana_version
        return
    fi

    echo "null"
}

prepare_stack() {
    echo "Prepare stack"

    local args="-v"
    if [ -n "${STACK_VERSION+x}" ]; then
        args="${args} --version ${STACK_VERSION}"
    else
        kibana_constraint=$(kibana_version)
        if [ "$condition" != "null" ]; then
            # FIXME
            true
        fi
    fi

    echo "Update the Elastic stack"
    ${ELASTIC_PACKAGE_BIN} stack update ${args}
    echo ""

    echo "Boot up the Elastic stack"
    ${ELASTIC_PACKAGE_BIN} stack up -d ${args}
    echo ""
}

is_spec_3_0_0() {
    local pkg_spec=$(cat manifest.yml | yq '.format_version')
    local major_version=$(echo $pkg_spec | cut -d '.' -f 1)

    if [ $major_version -ge 3 ]; then
        return 0
    fi
    return 1
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

with_yq
with_mage
with_docker_compose
with_kubernetes

use_elastic_package

prepare_stack

echo "Checking python command..."
if ! command -v python &> /dev/null ; then
    echo "⚠️  python is not installed"
fi
if ! command -v python3 &> /dev/null ; then
    echo "⚠️  python3 is not installed"
fi

cd packages
for it in $(find . -maxdepth 1 -mindepth 1 -type d); do
    integration=$(basename ${it})
    echo "Package ${integration}: check"

    pushd ${integration} 2> /dev/null

    if [ ! is_spec_3_0_0 ]; then
        echo "Not v3 spec version. Skipped"
        continue
    fi

    echo "Check integration: ${integration}"
    ${ELASTIC_PACKAGE_BIN} check -v

    # echo "Test integration: ${integration}"
    #  # eval "$(../../build/elastic-package stack shellinit)"
    # ${ELASTIC_PACKAGE_BIN} test -v --report-format xUnit --report-output file --test-coverage

    popd 2> /dev/null
    exit 0
done

