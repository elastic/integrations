#!/bin/bash

source .buildkite/scripts/common.sh
set -euo pipefail

if [ ${SKIP_PUBLISHING:-"false"} == "true" ] ; then
    echo "packageStoragePublish: skipping because skip_publishing param is ${SKIP_PUBLISHING}"
    exit 0
fi

if [ "${BUILDKITE_PULL_REQUEST}" == "false" ]; then
    if [[ "${BUILDKITE_BRANCH}" == "main" || "${BUILDKITE_BRANCH}" =~ ^backport- ]]; then
        echo "packageStoragePublish: not the main branch or a backport branch, nothing will be published"
        exit 0
    fi
fi

add_bin_path
with_go
with_yq
use_elastic_package

unpublished="false"

cd packages
for it in $(find . -maxdepth 1 -mindepth 1 -type d); do
    integration=$(basename ${it})
    echo "Package ${integration}: check"

    version=$(cat manifest.yml | yq .version)
    name=$(cat manifest.yml | yq .name)

    package_zip="${name}-${version}.zip"

    if is_already_published ${packageZip} ; then
        echo "Skipping. ${packageZip} already published"
        continue
    fi

    pushd ${integration} > /dev/null
    echo "Build integration as zip: ${integration}"
    ${ELASTIC_PACKAGE_BIN} check
    ${ELASTIC_PACKAGE_BIN} build --zip
    popd > /dev/null

    unpublished="true"
done

if [ "${unpublished}" == "false" ]; then
    echo "All packages are in sync"
    exit 0
fi


# TODO require signing: to be based on elastic-package
# TODO require publishing: to be based on elastic-package
