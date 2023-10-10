#!/bin/bash

source .buildkite/scripts/common.sh
set -euo pipefail

if [ ${SKIP_PUBLISHING:-"false"} == "true" ] ; then
    echo "packageStoragePublish: skipping because skip_publishing param is ${SKIP_PUBLISHING}"
    exit 0
fi

skipPublishing() {
    if [[ "${BUILDKITE_PULL_REQUEST}" == "true" ]]; then
        return 0
    fi

    if [[ "${BUILDKITE_BRANCH}" == "main" ]]; then
        return 1
    fi
    if [[ "${BUILDKITE_BRANCH}" =~ ^backport- ]]; then
        return 1
    fi

    return 0
}

if skipPublishing ; the
    echo "packageStoragePublish: not the main branch or a backport branch, nothing will be published"
    exit 0
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

    pushd ${integration} > /dev/null

    version=$(cat manifest.yml | yq .version)
    name=$(cat manifest.yml | yq .name)

    package_zip="${name}-${version}.zip"

    if is_already_published ${package_zip} ; then
        echo "Skipping. ${package_zip} already published"
        popd > /dev/null
        continue
    fi

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
