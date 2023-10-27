#!/bin/bash

source .buildkite/scripts/common.sh
set -euo pipefail

if [ ${SKIP_PUBLISHING:-"false"} == "true" ] ; then
    echo "packageStoragePublish: skipping because skip_publishing param is ${SKIP_PUBLISHING}"
    exit 0
fi

export BUILD_TAG="buildkite-${BUILDKITE_PIPELINE_SLUG}-${BUILDKITE_BUILD_NUMBER}"
export REPO_BUILD_TAG="${REPO_NAME}/${BUILD_TAG}"

JENKINS_TRIGGER_PATH=".buildkite/scripts/triggerJenkinsJob"

# signing
INFRA_SIGNING_BUCKET_NAME='internal-ci-artifacts'
INFRA_SIGNING_BUCKET_SIGNED_ARTIFACTS_SUBFOLDER="${REPO_BUILD_TAG}/signed-artifacts"
INFRA_SIGNING_BUCKET_ARTIFACTS_PATH="gs://${INFRA_SIGNING_BUCKET_NAME}/${REPO_BUILD_TAG}"
INFRA_SIGNING_BUCKET_SIGNED_ARTIFACTS_PATH="gs://${INFRA_SIGNING_BUCKET_NAME}/${INFRA_SIGNING_BUCKET_SIGNED_ARTIFACTS_SUBFOLDER}"


skipPublishing() {
    if [[ "${BUILDKITE_PULL_REQUEST}" != "false" ]]; then
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

check_and_build_package() {
    ${ELASTIC_PACKAGE_BIN} check
    ${ELASTIC_PACKAGE_BIN} build --zip
}

report_build_failure() {
    local integration="${1}"
    echo "Build package ${integration}failed"

    # if running in Buildkite , add an annotation
    if [ -n "$BUILDKITE_BRANCH" ]; then
        buildkite-agent annotate "Build package ${integration} failed" --style "warning"
    fi
}

build_packages() {
    pushd packages > /dev/null

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
        check_and_build_package || report_build_failure ${integration}
        popd > /dev/null

        unpublished="true"
    done
    popd > /dev/null
}

sign_packages() {
    echo "Signing packages"
    # TODO require signing: to be based on elastic-package
}

publish_packages() {
    echo "Publishing packages"
    # TODO require publishing: to be based on elastic-package
}

if skipPublishing ; then
    echo "packageStoragePublish: not the main branch or a backport branch, nothing will be published"
    exit 0
fi

echo "Checking gsutil command..."
if ! command -v gsutil &> /dev/null ; then
    echo "⚠️  gsutil is not installed"
    exit 1
fi

add_bin_path
with_go
with_yq
use_elastic_package

unpublished="false"

build_packages


if [ "${unpublished}" == "false" ]; then
    echo "All packages are in sync"
    exit 0
fi

sign_packages
publish_packages
