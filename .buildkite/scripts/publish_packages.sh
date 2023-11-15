#!/bin/bash

source .buildkite/scripts/common.sh
set -euo pipefail

SKIP_PUBLISHING=${SKIP_PUBLISHING:-"false"}

DRY_RUN=${DRY_RUN:-"true"}

export BUILD_TAG="buildkite-${BUILDKITE_PIPELINE_SLUG}-${BUILDKITE_BUILD_NUMBER}"
export REPO_BUILD_TAG="${REPO_NAME}/${BUILD_TAG}"

JENKINS_TRIGGER_PATH="${WORKSPACE}/.buildkite/scripts/triggerJenkinsJob"

BUILD_PACKAGES_PATH="${WORKSPACE}/build/packages"

# signing
INFRA_SIGNING_BUCKET_NAME='internal-ci-artifacts'
INFRA_SIGNING_BUCKET_SIGNED_ARTIFACTS_SUBFOLDER="${REPO_BUILD_TAG}/signed-artifacts"
INFRA_SIGNING_BUCKET_ARTIFACTS_PATH="gs://${INFRA_SIGNING_BUCKET_NAME}/${REPO_BUILD_TAG}"
INFRA_SIGNING_BUCKET_SIGNED_ARTIFACTS_PATH="gs://${INFRA_SIGNING_BUCKET_NAME}/${INFRA_SIGNING_BUCKET_SIGNED_ARTIFACTS_SUBFOLDER}"

## Publishing
PACKAGE_STORAGE_INTERNAL_BUCKET_QUEUE_PUBLISHING_PATH="gs://elastic-bekitzur-package-storage-internal/queue-publishing/${REPO_BUILD_TAG}"

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

        if is_already_published "${package_zip}" ; then
            echo "Skipping. ${package_zip} already published"
            popd > /dev/null
            continue
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

sign_packages() {
    pushd "${BUILD_PACKAGES_PATH}" > /dev/null

    google_cloud_signing_auth

    # upload zip package (trailing forward slashes are required)
    echo "Upload zip packages files for signing"
    gsutil cp *.zip "${INFRA_SIGNING_BUCKET_ARTIFACTS_PATH}/"

    echo "Trigger Jenkins job for signing packages"
    pushd "${JENKINS_TRIGGER_PATH}" > /dev/null

    go run main.go \
      --jenkins-job sign \
      --folder "${INFRA_SIGNING_BUCKET_ARTIFACTS_PATH}"

    popd > /dev/null

    echo "Download signatures"
    gsutil cp "${INFRA_SIGNING_BUCKET_SIGNED_ARTIFACTS_PATH}/*.asc" "."

    echo "Rename asc to sig"
    for f in *.asc; do
        mv "$f" "${f%.asc}.sig"
    done

    popd > /dev/null

    google_cloud_logout_active_account
}

publish_packages() {
    pushd "${BUILD_PACKAGES_PATH}" > /dev/null

    google_cloud_upload_auth

    for package_zip in *.zip ; do
        if [ ! -f "${package_zip}.sig" ]; then
            echo "Missing signature file for ${package_zip}"
            continue
        fi

        # upload files (trailing forward slashes are required)
        echo "Upload package .zip file ${package_zip} for publishing"
        gsutil cp "${package_zip}" "${PACKAGE_STORAGE_INTERNAL_BUCKET_QUEUE_PUBLISHING_PATH}/"

        echo "Upload package .sig file ${package_zip}.sig for publishing"
        gsutil cp "${package_zip}.sig" "${PACKAGE_STORAGE_INTERNAL_BUCKET_QUEUE_PUBLISHING_PATH}/"

        echo "Trigger Jenkins job for publishing package ${package_zip}"
        pushd "${JENKINS_TRIGGER_PATH}" > /dev/null

        # TODO: Change dry-run parameter to false
        go run main.go \
            --jenkins-job publish \
            --dry-run=true \
            --legacy-package=false \
            --package="${PACKAGE_STORAGE_INTERNAL_BUCKET_QUEUE_PUBLISHING_PATH}/${package_zip}" \
            --signature="${PACKAGE_STORAGE_INTERNAL_BUCKET_QUEUE_PUBLISHING_PATH}/${package_zip}.sig"

        popd > /dev/null
    done
    popd > /dev/null

    google_cloud_logout_active_account
}

if [ "${SKIP_PUBLISHING}" == "true" ] ; then
    echo "packageStoragePublish: skipping because skip_publishing param is ${SKIP_PUBLISHING}"
    exit 0
fi

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

echo "--- Build packages"
build_packages

if [ "${unpublished}" == "false" ]; then
    echo "All packages are in sync"
    exit 0
fi

pushd "${BUILD_PACKAGES_PATH}" > /dev/null
echo "--- packageStoragePublish: Packages to be published $(ls ./*.zip | wc -l)"
ls ./*.zip
popd > /dev/null

if [ "${DRY_RUN}" == "true" ]; then
    exit 0
fi

echo "--- Sign packages"
sign_packages

echo "--- Publish packages"
publish_packages
