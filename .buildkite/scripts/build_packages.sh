#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail

SKIP_PUBLISHING=${SKIP_PUBLISHING:-"false"}
ARTIFACTS_FOLDER=${ARTIFACTS_FOLDER:-"packageArtifacts"}
BUILD_PACKAGES_FOLDER="build/packages"
DRY_RUN=${DRY_RUN:-"true"}

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
    pushd packages > /dev/null || exit 1

    for it in $(find . -maxdepth 1 -mindepth 1 -type d); do
        local package
        local version
        local name
        package=$(basename "${it}")
        echo "Package ${package}: check"

        pushd "${package}" > /dev/null || exit 1

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
        popd > /dev/null || exit 1
    done
    popd > /dev/null || exit 1
}

if [ "${SKIP_PUBLISHING}" == "true" ] ; then
    echo "packageStoragePublish: skipping because SKIP_PUBLISHING environment variable is ${SKIP_PUBLISHING}"
    exit 0
fi

if skipPublishing ; then
    echo "packageStoragePublish: not the main branch or a backport branch, nothing will be published"
    exit 0
fi

add_bin_path

with_yq
with_go
use_elastic_package

echo "--- Build packages"

if [[ "$BUILDKITE_RETRY_COUNT" != "0" ]]; then
    echo "Please, trigger a new build to avoid issues publishing packages duplicating the artifacts in this build."
    exit 1
fi

unpublished=false
build_packages

if [[ "${unpublished}" == "false" ]]; then
    exit 0
fi

cd "${WORKSPACE}" || exit 1
mkdir -p "${ARTIFACTS_FOLDER}"
cp "${BUILD_PACKAGES_FOLDER}"/*.zip "${ARTIFACTS_FOLDER}"/

if [ "${DRY_RUN}" == "true" ]; then
    echo "DRY_RUN enabled. Publish packages steps skipped."
    exit 0
fi

# triggering dynamically the steps for signing and publishing
# allow us to check whether or not this group of steps needs to be run in one script
# signing and publish steps must run just if there are any packages to be published

PIPELINE_FILE="pipeline-sign-publish.yml"

cat <<EOF > "${PIPELINE_FILE}"
steps:
  - group: ":outbox_tray: Publish packages"
    key: "publish-packages-buildkite"
    steps:
      # If you change 'key: sign-service' then change SIGNING_STEP_KEY value from trigger-publish step pipeline
      - label: ":key: Sign artifacts"
        trigger: unified-release-gpg-signing
        key: sign-service
        depends_on:
          - step: "build-packages"
            allow_failure: false
        build:
          env:
            INPUT_PATH: "buildkite://"

      - label: ":esbuild: Trigger publishing packages if any"
        key: "trigger-publish"
        command: ".buildkite/scripts/trigger_publish_packages.sh"
        env:
          SIGNING_STEP_KEY: "sign-service"
          ARTIFACTS_FOLDER: "packageArtifacts"
          DRY_RUN: "${DRY_RUN}"
        agents:
          image: "${LINUX_AGENT_IMAGE}"
          cpu: "8"
          memory: "8G"
        depends_on:
          - step: "sign-service"
            allow_failure: false
EOF

buildkite-agent pipeline upload "${PIPELINE_FILE}"
