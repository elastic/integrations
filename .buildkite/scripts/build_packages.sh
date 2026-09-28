#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail

SKIP_PUBLISHING=${SKIP_PUBLISHING:-"false"}
# Comma-separated list of package zip filenames to skip (e.g. "foo-1.0.0.zip,bar-2.0.0.zip")
SKIP_PACKAGES=${SKIP_PACKAGES:-""}
ARTIFACTS_FOLDER=${ARTIFACTS_FOLDER:-"packageArtifacts"}
BUILD_PACKAGES_FOLDER="build/packages"
DRY_RUN=${DRY_RUN:-"true"}

is_skipped_package() {
    [[ ",${SKIP_PACKAGES}," == *",${1},"* ]]
}

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

    # feature/* and other non-publishing branches fall through here
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
        buildkite-agent annotate "Build package ${package} failed, not published." --context "ctx-build-${package}" --style "warning"
    fi
}

report_publish_check_failure() {
    local package="${1}"
    echo "[${package}] Skipped. Could not determine if already published after retries"

    if [ -n "${BUILDKITE_BRANCH+x}" ]; then
        buildkite-agent annotate "Could not determine if ${package} is already published (storage unreachable). Package was skipped to avoid duplicate publish." --context "ctx-check-${package}" --style "error" || true
    fi
}

# Check whether a package zip is already published on the package storage.
# Returns 0 (published), 1 (not published / 404), or 2 (transient error after retries).
# retry() is not used because it retries on any non-zero exit, making it impossible
# to distinguish a definitive 404 (exit 1) from a transient failure (exit 2).
# On retry exhaustion the caller skips publishing rather than proceeding, accepting
# the risk of a missed publish to avoid the harder-to-fix risk of a duplicate publish.
is_already_published() {
    local package_zip="$1"
    local url="https://package-storage.elastic.co/artifacts/packages/${package_zip}"
    local retries=3
    local count=0
    local http_code
    local delay

    while true; do
        http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 --head "${url}")
        if [ "${http_code}" == "200" ]; then
            echo "- Already published ${package_zip}"
            return 0
        elif [ "${http_code}" == "404" ]; then
            echo "- Not published ${package_zip}"
            return 1
        fi
        count=$((count + 1))
        if [ "${count}" -ge "${retries}" ]; then
            echoerr "Failed to check if ${package_zip} is published after ${retries} attempts (last HTTP status: ${http_code})"
            return 2
        fi
        delay=$((2 ** count))
        echoerr "Unexpected HTTP status ${http_code} checking ${package_zip}, retrying in ${delay}s... (attempt $((count + 1))/${retries})"
        sleep "${delay}"
    done
}

build_packages() {
    local packages=""
    local version=""
    local name=""
    local package_zip=""
    local package_path=""

    packages=$(list_all_directories)
    for package_path in ${packages}; do
        pushd "${package_path}" > /dev/null || exit 1
        echo "Package \"${package_path}\": check"

        version=$(yq .version manifest.yml)
        name=$(yq .name manifest.yml)

        package_zip="${name}-${version}.zip"

        if is_skipped_package "${package_zip}" ; then
            echo "Skipping. ${package_zip} is in the skip list"
            popd > /dev/null
            continue
        fi

        local published_status=0
        is_already_published "${package_zip}" || published_status=$?
        if [ "${published_status}" -eq 0 ]; then
            echo "Skipping. ${package_zip} already published"
            popd > /dev/null
            continue
        elif [ "${published_status}" -eq 2 ]; then
            report_publish_check_failure "${package_zip}"
            popd > /dev/null
            continue
        fi

        echo "Build package as zip: ${package_path}"
        if check_and_build_package "${package_path}" ; then
            unpublished="true"
        else
            report_build_failure "${package_path}"
        fi
        popd > /dev/null || exit 1
    done
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
with_mage
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
