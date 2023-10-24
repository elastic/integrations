#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail

# default values
SERVERLESS=${SERVERLESS:-"false"}
STACK_VERSION=${STACK_VERSION:-""}
FORCE_CHECK_ALL=${FORCE_CHECK_ALL:-"false"}
SKIP_PUBLISHING=${SKIP_PUBLISHING:-"false"}

SKIPPED_PACKAGES_FILE_PATH="${WORKSPACE}/skipped_packages.txt"
FAILED_PACKAGES_FILE_PATH="${WORKSPACE}/failed_packages.txt"

if running_on_buildkite; then
    # just get the value from meta-data if it is running on Buildkite
    if buildkite-agent meta-data exists SERVERLESS_PROJECT; then
        SERVERLESS_PROJECT="$(buildkite-agent meta-data get SERVERLESS_PROJECT)"
    fi
fi

SERVERLESS_PROJECT=${SERVERLESS_PROJECT:-"observability"}
echo "Running packages on Serverles project type: ${SERVERLESS_PROJECT}"
if running_on_buildkite; then
    buildkite-agent annotate "Serverless Project: ${SERVERLESS_PROJECT}" --context "ctx-info-${SERVERLESS_PROJECT}" --style "info"
fi


if [ ! -d packages ]; then
    echo "Missing packages folder"
    if running_on_buildkite ; then
        buildkite-agent annotate "Missing packages folder" --style "error"
    fi
    exit 1
fi

add_bin_path

with_yq
with_mage
with_docker_compose
with_kubernetes

check_package_in_serverless() {
    local package="$1"

    echo "--- Package ${package}: check"
    pushd ${package} > /dev/null

    clean_safe_logs

    if [[ ${SERVERLESS} == "true" ]] ; then
        if [[ "${package}" == "fleet_server" ]]; then
            echo "fleet_server not supported. Skipped"
            echo "- [${package}] not supported" >> ${SKIPPED_PACKAGES_FILE_PATH}
            popd > /dev/null
            return
        fi
        if ! is_spec_3_0_0 ; then
            echo "Not v3 spec version. Skipped"
            echo "- [${package}] spec <3.0.0" >> ${SKIPPED_PACKAGES_FILE_PATH}
            popd > /dev/null
            return
        fi
    fi

    if ! reason=$(is_pr_affected ${package}) ; then
        echo "${reason}"
        echo "- ${reason}" >> ${SKIPPED_PACKAGES_FILE_PATH}
        popd > /dev/null
        return
    fi

    use_kind=0
    if kubernetes_service_deployer_used ; then
        echo "Kubernetes service deployer is used. Creating Kind cluster"
        use_kind=1
        create_kind_cluster
    fi

    if ! run_tests_package ${package} ; then
        echo "[${package}] run_tests_package failed"
        echo "- ${package}" >> ${FAILED_PACKAGES_FILE_PATH}
        any_package_failing=1
    fi

    # TODO: add benchmarks support (https://github.com/elastic/integrations/blob/befdc5cb752a08aaf5f79b0d9bdb68588ade9f27/.ci/Jenkinsfile#L180)
    # ${ELASTIC_PACKAGE_BIN} benchmark pipeline -v --report-format json --report-output file

    if [ ${use_kind} -eq 1 ]; then
        delete_kind_cluster
    fi

    teardown_serverless_test_package ${package}

    popd > /dev/null
}

use_elastic_package

prepare_serverless_stack

any_package_failing=0

pushd packages > /dev/null
for package in $(list_all_directories); do
    check_package_in_serverless ${package}
done
popd > /dev/null

if running_on_buildkite ; then
    if [ -f ${SKIPPED_PACKAGES_FILE_PATH} ]; then
        create_collapsed_annotation "Skipped packages in ${SERVERLESS_PROJECT}" ${SKIPPED_PACKAGES_FILE_PATH} "info" "ctx-skipped-packages-${SERVERLESS_PROJECT}"
    fi

    if [ -f ${FAILED_PACKAGES_FILE_PATH} ]; then
        create_collapsed_annotation "Failed packages in ${SERVERLESS_PROJECT}" ${FAILED_PACKAGES_FILE_PATH} "error" "ctx-failed-packages-${SERVERLESS_PROJECT}"
    fi
fi

if [ $any_package_failing -eq 1 ] ; then
    echo "These packages have failed:"
    cat ${FAILED_PACKAGES_FILE_PATH}
    exit 1
fi
