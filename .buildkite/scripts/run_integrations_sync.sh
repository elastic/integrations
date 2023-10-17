#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail

# default values
STACK_VERSION=${STACK_VERSION:-""}
FORCE_CHECK_ALL=${FORCE_CHECK_ALL:-"false"}
SKIP_PUBLISHING=${SKIP_PUBLISHING:-"false"}
SERVERLESS=${SERVERLESS:-"false"}
SERVERLESS_PROJECT=${SERVERLESS_PROJECT:-"observability"}


if [ ! -d packages ]; then
    echo "Missing packages folder"
    buildkite-agent annotate "Missing packages folder" --style "error"
    exit 1
fi

add_bin_path

with_yq
with_mage
with_docker_compose
with_kubernetes

use_elastic_package

prepare_serverless_stack

packages_visited=0
# num_packages=0  # TODO: to be removed
# maximum_packages=25

pushd packages > /dev/null

for integration in $(list_all_directories); do
    echo "--- Package ${integration}: check"

    pushd ${integration} > /dev/null
    packages_visited=$((packages_visited+1))

    if [[ ${SERVERLESS} == "true" ]] ; then
        if ! is_spec_3_0_0 ]]; then
            echo "Not v3 spec version. Skipped"
            popd > /dev/null
            continue
        fi
    fi

    if ! is_pr_affected ${integration} ; then
        echo "[${integration}] Skipped"
        popd > /dev/null
        continue
    fi

    use_kind=0
    if kubernetes_service_deployer_used ; then
        use_kind=1
        create_kind_cluster
    fi

    check_install_and_test_package ${integration} || buildkite-agent annotate "Package ${integration} failed" --style "error"

    # TODO: add benchmarks support (https://github.com/elastic/integrations/blob/befdc5cb752a08aaf5f79b0d9bdb68588ade9f27/.ci/Jenkinsfile#L180)
    # ${ELASTIC_PACKAGE_BIN} benchmark pipeline -v --report-format json --report-output file

    if [ ${use_kind} -eq 1 ]; then
        delete_kind_cluster
    fi

    teardown_serverless_test_package ${integration}

    popd > /dev/null

    # TODO: debug to be removed
    # num_packages=$((num_packages+1))
    # if [ $num_packages -eq ${maximum_packages} ]; then
    #     break
    # fi
done
popd > /dev/null

echo "Total packages examined: ${packages_visited}"
