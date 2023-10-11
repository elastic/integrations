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
    buildkite-agent annotate "Missing packages folder" --style "error"
    exit 1
fi

kibana_version_manifest() {
    local kibana_version=$(cat manifest.yml | yq ".conditions.kibana.version")
    if [ $kibana_version != "null" ]; then
        echo "${kibana_version}"
        return
    fi

    kibana_version=$(cat manifest.yml | yq ".conditions.\"kibana.version\"")
    if [ $kibana_version != "null" ]; then
        echo "${kibana_version}"
        return
    fi

    echo "null"
}

is_unsupported_stack() {
    if [ "${STACK_VERSION}" == "" ]; then
        return 1
    fi

    local kibana_version=$(kibana_version_manifest)
    if [ "${kibana_version}" == "null" ]; then
        return 1
    fi
    if [[ ! ${kibana_version} =~ \^7\. && ${STACK_VERSION} =~ ^7\. ]]; then
        return 0
    fi
    if [[ ! ${kibana_version} =~ \^8\. && ${STACK_VERSION} =~ ^8\. ]]; then
        return 0
    fi
    return 1
}

oldest_supported_version() {
    local kibana_version=$(cat manifest.yml | yq ".conditions.kibana.version")
    if [ $kibana_version != "null" ]; then
        python3 .buildkite/scripts/find_oldest_supported_version --manifest manifest.yml
        return
    fi

    kibana_version=$(cat manifest.yml | yq ".conditions.\"kibana.version\"")
    if [ $kibana_version != "null" ]; then
        python3 .buildkite/scripts/find_oldest_supported_version --manifest manifest.yml
        return
    fi

    echo "null"
}

prepare_serverless_stack() {
    echo "--- Prepare serverless stack"

    local args="-v"
    if [ -n "${STACK_VERSION}" ]; then
        args="${args} --version ${STACK_VERSION}"
    # TODO What stack version to use (for agents) in serverless?
    # else
    fi

    export EC_API_KEY=${EC_API_KEY_SECRET}
    export EC_HOST=${EC_HOST_SECRET}


    echo "Boot up the Elastic stack"
    # ${ELASTIC_PACKAGE_BIN} stack up -d ${args} --provider serverless -U stack.serverless.region=${EC_REGION_SECRET} -U stack.serverless.type=${SERVERLESS_PROJECT}
    ${ELASTIC_PACKAGE_BIN} stack up -d ${args}
    echo ""
}

is_spec_3_0_0() {
    local pkg_spec=$(cat manifest.yml | yq '.format_version')
    local major_version=$(echo $pkg_spec | cut -d '.' -f 1)

    echo "pkg_spec ${pkg_spec}"
    echo "major_version ${major_version}"

    if [ ${major_version} -ge 3 ]; then
        return 0
    fi
    return 1
}

get_from_changeset() {
    if [ "${BUILDKITE_PULL_REQUEST_BASE_BRANCH}" != "false" ]; then
        # pull request
        echo "origin/${BUILDKITE_PULL_REQUEST_BASE_BRANCH}"
        return
    fi
    # main or backport branches
    previous_commit=$(git rev-parse --verify FETCH_HEAD~1)
    echo "${previous_commit}"
}

get_to_changeset() {
    echo "${BUILDKITE_COMMIT}"
}

is_pr_affected() {
    local integration="${1}"

    if is_unsupported_stack ; then
        echo "[${integration}] PR is not affected: unsupported stack (${STACK_VERSION})"
        return 1
    fi

    if [[ ${FORCE_CHECK_ALL} == "true" ]];then
        echo "[${integration}] PR is affected: \"force_check_all\" parameter enabled"
        return 0
    fi

    # setting default values for a PR
    # TODO: get previous built commit as in Jenkins (groovy)
    # def from = env.CHANGE_TARGET?.trim() ? "origin/${env.CHANGE_TARGET}" : "${env.GIT_PREVIOUS_COMMIT?.trim() ? env.GIT_PREVIOUS_COMMIT : env.GIT_BASE_COMMIT}"
    local from="$(get_from_changeset)"
    local to="$(get_to_changeset)"

    # TODO: If running for an integration branch (main, backport-*) check with
    # GIT_PREVIOUS_SUCCESSFUL_COMMIT to check if the branch is still healthy.
    # If this value is not available, check with last commit.
    if [[ ${BUILDKITE_BRANCH} == "main" || ${BUILDKITE_BRANCH} =~ ^backport- ]]; then
        echo "[${integration}] PR is affected: running on ${BUILDKITE_BRANCH} branch"
        # TODO: get previous successful commit as in Jenkins (groovy)
        # from = env.GIT_PREVIOUS_SUCCESSFUL_COMMIT?.trim() ? env.GIT_PREVIOUS_SUCCESSFUL_COMMIT : "origin/${env.BRANCH_NAME}^"
        from="origin/${BUILDKITE_BRANCH}^"
        to="origin/${BUILDKITE_BRANCH}"
    fi

    echo "[${integration}] git-diff: check non-package files"
    if git diff --name-only $(git merge-base ${from} ${to}) ${to} | egrep '^(packages/|.github/CODEOWNERS)' ; then
        echo "[${integration}] PR is affected: found non-package files"
        return 0
    fi
    echo "[${integration}] git-diff: check package files"
    if git diff --name-only $(git merge-base ${from} ${to}) ${to} | egrep '^packages/${integration}/' ; then
        echo "[${integration}] PR is affected: found package files"
        return 0
    fi
    echo "[${integration}] PR is not affected"
    return 1
}

is_pr() {
    if [ "${BUILDKITE_PULL_REQUEST}" == "false" ]; then
        return 0
    fi
    return 1
}

kubernetes_service_deployer_used() {
    echo "Check if Kubernetes service deployer is used"
    find . -type d | egrep '_dev/deploy/k8s$'
}

create_kind_cluster() {
    echo "--- Create kind cluster"
    kind create cluster --config ${WORKSPACE}/kind-config.yaml --image kindest/node:${K8S_VERSION}
}


delete_kind_cluster() {
    echo "--- Delete kind cluster"
    kind delete cluster || true
}

add_bin_path

with_yq
with_mage
with_docker_compose
with_kubernetes

use_elastic_package

prepare_serverless_stack

num_packages=0  # TODO: to be removed
maximum_packages=5

pushd packages > /dev/null
for it in $(find . -maxdepth 1 -mindepth 1 -type d); do
    integration=$(basename ${it})
    echo "--- Package ${integration}: check"

    pushd ${integration} 2> /dev/null

    if [[ ${SERVERLESS} == "true" ]] ; then
        if ! is_spec_3_0_0 ]]; then
            echo "Not v3 spec version. Skipped"
            popd 2> /dev/null
            continue
        fi
    fi

    if ! is_pr_affected ${integration} ; then
        echo "[${integration}] Skipped"
        # popd 2> /dev/null
        # continue # TODO enable this skip after testing
    fi

    if kubernetes_service_deployer_used ; then
        create_kind_cluster
    fi

    echo "Check integration: ${integration}"
    ${ELASTIC_PACKAGE_BIN} check -v

    echo "Test integration: ${integration}"
    #  # eval "$(../../build/elastic-package stack shellinit)"
    ${ELASTIC_PACKAGE_BIN} test -v --report-format xUnit --report-output file --test-coverage

    # TODO: debug to be removed
    num_packages=$((num_packages+1))
    popd 2> /dev/null
    if [ $num_packages -eq ${maximum_packages} ]; then
        break
    fi
done
popd > /dev/null

