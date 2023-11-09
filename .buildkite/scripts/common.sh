#!/bin/bash

set -euo pipefail

WORKSPACE="$(pwd)"
BIN_FOLDER="${WORKSPACE}/bin"
platform_type="$(uname)"
hw_type="$(uname -m)"
platform_type_lowercase="${platform_type,,}"

SCRIPTS_BUILDKITE_PATH="${WORKSPACE}/.buildkite/scripts"

GOOGLE_CREDENTIALS_FILENAME="google-cloud-credentials.json"
export ELASTIC_PACKAGE_BIN=${WORKSPACE}/build/elastic-package

API_BUILDKITE_PIPELINES_URL="https://api.buildkite.com/v2/organizations/elastic/pipelines/"


running_on_buildkite() {
    if [[ "${BUILDKITE:-"false"}" == "true" ]]; then
        return 0
    fi
    return 1
}

retry() {
  local retries=$1
  shift
  local count=0
  until "$@"; do
    exit=$?
    wait=$((2 ** count))
    count=$((count + 1))
    if [ $count -lt "$retries" ]; then
      >&2 echo "Retry $count/$retries exited $exit, retrying in $wait seconds..."
      sleep $wait
    else
      >&2 echo "Retry $count/$retries exited $exit, no more retries left."
      return $exit
    fi
  done
  return 0
}

cleanup() {
  echo "Deleting temporary files..."
  rm -rf ${WORKSPACE}/${TMP_FOLDER_TEMPLATE_BASE}.*
  echo "Done."
}

unset_secrets () {
  for var in $(printenv | sed 's;=.*;;' | sort); do
    if [[ "$var" == *_SECRET || "$var" == *_TOKEN ]]; then
        unset "$var"
    fi
  done
}

check_platform_architecture() {
  case "${hw_type}" in
    "x86_64")
      arch_type="amd64"
      ;;
    "aarch64")
      arch_type="arm64"
      ;;
    "arm64")
      arch_type="arm64"
      ;;
    *)
    echo "The current platform/OS type is unsupported yet"
    ;;
  esac
}

# Helpers for Buildkite
repo_name() {
    # Example of URL: git@github.com:acme-inc/my-project.git
    local repoUrl=$1

    orgAndRepo=$(echo $repoUrl | cut -d':' -f 2)
    echo "$(basename ${orgAndRepo} .git)"
}

buildkite_pr_branch_build_id() {
    if [ "${BUILDKITE_PULL_REQUEST}" == "false" ]; then
        # add pipeline slug ad build_id to distinguish between integration and integrations-serverless builds
        # when both are executed using main branch
        echo "${BUILDKITE_BRANCH}-${BUILDKITE_PIPELINE_SLUG}-${BUILDKITE_BUILD_NUMBER}"
        return
    fi
    echo "PR-${BUILDKITE_PULL_REQUEST}-${BUILDKITE_BUILD_NUMBER}"
}


# Helpers to install required tools
create_bin_folder() {
  mkdir -p ${BIN_FOLDER}
}

add_bin_path() {
  create_bin_folder
  echo "Adding PATH to the environment variables..."
  export PATH="${BIN_FOLDER}:${PATH}"  # TODO: set bin folder after PATH
}

with_go() {
  create_bin_folder
  echo "--- Setting up the Go environment..."
  check_platform_architecture
  echo " GVM ${SETUP_GVM_VERSION} (platform ${platform_type_lowercase} arch ${arch_type}"
  retry 5 curl -sL -o ${BIN_FOLDER}/gvm "https://github.com/andrewkroh/gvm/releases/download/${SETUP_GVM_VERSION}/gvm-${platform_type_lowercase}-${arch_type}"
  chmod +x ${BIN_FOLDER}/gvm
  eval "$(gvm $(cat .go-version))"
  go version
  which go
  export PATH="${PATH}:$(go env GOPATH):$(go env GOPATH)/bin"
}

with_mage() {
    create_bin_folder
    with_go

    local install_packages=(
            "github.com/magefile/mage"
            "github.com/elastic/go-licenser"
            "golang.org/x/tools/cmd/goimports"
            "github.com/jstemmer/go-junit-report"
            "gotest.tools/gotestsum"
    )
    for pkg in "${install_packages[@]}"; do
        go install "${pkg}@latest"
    done
    mage --version
}

with_docker_compose() {
    create_bin_folder
    check_platform_architecture

    echo "--- Setting up the Docker-compose environment..."
    retry 5 curl -sSL -o ${BIN_FOLDER}/docker-compose "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-${platform_type_lowercase}-${hw_type}"
    chmod +x ${BIN_FOLDER}/docker-compose
    docker-compose version
}

with_kubernetes() {
    create_bin_folder
    check_platform_architecture

    echo "--- Install kind"
    retry 5 curl -sSLo ${BIN_FOLDER}/kind "https://github.com/kubernetes-sigs/kind/releases/download/${KIND_VERSION}/kind-${platform_type_lowercase}-${arch_type}"
    chmod +x ${BIN_FOLDER}/kind
    kind version
    which kind

    echo "--- Install kubectl"
    retry 5 curl -sSLo ${BIN_FOLDER}/kubectl "https://storage.googleapis.com/kubernetes-release/release/${K8S_VERSION}/bin/${platform_type_lowercase}/${arch_type}/kubectl"
    chmod +x ${BIN_FOLDER}/kubectl
    kubectl version --client
    which kubectl
}

with_yq() {
    check_platform_architecture
    local binary="yq_${platform_type_lowercase}_${arch_type}"

    retry 5 curl -sSL -o ${BIN_FOLDER}/yq.tar.gz "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/${binary}.tar.gz"

    tar -C ${BIN_FOLDER} -xpf ${BIN_FOLDER}/yq.tar.gz ./${binary}

    mv ${BIN_FOLDER}/${binary} ${BIN_FOLDER}/yq
    chmod +x ${BIN_FOLDER}/yq
    yq --version

    rm -rf ${BIN_FOLDER}/yq.tar.gz
}

## Logging and logout from Google Cloud
google_cloud_upload_auth() {
  local secretFileLocation=$(mktemp -d -p "${WORKSPACE}" -t "${TMP_FOLDER_TEMPLATE_BASE}.XXXXXXXXX")/${GOOGLE_CREDENTIALS_FILENAME}
  echo "${PRIVATE_INFRA_GCS_CREDENTIALS_SECRET}" > ${secretFileLocation}
  gcloud auth activate-service-account --key-file ${secretFileLocation} 2> /dev/null
  export GOOGLE_APPLICATION_CREDENTIALS=${secretFileLocation}
}

google_cloud_signing_auth() {
  local secretFileLocation=$(mktemp -d -p "${WORKSPACE}" -t "${TMP_FOLDER_TEMPLATE_BASE}.XXXXXXXXX")/${GOOGLE_CREDENTIALS_FILENAME}
  echo "${SIGNING_PACKAGES_GCS_CREDENTIALS_SECRET}" > ${secretFileLocation}
  gcloud auth activate-service-account --key-file ${secretFileLocation} 2> /dev/null
  export GOOGLE_APPLICATION_CREDENTIALS=${secretFileLocation}
}

google_cloud_auth_safe_logs() {
    local gsUtilLocation=$(mktemp -d -p ${WORKSPACE} -t ${TMP_FOLDER_TEMPLATE})
    local secretFileLocation=${gsUtilLocation}/${GOOGLE_CREDENTIALS_FILENAME}

    echo "${PRIVATE_CI_GCS_CREDENTIALS_SECRET}" > ${secretFileLocation}

    gcloud auth activate-service-account --key-file ${secretFileLocation} 2> /dev/null
    export GOOGLE_APPLICATION_CREDENTIALS=${secretFileLocation}
}

google_cloud_logout_active_account() {
  local active_account=$(gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null)
    if [[ -n "$active_account" && -n "${GOOGLE_APPLICATION_CREDENTIALS+x}" ]]; then
    echo "Logging out from GCP for active account"
    gcloud auth revoke $active_account > /dev/null 2>&1
  else
    echo "No active GCP accounts found."
  fi

  if [ -n "${GOOGLE_APPLICATION_CREDENTIALS+x}" ]; then
    rm -rf ${GOOGLE_APPLICATION_CREDENTIALS}
    unset GOOGLE_APPLICATION_CREDENTIALS
  fi
}

## Helpers for integrations pipelines
check_git_diff() {
    cd ${WORKSPACE}
    echo "git update-index"
    git update-index --refresh
    echo "git diff-index"
    git diff-index --exit-code HEAD --
}

use_elastic_package() {
    echo "--- Installing elastic-package"
    mkdir -p build
    go build -o ${ELASTIC_PACKAGE_BIN} github.com/elastic/elastic-package
}

is_already_published() {
    local packageZip=$1

    if curl -s --head https://package-storage.elastic.co/artifacts/packages/${packageZip} | grep -q "HTTP/2 200" ; then
        echo "- Already published ${packageZip}"
        return 0
    fi
    echo "- Not published ${packageZip}"
    return 1
}

create_kind_cluster() {
    echo "--- Create kind cluster"
    kind create cluster --config ${WORKSPACE}/kind-config.yaml --image kindest/node:${K8S_VERSION}
}


delete_kind_cluster() {
    echo "--- Delete kind cluster"
    kind delete cluster || true
}

kibana_version_manifest() {
    local kibana_version=$(cat manifest.yml | yq ".conditions.kibana.version")
    if [ "${kibana_version}" != "null" ]; then
        echo "${kibana_version}"
        return
    fi

    kibana_version=$(cat manifest.yml | yq ".conditions.\"kibana.version\"")
    if [ "${kibana_version}" != "null" ]; then
        echo "${kibana_version}"
        return
    fi

    echo "null"
}

capabilities_manifest() {
    cat manifest.yml | yq ".conditions.elastic.capabilities"
}

is_supported_capability() {
    if [ "${SERVERLESS_PROJECT}" == "" ]; then
        return 0
    fi

    local capabilities=$(capabilities_manifest)

    # if no capabilities defined, it is available iavailable all projects
    if [[  "${capabilities}" == "null" ]]; then
        return 0
    fi

    if [[ ${SERVERLESS_PROJECT} == "observability" ]]; then
        if echo ${capabilities} |egrep 'apm|observability|uptime' ; then
            return 0
        else
            return 1
        fi
    fi

    if [[ ${SERVERLESS_PROJECT} == "security" ]]; then
        if echo ${capabilities} |egrep 'security' ; then
            return 0
        else
            return 1
        fi
    fi

    return 1
}

is_supported_stack() {
    if [ "${STACK_VERSION}" == "" ]; then
        return 0
    fi

    local kibana_version=$(kibana_version_manifest)
    if [ "${kibana_version}" == "null" ]; then
        return 0
    fi
    if [[ ! ${kibana_version} =~ \^7\. && ${STACK_VERSION} =~ ^7\. ]]; then
        return 1
    fi
    if [[ ! ${kibana_version} =~ \^8\. && ${STACK_VERSION} =~ ^8\. ]]; then
        return 1
    fi
    return 0
}

oldest_supported_version() {
    local kibana_version=$(kibana_version_manifest)
    if [ $kibana_version != "null" ]; then
        python3 ${SCRIPTS_BUILDKITE_PATH}/find_oldest_supported_version.py --manifest manifest.yml
        return
    fi
    echo "null"
}

create_elastic_package_profile() {
    local name="$1"
    ${ELASTIC_PACKAGE_BIN} profiles create "${name}"
    ${ELASTIC_PACKAGE_BIN} profiles use "${name}"
}

prepare_stack() {
    echo "--- Prepare stack"

    local args="-v"
    if [ -n "${STACK_VERSION}" ]; then
        args="${args} --version ${STACK_VERSION}"
    else
        local version=$(oldest_supported_version)
        if [[ "${version}" != "null" ]]; then
            args="${args} --version ${version}"
        fi
    fi

    echo "Boot up the Elastic stack"
    if ! ${ELASTIC_PACKAGE_BIN} stack up -d ${args} ; then
        return 1
    fi
    echo ""
    ${ELASTIC_PACKAGE_BIN} stack status
    echo ""
}

is_serverless() {
    if [[ "${SERVERLESS}" == "true" ]]; then
        return 0
    fi
    return 1
}

prepare_serverless_stack() {
    echo "--- Prepare serverless stack"

    local args="-v"
    if [ -n "${STACK_VERSION}" ]; then
        args="${args} --version ${STACK_VERSION}"
    fi

    # Currently, if STACK_VERSION is not defined, for serverless it will be
    # used as Elastic stack version (for agents) the default version in elastic-package

    # Creating a new profile allow to set a specific name for the serverless project
    local profile_name="integrations-${BUILDKITE_PIPELINE_SLUG}-${BUILDKITE_BUILD_NUMBER}-${SERVERLESS_PROJECT}"
    if [[ "${BUILDKITE_PULL_REQUEST}" != "false" ]]; then
        profile_name="integrations-${BUILDKITE_PULL_REQUEST}-${BUILDKITE_BUILD_NUMBER}-${SERVERLESS_PROJECT}"
    fi
    create_elastic_package_profile ${profile_name}

    export EC_API_KEY=${EC_API_KEY_SECRET}
    export EC_HOST=${EC_HOST_SECRET}

    echo "Boot up the Elastic stack"
    ${ELASTIC_PACKAGE_BIN} stack up \
        -d \
        ${args} \
        --provider serverless \
        -U stack.serverless.region=${EC_REGION_SECRET},stack.serverless.type=${SERVERLESS_PROJECT} 2>&1 | egrep -v "^Password: " # To remove password from the output
    echo ""
    ${ELASTIC_PACKAGE_BIN} stack status
    echo ""
}

is_spec_3_0_0() {
    local pkg_spec=$(cat manifest.yml | yq '.format_version')
    local major_version=$(echo $pkg_spec | cut -d '.' -f 1)

    if [ ${major_version} -ge 3 ]; then
        return 0
    fi
    return 1
}

echoerr() {
    echo "$@" 1>&2
}

get_commit_from_build() {
    local pipeline="$1"
    local branch="$2"
    local state_query_param="$3"

    local api_url="${API_BUILDKITE_PIPELINES_URL}/${pipeline}/builds?branch=${branch}&${state_query_param}&per_page=1"
    local previous_commit=$(curl -sH "Authorization: Bearer ${BUILDKITE_API_TOKEN}" "${api_url}" | jq '.[0] |.commit')
    echoerr ">>> Commit from ${pipeline} - branch ${branch} - status: ${status} -> ${previous_commit}"

    echo ${previous_commit}
}

get_previous_commit() {
    local pipeline="$1"
    local branch="$2"
    # Not using state=finished because it implies also skip and cancelled builds https://buildkite.com/docs/pipelines/notifications#build-states
    local status="state[]=failed&state[]=passed"
    local previous_commit=$(get_commit_from_build "${pipeline}" "${branch}" "${status}")
    echo ${previous_commit}
}

get_previous_successful_commit() {
    local pipeline="$1"
    local branch="$2"
    local status="state=passed"
    local previous_commit=$(get_commit_from_build "${pipeline}" "${branch}" "${status}")
    echo ${previous_commit}
}

get_from_changeset() {
    local from=""
    if [ "${BUILDKITE_PULL_REQUEST}" != "false" ]; then
        echo "origin/${BUILDKITE_PULL_REQUEST_BASE_BRANCH}"
        return
    fi

    local previous_commit=$(get_previous_commit ${BUILDKITE_PIPELINE_SLUG} ${BUILDKITE_BRANCH})

    if [[ "${previous_commit}" != "null" ]] ; then
        from="${previous_commit}"
    else
        from="${BUILDKITE_COMMIT}^"
    fi

    if [[ "${BUILDKITE_BRANCH}" == "main" || ${BUILDKITE_BRANCH} =~ ^backport- ]]; then
        local previous_successful_commit=$(get_previous_successful_commit ${BUILDKITE_PIPELINE_SLUG} ${BUILDKITE_BRANCH})

        from="${previous_successful_commit}"
        if [[ "${previous_successful_commit}" == "null" ]]; then
            from="origin/${BUILDKITE_BRANCH}^"
        fi
    fi

    echo "${from}"
}

get_to_changeset() {
    local to="${BUILDKITE_COMMIT}"

    if [[ "${BUILDKITE_BRANCH}" == "main" || ${BUILDKITE_BRANCH} =~ ^backport- ]]; then
        to="origin/${BUILDKITE_BRANCH}"
    fi
    echo ${to}
}

is_pr_affected() {
    local package="${1}"

    if ! is_supported_stack ; then
        echo "[${package}] PR is not affected: unsupported stack (${STACK_VERSION})"
        return 1
    fi

    if is_serverless; then
        if ! is_supported_capability ; then
            echo "[${package}] PR is not affected: capabilities not mached with the project (${SERVERLESS_PROJECT})"
            return 1
        fi
    fi

    if [[ "${FORCE_CHECK_ALL}" == "true" ]];then
        echo "[${package}] PR is affected: \"force_check_all\" parameter enabled"
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
        echo "[${package}] PR is affected: running on ${BUILDKITE_BRANCH} branch"
        # TODO: get previous successful commit as in Jenkins (groovy)
        # from = env.GIT_PREVIOUS_SUCCESSFUL_COMMIT?.trim() ? env.GIT_PREVIOUS_SUCCESSFUL_COMMIT : "origin/${env.BRANCH_NAME}^"
        from="origin/${BUILDKITE_BRANCH}^"
        to="origin/${BUILDKITE_BRANCH}"
    fi

    echo "[${package}] git-diff: check non-package files"
    if git diff --name-only $(git merge-base ${from} ${to}) ${to} | egrep -v '^(packages/|.github/CODEOWNERS)' ; then
        echo "[${package}] PR is affected: found non-package files"
        return 0
    fi
    echo "[${package}] git-diff: check package files"
    if git diff --name-only $(git merge-base ${from} ${to}) ${to} | egrep "^packages/${package}/" ; then
        echo "[${package}] PR is affected: found package files"
        return 0
    fi
    echo "[${package}] PR is not affected"
    return 1
}

is_pr() {
    if [[ "${BUILDKITE_PULL_REQUEST}" == "false" || "${BUILDKITE_TAG}" == "" ]]; then
        return 0
    fi
    return 1
}

kubernetes_service_deployer_used() {
    find . -type d | egrep '_dev/deploy/k8s$'
}

teardown_serverless_test_package() {
    local package=$1
    local build_directory="${WORKSPACE}/build"
    local dump_directory="${build_directory}/elastic-stack-dump/${package}"

    echo "Collect Elastic stack logs"
    ${ELASTIC_PACKAGE_BIN} stack dump -v --output ${dump_directory}

    upload_safe_logs_from_package ${package} ${build_directory}
}

teardown_test_package() {
    local package=$1
    local build_directory="${WORKSPACE}/build"
    local dump_directory="${build_directory}/elastic-stack-dump/${package}"

    echo "Collect Elastic stack logs"
    ${ELASTIC_PACKAGE_BIN} stack dump -v --output ${dump_directory}

    upload_safe_logs_from_package ${package} ${build_directory}

    echo "Take down the Elastic stack"
    ${ELASTIC_PACKAGE_BIN} stack down -v
}

list_all_directories() {
    find . -maxdepth 1 -mindepth 1 -type d | xargs -I {} basename {} | sort
}

check_package() {
    local package=$1
    echo "Check package: ${package}"
    if ! ${ELASTIC_PACKAGE_BIN} check -v ; then
        return 1
    fi
    echo ""
    return 0
}

install_package() {
    local package=$1
    echo "Install package: ${package}"
    if ! ${ELASTIC_PACKAGE_BIN} install -v ; then
        return 1
    fi
    echo ""
    return 0
}

test_package_in_local_stack() {
    local package=$1
    TEST_OPTIONS="-v --report-format xUnit --report-output file --test-coverage"

    echo "Test package: ${package}"
    # Run all test suites
    ${ELASTIC_PACKAGE_BIN} test ${TEST_OPTIONS}
    local ret=$?
    echo ""
    return $ret
}

# Currently, system tests are not run in serverless to avoid lasting the build
# too much time, since all packages are run in the same step one by one.
# Packages are tested one by one to avoid creating more than 100 projects for one build.
test_package_in_serverless() {
    local package=$1
    TEST_OPTIONS="-v --report-format xUnit --report-output file"

    echo "Test package: ${package}"
    if ! ${ELASTIC_PACKAGE_BIN} test asset ${TEST_OPTIONS} --test-coverage ; then
        return 1
    fi
    if ! ${ELASTIC_PACKAGE_BIN} test static ${TEST_OPTIONS} --test-coverage ; then
        return 1
    fi
    # FIXME: adding test-coverage for serverless results in errors like this:
    # Error: error running package pipeline tests: could not complete test run: error calculating pipeline coverage: error fetching pipeline stats for code coverage calculations: need exactly one ES node in stats response (got 4)
    if ! ${ELASTIC_PACKAGE_BIN} test pipeline ${TEST_OPTIONS} ; then
        return 1
    fi
    echo ""
    return 0
}

run_tests_package() {
    local package=$1
    echo "--- [${package}] format and lint"
    if ! check_package ${package} ; then
        return 1
    fi

    # For non serverless, each Elastic stack is boot up checking each package manifest
    if ! is_serverless ; then
        prepare_stack
    fi

    echo "--- [${package}] test installation"
    if ! install_package ${package} ; then
        return 1
    fi
    echo "--- [${package}] run test suites"
    if is_serverless; then
        if ! test_package_in_serverless ${package} ; then
            return 1
        fi
    else
        if ! test_package_in_local_stack ${package} ; then
            return 1
        fi
    fi

    return 0
}

create_collapsed_annotation() {
    local title="$1"
    local file="$2"
    local style="$3"
    local context="$4"

    local annotation_file="tmp.annotation.md"
    echo "<details><summary>${title}</summary>" >> ${annotation_file}
    echo -e "\n\n" >> ${annotation_file}
    cat ${file} >> ${annotation_file}
    echo "</details>" >> ${annotation_file}

    cat ${annotation_file} | buildkite-agent annotate --style "${style}" --context "${context}"

    rm -f ${annotation_file}
}

upload_safe_logs() {
    local bucket="$1"
    local source="$2"
    local target="$3"

    if ! ls ${source} 2>&1 > /dev/null ; then
        echo "upload_safe_logs: artifacts files not found, nothing will be archived"
        return
    fi

    google_cloud_auth_safe_logs

    gsutil cp ${source} "gs://${bucket}/buildkite/${REPO_BUILD_TAG}/${target}"

    google_cloud_logout_active_account
}

clean_safe_logs() {
    rm -rf ${WORKSPACE}/build/elastic-stack-dump
    rm -rf ${WORKSPACE}/build/container-logs
}

upload_safe_logs_from_package() {
    if [[ "${UPLOAD_SAFE_LOGS}" -eq 0 ]] ; then
        return
    fi

    local package=$1
    local build_directory=$2

    local parent_folder="insecure-logs"

    upload_safe_logs \
        "${JOB_GCS_BUCKET_INTERNAL}" \
        "${build_directory}/elastic-stack-dump/${package}/logs/elastic-agent-internal/*.*" \
        "${parent_folder}/${package}/elastic-agent-logs/"

    # required for <8.6.0
    upload_safe_logs \
        "${JOB_GCS_BUCKET_INTERNAL}" \
        "${build_directory}/elastic-stack-dump/${package}/logs/elastic-agent-internal/default/*" \
        "${parent_folder}/${package}/elastic-agent-logs/default/"

    upload_safe_logs \
        "${JOB_GCS_BUCKET_INTERNAL}" \
        "${build_directory}/container-logs/*.log" \
        "${parent_folder}/${package}/container-logs/"
}

# Helper to run all tests and checks for a package
process_package() {
    local package="$1"
    local exit_code=0

    echo "--- Package ${package}: check"
    pushd ${package} > /dev/null

    clean_safe_logs

    if is_serverless ; then
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

    echo "${reason}"

    use_kind=0
    if kubernetes_service_deployer_used ; then
        echo "Kubernetes service deployer is used. Creating Kind cluster"
        use_kind=1
        if ! create_kind_cluster ; then
            popd > /dev/null
            return 1
        fi
    fi

    if ! run_tests_package ${package} ; then
        exit_code=1
        echo "[${package}] run_tests_package failed"
        echo "- ${package}" >> ${FAILED_PACKAGES_FILE_PATH}
    fi

    if ! is_serverless ; then
        if [[ $exit_code -eq 0 ]]; then
            # TODO: add benchmarks support stash and comments in PR
            # https://github.com/elastic/integrations/blob/befdc5cb752a08aaf5f79b0d9bdb68588ade9f27/.ci/Jenkinsfile#L180
            ${ELASTIC_PACKAGE_BIN} benchmark pipeline -v --report-format json --report-output file
        fi
    fi

    if [ ${use_kind} -eq 1 ]; then
        delete_kind_cluster
    fi

    if is_serverless ; then
        teardown_serverless_test_package ${package}
    else
        if ! teardown_test_package ${package} ; then
            exit_code=1
            echo "[${package}] teardown_test_package failed"
        fi
    fi

    popd > /dev/null
    return $exit_code
}

## TODO: Benchmark helpers
add_github_comment_benchmark() {
    if ! is_pr ; then
        return
    fi

    local benchmark_github_file="report.md"
    local benchmark_results="benchmark-results"
    local current_benchmark_results="build/${benchmark_results}"
    local baseline="build/${BUILDKITE_PULL_REQUEST_BASE_BRANCH}/${benchmark_results}"
    local is_full_report="false"

    if [[ "${GITHUB_PR_TRIGGER_COMMENT}" =~ benchmark\ fullreport ]]; then
        is_full_report="true"
    fi

    pushd ${WORKSPACE} > /dev/null

    mkdir -p ${current_benchmark_results}
    mkdir -p ${baseline}

    # download PR benchmarks
    local bucket_uri=$(get_benchmark_bucket_uri)
    download_benchmark_results \
        ${JOB_GCS_BUCKET} \
        $(get_benchmark_path_prefix) \
        ${current_benchmark_results}

    # download main benchmark if any
    download_benchmark_results \
        ${JOB_GCS_BUCKET} \
        $(get_benchmark_path_prefix) \
        baseline

    echo "Debug: current benchmark"
    ls -l ${current_benchmark_results}

    echo "Debug: baseline benchmark"
    ls -l ${baseline}

    echo "Run benchmark report"
    ${ELASTIC_PACKAGE_BIN} report benchmark \
        --fail-on-missing=false \
        --new="${current_benchmark_results}" \
        --old="${baseline}" \
        --threshold=${BENCHMARK_THRESHOLD} \
        --report-output-path="${benchmark_github_file}" \
        --full=${is_full_report}


    if [ ! -f ${benchmark_github_file} ]; then
        echo "add_github_comment_benchmark: it was not possible to send the message"
        return
    fi
    # TODO: write github comment in PR
    popd > /dev/null
}

stash_benchmark_results() {
    local wildcard="build/benchmark-results/*.json"
    if ! ls ${wildcard} ; then
        echo "isBenchmarkResultsPresent: benchmark files not found, report won't be stashed"
        return 0
    fi

    upload_benchmark_results \
        ${JOB_GCS_BUCKET} \
        ${wildcard} \
        $(get_benchmark_path_prefix)
}

get_benchmark_bucket_uri() {
    echo "gs://${JOB_GCS_BUCKET}/$(get_benchmark_path_prefix)"
}

get_benchmark_path_prefix() {
    echo "${BUILDKITE_PIPELINE_SLUG}/${buildkite_pr_branch_build_id}/benchmark-results/"
}

upload_benchmark_results() {
    local bucket="$1"
    local source="$2"
    local target="$3"

    if ! ls ${source} 2>&1 > /dev/null ; then
        echo "upload_benchmark_results: artifacts files not found, nothing will be archived"
        return
    fi

    google_cloud_auth_safe_logs

    gsutil cp ${source} "gs://${bucket}/buildkite/${REPO_BUILD_TAG}/${target}"

    google_cloud_logout_active_account
}

download_benchmark_results() {
    local bucket="$1"
    local source="$2"
    local target="$3"

    google_cloud_auth_safe_logs

    gsutil cp "gs://${bucket}/buildkite/${REPO_BUILD_TAG}/${source}" ${target}

    google_cloud_logout_active_account
}
