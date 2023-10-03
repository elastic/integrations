#!/bin/bash

set -euo pipefail

WORKSPACE="$(pwd)"
BIN_FOLDER="${WORKSPACE}/bin"
REPO="integrations"
TMP_FOLDER_TEMPLATE_BASE="tmp.${REPO}"
platform_type="$(uname)"
hw_type="$(uname -m)"

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

check_platform_architeture() {
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

create_bin_folder() {
  mkdir -p ${BIN_FOLDER}
}

add_bin_path() {
  create_bin_folder
  echo "Adding PATH to the environment variables..."
  export PATH="${PATH}:${BIN_FOLDER}"
}

with_go() {
  create_bin_folder
  echo "Setting up the Go environment..."
  check_platform_architeture
  local platform_type_lowercase="${platform_type,,}"
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
    retry 5 curl -SL -o ${BIN_FOLDER}/docker-compose "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-linux-x86_64"
    chmod +x ${BIN_FOLDER}/docker-compose
    docker-compose version
}

with_kubernetes() {
    create_bin_folder
    retry 5 curl -sSLo ${BIN_FOLDER}/kind "https://github.com/kubernetes-sigs/kind/releases/download/${KIND_VERSION}/kind-linux-amd64"
    chmod +x ${BIN_FOLDER}/kind
    kind version
    which kind

    retry 5 curl -sSLo ${BIN_FOLDER}/kubectl "https://storage.googleapis.com/kubernetes-release/release/${K8S_VERSION}/bin/linux/amd64/kubectl"
    chmod +x ${BIN_FOLDER}/kubectl
    kubectl version --client
    which kubectl
}

google_cloud_upload_auth() {
  local secretFileLocation=$(mktemp -d -p "${WORKSPACE}" -t "${TMP_FOLDER_TEMPLATE_BASE}.XXXXXXXXX")/google-cloud-credentials.json
  echo "${PRIVATE_INFRA_GCS_CREDENTIALS_SECRET}" > ${secretFileLocation}
  gcloud auth activate-service-account --key-file ${secretFileLocation} 2> /dev/null
  export GOOGLE_APPLICATION_CREDENTIALS=${secretFileLocation}
}

google_cloud_signing_auth() {
  local secretFileLocation=$(mktemp -d -p "${WORKSPACE}" -t "${TMP_FOLDER_TEMPLATE_BASE}.XXXXXXXXX")/google-cloud-credentials.json
  echo "${SIGNING_PACKAGES_GCS_CREDENTIALS_SECRET}" > ${secretFileLocation}
  gcloud auth activate-service-account --key-file ${secretFileLocation} 2> /dev/null
  export GOOGLE_APPLICATION_CREDENTIALS=${secretFileLocation}
}

google_cloud_logout_active_account() {
  local active_account=$(gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null)
  if [ -n "$active_account" ]; then
    echo "Logging out from GCP for active account"
    gcloud auth revoke $active_account > /dev/null 2>&1
    if [ -n "$GOOGLE_APPLICATION_CREDENTIALS" ]; then
      unset GOOGLE_APPLICATION_CREDENTIALS
    fi
    cleanup
  else
    echo "No active GCP accounts found."
  fi
}
