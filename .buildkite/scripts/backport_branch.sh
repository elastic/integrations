#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail

if buildkite-agent meta-data exists BASE_COMMIT; then
  BASE_COMMIT="$(buildkite-agent meta-data get BASE_COMMIT)"
else
  BASE_COMMIT=${BASE_COMMIT:-""}
fi

if buildkite-agent meta-data exists PACKAGE_NAME; then
  PACKAGE_NAME="$(buildkite-agent meta-data get PACKAGE_NAME)"
else
  PACKAGE_NAME=${PACKAGE_NAME:-""}
fi

if buildkite-agent meta-data exists PACKAGE_VERSION; then
  PACKAGE_VERSION="$(buildkite-agent meta-data get PACKAGE_VERSION)"
else
  PACKAGE_VERSION="${PACKAGE_VERSION:-""}"
fi

if buildkite-agent meta-data exists REMOVE_ALL_PACKAGES; then
  REMOVE_ALL_PACKAGES="$(buildkite-agent meta-data get REMOVE_ALL_PACKAGES)"
else
  REMOVE_ALL_PACKAGES="${REMOVE_ALL_PACKAGES:-"false"}"
fi

if [[ -z "$PACKAGE_NAME" ]] || [[ -z "$PACKAGE_VERSION" ]]; then
  buildkite-agent annotate "The variables **PACKAGE_NAME** or **PACKAGE_VERSION** aren't defined, please try again" --style "warning"
  exit 1
fi

FULL_PACKAGE_NAME="${PACKAGE_NAME}-${PACKAGE_VERSION}"
FULL_ZIP_PACKAGE_NAME="${PACKAGE_NAME}-${PACKAGE_VERSION}.zip"
SOURCE_BRANCH="main"
BACKPORT_BRANCH_NAME="backport-${PACKAGE_NAME}-${PACKAGE_VERSION}"
PACKAGES_FOLDER_PATH="packages"

isPackagePublished() {
  local packageZip=$1
  local responseCode=$(curl -s -o /dev/null -w "%{http_code}" "https://package-storage.elastic.co/artifacts/packages/${packageZip}")
  if [[ $responseCode == "200" ]]; then
    return 0
  else
    return 1
  fi
}

isCommitExist() {
  local commit_sha=$1
  local branch=$2
  git checkout $branch
  local searchResult="$(git branch --contains $commit_sha | grep $branch | awk '{print $2}')"
  echp "${searchResult}"
  git checkout $BUILDKITE_BRANCH
  if [ "${searchResult}" == "${branch}" ]; then
    return 0
  else
    return 1
  fi
}

createBackportBranch() {
  if [ git checkout -b $BACKPORT_BRANCH_NAME $BASE_COMMIT ]; then
    echo "The branch $BACKPORT_BRANCH_NAME has created."
  else
    buildkite-agent annotate "The backport branch $backport_branch_name wasn't created." --style "warning"
    exit 1
  fi
}

removeAllPackages() {
  for dir in "$PACKAGES_FOLDER_PATH"/*; do
    if [[ -d "$dir" ]] && [[ "$(basename "$dir")" != "$PACKAGE_NAME" ]]; then
      echo "Removing directory: $dir"
      rm -rf "$dir"
    fi
  done
}

processFifes() {
  local BUILDKITE_FOLDER_PATH=".buildkite"
  local JENKINSFILE_PATH=".ci\Jenkinsfile"
  git checkout $BACKPORT_BRANCH_NAME
  echo "Copying $BUILDKITE_FOLDER_PATH..."
  git checkout $SOURCE_BRANCH -- $BUILDKITE_FOLDER_PATH
  echo "Copying $JENKINSFILE_PATH..."
  git checkout $SOURCE_BRANCH $JENKINSFILE_PATH
  ls -la $BUILDKITE_FOLDER_PATH
  ls -la

  if [ "${REMOVE_ALL_PACKAGES}" == "true" ]; then
    echo "Removing all packages from $PACKAGES_FOLDER_PATH folder"
    removeAllPackages
  fi

  echo "Commiting and pushing..."
  # git add .
  # git commit -m "Add $BUILDKITE_FOLDER_PATH and $JENKINSFILE_PATH to backport branch: $BACKPORT_BRANCH_NAME"
  # git push origin $BACKPORT_BRANCH_NAME
}

echo "Check if the package has published"
if ! isPackagePublished "${FULL_ZIP_PACKAGE_NAME}"; then
  buildkite-agent annotate "The package version: $FULL_PACKAGE_NAME hasn't published yet." --style "warning"
  exit 1
fi

echo "Check if commit exists."
git branch

if [[ ! -z "$BASE_COMMIT" ]] && [[ isCommitExist "$BASE_COMMIT" "$SOURCE_BRANCH" ]]; then
  buildkite-agent annotate "The entered commit hasn't found in the **$SOURCE_BRANCH** branch" --style "warning"
  exit 1
fi

echo "Creating local backport-branch"
createBackportBranch "${PACKAGE_NAME}" "${VERSION}" "${BASE_COMMIT}"

echo "Adding CI files to the branch"
processFifes

buildkite-agent annotate "The backport branch: $BACKPORT_BRANCH_NAME has created. $BUILDKITE_FOLDER_PATH and $JENKINSFILE_PATH have added to the branch." --style "info"
