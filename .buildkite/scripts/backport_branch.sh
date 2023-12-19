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

if buildkite-agent meta-data exists REMOVE_OTHER_PACKAGES; then
  REMOVE_OTHER_PACKAGES="$(buildkite-agent meta-data get REMOVE_OTHER_PACKAGES)"
else
  REMOVE_OTHER_PACKAGES="${REMOVE_OTHER_PACKAGES:-"false"}"
fi

if [[ -z "$PACKAGE_NAME" ]] || [[ -z "$PACKAGE_VERSION" ]]; then
  buildkite-agent annotate "The variables **PACKAGE_NAME** or **PACKAGE_VERSION** aren't defined, please try again" --style "warning"
  exit 1
fi

FULL_ZIP_PACKAGE_NAME="${PACKAGE_NAME}-${PACKAGE_VERSION}.zip"
TRIMED_PACKAGE_VERSION=""
TRIMED_PACKAGE_VERSION="$(echo "$PACKAGE_VERSION" | cut -d '.' -f -2)"
SOURCE_BRANCH="main"
BACKPORT_BRANCH_NAME="backport-${PACKAGE_NAME}-${TRIMED_PACKAGE_VERSION}"
PACKAGES_FOLDER_PATH="packages"

isPackagePublished() {
  local packageZip=$1
  local responseCode
  responseCode=$(curl -s -o /dev/null -w "%{http_code}" "https://package-storage.elastic.co/artifacts/packages/${packageZip}")
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
  local searchResult=""
  searchResult="$(git branch --contains $commit_sha | grep $branch | awk '{print $2}')"
  echo "${searchResult}"
  git checkout $BUILDKITE_BRANCH
  if [ "${searchResult}" == "${branch}" ]; then
    echo "The commit $commit_sha exists in the branch $branch"
    return 0
  else
    echo "The commit $commit_sha doesn't exist in the branch $branch"
    return 1
  fi
}

isBranchExist() {
  local branch=$1
  if git ls-remote --exit-code origin "$branch" >/dev/null 2>&1; then
    echo "The backport branch $branch already exists"
    return 0
  else
    echo "The backport branch $branch does not exist"
    return 1
  fi
}

createLocalBackportBranch() {
  local branch_name=$1
  local source_commit=$2
  if git checkout -b "$branch_name" "$source_commit"; then
    echo "The branch $branch_name has created."
  else
    buildkite-agent annotate "The backport branch **$BACKPORT_BRANCH_NAME** hasn't created." --style "warning"
    exit 1
  fi
}

removeOtherPackages() {
  local sourceFolder=$1
  for dir in "$sourceFolder"/*; do
    if [[ -d "$dir" ]] && [[ "$(basename "$dir")" != "$PACKAGE_NAME" ]]; then
      echo "Removing directory: $dir"
      rm -rf "$dir"
    fi
  done
}

updateBackportBranch() {
  local BUILDKITE_FOLDER_PATH=".buildkite"
  local JENKINS_FOLDER_PATH=".ci"
  git checkout $BACKPORT_BRANCH_NAME
  ls -la                                                                        #TODO remove after tests
  echo "Copying $BUILDKITE_FOLDER_PATH from $SOURCE_BRANCH..."
  git checkout $SOURCE_BRANCH -- $BUILDKITE_FOLDER_PATH
  echo "Copying $JENKINS_FOLDER_PATH from $SOURCE_BRANCH..."
  git checkout $SOURCE_BRANCH -- $JENKINS_FOLDER_PATH
  ls -la                                                                        #TODO remove after tests
  ls -la $BUILDKITE_FOLDER_PATH                                                 #TODO remove after tests
  ls -la $JENKINS_FOLDER_PATH                                                   #TODO remove after tests

  if [ "${REMOVE_OTHER_PACKAGES}" == "true" ]; then
    echo "Removing all packages from $PACKAGES_FOLDER_PATH folder"
    removeOtherPackages "$PACKAGES_FOLDER_PATH"
    ls -la $PACKAGES_FOLDER_PATH
  fi

  echo "Setting up git environment..."
  git config --global user.name "${GITHUB_USERNAME_SECRET}"
  git config --global user.email "${GITHUB_EMAIL_SECRET}"
  # git config remote.origin.url "https://${GITHUB_USERNAME_SECRET}:${GITHUB_TOKEN_SECRET}@github.com/elastic/integrations.git"

  echo "Commiting and pushing..."
  git add $BUILDKITE_FOLDER_PATH
  git add $JENKINS_FOLDER_PATH
  git commit -m "Add $BUILDKITE_FOLDER_PATH and $JENKINS_FOLDER_PATH to backport branch: $BACKPORT_BRANCH_NAME from the $SOURCE_BRANCH branch"
  # git push origin $BACKPORT_BRANCH_NAME
}

if ! [[ $PACKAGE_VERSION =~ ^[0-9]+(\.[0-9]+){2}$ ]]; then
  buildkite-agent annotate "The entered package version ${PACKAGE_VERSION} doesn't match the pattern: X.Y.Z" --style "error"
  exit 1
fi

add_bin_path

with_yq

echo "Check the entered version and PACKAGE_VERSION are equal"
version="$(cat packages/${PACKAGE_NAME}/manifest.yml | yq -r .version)"
if [[ "${version}" != "${PACKAGE_VERSION}" ]]; then
  buildkite-agent annotate "Unexpected version found in packages/${PACKAGE_NAME}/manifest.yml" --style "error"
  exit 1
fi

echo "Check that this changeset is the one creating the version $PACKAGE_NAME"
if ! git show -p ${BASE_COMMIT} packages/${PACKAGE_NAME}/manifest.yml | grep -E "^\+version: ${PACKAGE_VERSION}" ; then
  buildkite-agent annotate "This changeset does not creates the version ${PACKAGE_VERSION}" --style "error"
  exit 1
fi

echo "Check if the package has published"
if ! isPackagePublished "$FULL_ZIP_PACKAGE_NAME"; then
  buildkite-agent annotate "The package version: **${PACKAGE_NAME}-${PACKAGE_VERSION}** hasn't neen published yet." --style "error"
  exit 1
fi

echo "Check if the base commit exists."
if [ ! -z "$BASE_COMMIT" ]; then
  if ! isCommitExist "$BASE_COMMIT" "$SOURCE_BRANCH"; then
    buildkite-agent annotate "The entered commit hasn't found in the **${SOURCE_BRANCH}** branch" --style "error"
    exit 1
  fi
fi

echo "Check if the backport-branch exists"
MSG=""
if ! isBranchExist "$BACKPORT_BRANCH_NAME"; then
  MSG="The backport branch: **$BACKPORT_BRANCH_NAME** has been created."
  createLocalBackportBranch "$BACKPORT_BRANCH_NAME" "$BASE_COMMIT"
else
  MSG="The backport branch: **$BACKPORT_BRANCH_NAME** has been updated."
fi

echo "Adding CI files into the branch ${BACKPORT_BRANCH_NAME}"
updateBackportBranch

buildkite-agent annotate "$MSG" --style "success"
