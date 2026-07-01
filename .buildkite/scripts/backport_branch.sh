#!/bin/bash

source .buildkite/scripts/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/backport_branch_lib.sh"

set -euo pipefail

cleanup_gh() {
    pushd "$WORKSPACE" > /dev/null
    git config remote.origin.url "https://github.com/elastic/integrations.git"
    popd > /dev/null
}

cleanup() {
  local exit_code=$?
  cleanup_gh
  exit "${exit_code}"
}

trap cleanup EXIT

# annotate_and_echo posts a Buildkite annotation and echoes the same message
# to the build log so it is visible in both the annotation panel and the raw output.
# Usage: annotate_and_echo <style> <message>
#   style: error | warning | success | info
annotate_and_echo() {
    local style="${1}"
    local message="${2}"
    echo "${message}"
    buildkite-agent annotate "${message}" --style "${style}"
}

DRY_RUN="$(buildkite-agent meta-data get DRY_RUN --default "${DRY_RUN:-"true"}")"
BASE_COMMIT="$(buildkite-agent meta-data get BASE_COMMIT --default "${BASE_COMMIT:-""}")"
PACKAGE_NAME="$(buildkite-agent meta-data get PACKAGE_NAME --default "${PACKAGE_NAME:-""}")"
PACKAGE_VERSION="$(buildkite-agent meta-data get PACKAGE_VERSION --default "${PACKAGE_VERSION:-""}")"
REMOVE_OTHER_PACKAGES="$(buildkite-agent meta-data get REMOVE_OTHER_PACKAGES --default "${REMOVE_OTHER_PACKAGES:-"true"}")"
BACKPORT_BRANCH_NAME="$(buildkite-agent meta-data get BACKPORT_BRANCH_NAME --default "${BACKPORT_BRANCH_NAME:-""}")"
PR_NUMBER="$(buildkite-agent meta-data get PR_NUMBER --default "${PR_NUMBER:-""}")"

if [[ -z "$PACKAGE_NAME" ]] || [[ -z "$PACKAGE_VERSION" ]]; then
  annotate_and_echo "warning" "The variables **PACKAGE_NAME** or **PACKAGE_VERSION** aren't defined, please try again"
  exit 1
fi

if [[ -n "${PR_NUMBER}" ]] && ! [[ "${PR_NUMBER}" =~ ^[0-9]+$ ]]; then
  annotate_and_echo "error" "Invalid PR_NUMBER **${PR_NUMBER}**: must be a positive integer"
  exit 1
fi

# Report data set in the input step
PARAMETERS=(
    "**DRY_RUN**=$DRY_RUN"
    "**BASE_COMMIT**=$BASE_COMMIT"
    "**PACKAGE_NAME**=$PACKAGE_NAME"
    "**PACKAGE_VERSION**=$PACKAGE_VERSION"
    "**REMOVE_OTHER_PACKAGES**=$REMOVE_OTHER_PACKAGES"
    "**BACKPORT_BRANCH_NAME**=$BACKPORT_BRANCH_NAME"
    "**PR_NUMBER**=$PR_NUMBER"
)

# Show each parameter in a different line
echo "Parameters: ${PARAMETERS[*]}" | sed 's/ /\n- /g' | buildkite-agent annotate \
    --style "info" \
    --context "context-parameters"

FULL_ZIP_PACKAGE_NAME="${PACKAGE_NAME}-${PACKAGE_VERSION}.zip"
TRIMMED_PACKAGE_VERSION="$(echo "$PACKAGE_VERSION" | cut -d '.' -f -2)"
SOURCE_BRANCH="main"
## In order to test other branches probably it is required to copy the dev files or magefile from the PR branch, and for that it would require these changes
# git checkout -b test_main
# SOURCE_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
# echo "--- SOURCE_BRANCH: ${SOURCE_BRANCH}"

# If the backport branch name is not set, use the expected one.
EXPECTED_BACKPORT_BRANCH_NAME="backport-${PACKAGE_NAME}-${TRIMMED_PACKAGE_VERSION}"
if [[ "${BACKPORT_BRANCH_NAME}" == "" ]]; then
  BACKPORT_BRANCH_NAME="${EXPECTED_BACKPORT_BRANCH_NAME}"
fi

PACKAGES_FOLDER_PATH="packages"
MSG=""

isPackagePublished() {
  local packageZip=$1
  local responseCode
  responseCode=$(retry 5 curl -s -o /dev/null -w "%{http_code}" "https://package-storage.elastic.co/artifacts/packages/${packageZip}")
  if [[ $responseCode == "200" ]]; then
    return 0
  else
    return 1
  fi
}

commitExists() {
  local commit_sha=$1
  local branch=$2
  git checkout "$branch"
  local searchResult=""
  searchResult="$(git branch --contains "$commit_sha" --format="%(refname:short)" | grep -E ^${branch}$)"
  git checkout "$BUILDKITE_BRANCH"
  if [ "${searchResult}" == "${branch}" ]; then
    echo "The commit $commit_sha exists in the branch $branch"
    return 0
  else
    echo "The commit $commit_sha doesn't exist in the branch $branch"
    return 1
  fi
}

branchExist() {
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
    echo "The branch $branch_name has been created."
  else
    annotate_and_echo "warning" "The backport branch **$BACKPORT_BRANCH_NAME** could not be created."
    exit 1
  fi
}

update_git_config() {
    pushd "$WORKSPACE" > /dev/null
    git config --global user.name "${GITHUB_USERNAME}"
    git config --global user.email "${GITHUB_EMAIL}"

    popd > /dev/null
}

updateBackportBranchContents() {
  local BUILDKITE_FOLDER_PATH=".buildkite"
  local JENKINS_FOLDER_PATH=".ci"
  local files_cached_num=""

  git checkout "$BACKPORT_BRANCH_NAME"
  echo "--- Copying $BUILDKITE_FOLDER_PATH from $SOURCE_BRANCH..."
  git checkout $SOURCE_BRANCH -- $BUILDKITE_FOLDER_PATH
  git add $BUILDKITE_FOLDER_PATH

  if git ls-tree -d --name-only main:.ci >/dev/null 2>&1; then
    echo "--- Copying $JENKINS_FOLDER_PATH from $SOURCE_BRANCH..."
    git checkout $SOURCE_BRANCH -- $JENKINS_FOLDER_PATH
    git add $JENKINS_FOLDER_PATH
  else
    if [ -d "${JENKINS_FOLDER_PATH}" ]; then
      echo "--- Removing $JENKINS_FOLDER_PATH from $BACKPORT_BRANCH_NAME..."
      rm -rf "$JENKINS_FOLDER_PATH"
      git add "$JENKINS_FOLDER_PATH"
    fi
  fi

  # Update scripts used by mage
  local MAGEFILE_SCRIPTS_FOLDER="dev/citools"
  local TESTSREPORTER_SCRIPTS_FOLDER="dev/testsreporter"
  local COVERAGE_SCRIPTS_FOLDER="dev/coverage"
  local CODEOWNERS_SCRIPTS_FOLDER="dev/codeowners"
  local PACKAGENAMES_SCRIPTS_FOLDER="dev/packagenames"
  local BACKPORTS_SCRIPTS_FOLDER="dev/backports"
  local DEV_SCRIPTS_FOLDER="dev/scripts"

  if git ls-tree -d --name-only main:${MAGEFILE_SCRIPTS_FOLDER} > /dev/null 2>&1 ; then
    echo "--- Copying magefile scripts from $SOURCE_BRANCH..."
    echo "Copying $MAGEFILE_SCRIPTS_FOLDER from $SOURCE_BRANCH..."
    git checkout "$SOURCE_BRANCH" -- "${MAGEFILE_SCRIPTS_FOLDER}"
    git add "${MAGEFILE_SCRIPTS_FOLDER}"

    echo "Copying $TESTSREPORTER_SCRIPTS_FOLDER from $SOURCE_BRANCH..."
    git checkout "$SOURCE_BRANCH" -- "${TESTSREPORTER_SCRIPTS_FOLDER}"
    git add "${TESTSREPORTER_SCRIPTS_FOLDER}"

    echo "Copying $COVERAGE_SCRIPTS_FOLDER from $SOURCE_BRANCH..."
    git checkout "$SOURCE_BRANCH" -- "${COVERAGE_SCRIPTS_FOLDER}"
    git add "${COVERAGE_SCRIPTS_FOLDER}"

    echo "Copying $CODEOWNERS_SCRIPTS_FOLDER from $SOURCE_BRANCH..."
    git checkout "$SOURCE_BRANCH" -- "${CODEOWNERS_SCRIPTS_FOLDER}"
    git add "${CODEOWNERS_SCRIPTS_FOLDER}"

    echo "Copying $PACKAGENAMES_SCRIPTS_FOLDER from $SOURCE_BRANCH..."
    git checkout "$SOURCE_BRANCH" -- "${PACKAGENAMES_SCRIPTS_FOLDER}"
    git add "${PACKAGENAMES_SCRIPTS_FOLDER}"

    echo "Copying $BACKPORTS_SCRIPTS_FOLDER from $SOURCE_BRANCH..."
    git checkout "$SOURCE_BRANCH" -- "${BACKPORTS_SCRIPTS_FOLDER}"
    git add "${BACKPORTS_SCRIPTS_FOLDER}"

    echo "Copying $DEV_SCRIPTS_FOLDER from $SOURCE_BRANCH..."
    git checkout "$SOURCE_BRANCH" -- "${DEV_SCRIPTS_FOLDER}"
    git add "${DEV_SCRIPTS_FOLDER}"

    echo "Copying magefile.go from $SOURCE_BRANCH..."
    git checkout "$SOURCE_BRANCH" -- "magefile.go"
    git add magefile.go

    # As this script runs in the context of the main branch (mainly go mod tidy), we need to copy
    # the .go-version file from the main branch to the backport branch. This avoids failures
    # installing dependencies in the backport Pull Request.
    echo "--- Copying .go-version from $SOURCE_BRANCH..."
    git checkout "$SOURCE_BRANCH" -- ".go-version"
    git add .go-version

    # Restore workflows from the main branch since modifying them requires extra permissions.
    # > error: GH013: Repository rule violations found for ...
    # > refusing to allow a GitHub App to create or update workflow `.github/workflows/bump-elastic-stack-version.yml` without `workflows` permission
    echo "--- Copying .github/workflows from $SOURCE_BRANCH..."
    git checkout "$SOURCE_BRANCH" -- ".github/workflows"
    git add .github/workflows

    # Copy tools.go so we have the dev scripts dependencies required
    echo "--- Copying tools.go from $SOURCE_BRANCH..."
    git checkout "$SOURCE_BRANCH" -- "tools.go"
    git add tools.go

    # Run go mod tidy to update just the dependencies related to magefile and dev scripts
    echo "--- Running go mod tidy to update dependencies related to magefile and dev scripts..."
    go mod tidy

    git add go.mod go.sum
  fi

  if [ "${REMOVE_OTHER_PACKAGES}" == "true" ]; then
    echo "--- Removing all packages from $PACKAGES_FOLDER_PATH folder"

    # Build the list of packages to keep: the target package plus any packages
    # it requires (composable packages declare dependencies under requires.input
    # and requires.content in their manifest.yml).
    local -a packages_to_keep=("${PACKAGE_PATH}")
    while IFS= read -r req_name; do
      local req_path
      req_path=$(get_package_path "${req_name}" || true)
      if [[ -n "${req_path}" ]]; then
        echo "Keeping required package: ${req_path} (required by ${PACKAGE_NAME})"
        packages_to_keep+=("${req_path}")
      else
        echo "Warning: required package '${req_name}' not found in packages folder"
      fi
    done < <(get_required_package_names "${PACKAGE_PATH}")

    remove_other_packages "${packages_to_keep[@]}"
    ls -la "${PACKAGES_FOLDER_PATH}"

    git add "${PACKAGES_FOLDER_PATH}/"
    git add .github/CODEOWNERS
  fi

  echo "--- Current git status before commit:"
  git status

  echo "--- Setting up git environment..."
  update_git_config

  files_cached_num=$(git diff --name-only --cached | wc -l)
  if [ "${files_cached_num}" -gt 0 ]; then
    echo "--- Committing changes..."
    git commit -m "Add $BUILDKITE_FOLDER_PATH and $JENKINS_FOLDER_PATH to backport branch: $BACKPORT_BRANCH_NAME from the $SOURCE_BRANCH branch"
  else
    echo "+++ Nothing to commit, skip."
  fi

  if [ "$DRY_RUN" == "true" ];then
    echo "--- DRY_RUN mode, nothing will be pushed."
    # Show just the relevant files diff (go.mod, go.sum, .buildkite, dev, .go-version, .github/CODEOWNERS and package to be backported)
    git --no-pager diff "$SOURCE_BRANCH...$BACKPORT_BRANCH_NAME" .buildkite/ dev/ go.sum go.mod .go-version tools.go .github/CODEOWNERS "${PACKAGE_PATH}"
  else
    echo "--- Pushing..."
    git push origin "$BACKPORT_BRANCH_NAME"
  fi

  cleanup_gh
}

if ! [[ "${PACKAGE_VERSION}" =~ ^[0-9]+(\.[0-9]+){2}(\-.*)?$ ]]; then
  annotate_and_echo "error" "The entered package version ${PACKAGE_VERSION} doesn't match the pattern"
  exit 1
fi

add_bin_path

with_yq
with_mage

echo "--- Validating custom backport branch name"
if ! mage ValidateBackportBranchName "${PACKAGE_NAME}" "${BACKPORT_BRANCH_NAME}"; then
  annotate_and_echo "error" "Invalid backport branch name **${BACKPORT_BRANCH_NAME}**: must match \`backport-${PACKAGE_NAME}-<suffix>\`"
  exit 1
fi

echo "--- Resolve package path from PACKAGE_NAME"
PACKAGE_PATH="$(get_package_path "${PACKAGE_NAME}" || true)"
if [[ -z "${PACKAGE_PATH}" ]]; then
  annotate_and_echo "error" "Package **${PACKAGE_NAME}** not found"
  exit 1
fi
echo "Package path: ${PACKAGE_PATH}"

echo "--- Check if the package is published"
if ! isPackagePublished "$FULL_ZIP_PACKAGE_NAME"; then
  annotate_and_echo "error" "The package version: **${PACKAGE_NAME}-${PACKAGE_VERSION}** hasn't been published yet."
  exit 1
fi

echo "--- Check if the base commit exists."
if [ ! -z "$BASE_COMMIT" ]; then
  if ! commitExists "$BASE_COMMIT" "$SOURCE_BRANCH"; then
    annotate_and_echo "error" "The entered commit was not found in the **${SOURCE_BRANCH}** branch"
    exit 1
  fi
fi


echo "--- Check if the backport-branch exists"
if branchExist "$BACKPORT_BRANCH_NAME"; then
  MSG="The backport branch: **$BACKPORT_BRANCH_NAME** is already created. Not updating contents of the branch."
  annotate_and_echo "warning" "$MSG"
  # Set meta-data so the notify step can distinguish this success case
  # (branch pre-existed) from a branch that was freshly created.
  buildkite-agent meta-data set BRANCH_ALREADY_EXISTED true
  exit 0
fi

# backport branch does not exist, running checks and create branch
version="$(git show "${BASE_COMMIT}":"${PACKAGE_PATH}/manifest.yml" | yq -r .version)"
echo "--- Check if version from ${BASE_COMMIT} (${version}) matches with version from input step ${PACKAGE_VERSION}"
if [[ "${version}" != "${PACKAGE_VERSION}" ]]; then
  annotate_and_echo "error" "Unexpected version found in ${PACKAGE_PATH}/manifest.yml"
  exit 1
fi

echo "---Check that this changeset is the one creating the version $PACKAGE_NAME"
if ! git show -p "${BASE_COMMIT}" "${PACKAGE_PATH}/manifest.yml" | grep -E "^\+version: \"{0,1}${PACKAGE_VERSION}" ; then
  annotate_and_echo "error" "This changeset does not create the version ${PACKAGE_VERSION}"
  exit 1
fi

echo "--- Creating the branch: $BACKPORT_BRANCH_NAME from the commit: $BASE_COMMIT"
createLocalBackportBranch "$BACKPORT_BRANCH_NAME" "$BASE_COMMIT"
MSG="The backport branch: **$BACKPORT_BRANCH_NAME** has been created."

echo "+++ Adding CI files into the branch ${BACKPORT_BRANCH_NAME}"
updateBackportBranchContents

if [ "${DRY_RUN}" == "true" ]; then
  MSG="[DRY_RUN] ${MSG}."
fi
annotate_and_echo "success" "$MSG"
