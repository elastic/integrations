#!/usr/bin/env bash
# Runs tests for scripts in .buildkite/scripts/.
# TODO: migrate to the bats framework (https://github.com/bats-core/bats-core)
#       for better test isolation, TAP output, and native setup/teardown support.
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
VENV_DIR="${REPO_ROOT}/.buildkite/.venv-ci-python-scripts"
REQ_FILE="${REPO_ROOT}/.buildkite/scripts/requirements-ci-python-scripts.txt"
FIND_OLDEST_SCRIPT="${REPO_ROOT}/.buildkite/scripts/find_oldest_supported_version.py"

run_tests_if_exists() {
    local script="$1"
    if [[ ! -f "${script}" ]]; then
        echo "Skipping ${script} (file not found)"
        return 0
    fi
    "${script}"
}

echo "=== Running find_oldest_supported_version.py tests ==="
if [[ ! -f "${VENV_DIR}/bin/activate" ]]; then
    rm -rf "${VENV_DIR}"
    if ! python3 -m venv "${VENV_DIR}"; then
        echo "--- Installing python3-venv"
        if command -v apt-get >/dev/null 2>&1; then
            echo "python3 -m venv unavailable; installing python3-venv"
            sudo apt-get update -q
            sudo DEBIAN_FRONTEND=noninteractive apt-get install -y python3-venv
        fi
        rm -rf "${VENV_DIR}"
        python3 -m venv "${VENV_DIR}"
    fi
fi
echo "--- Installing dependencies"
# shellcheck source=/dev/null
source "${VENV_DIR}/bin/activate"
python3 -m pip install -q -r "${REQ_FILE}"
echo "+++ Running tests"
python3 "${FIND_OLDEST_SCRIPT}" --test
echo "--- Deactivating venv"
deactivate

echo ""
echo "=== Running check_changelog_entries.sh tests ==="
run_tests_if_exists "${REPO_ROOT}/.buildkite/scripts/test_check_changelog_entries.sh"
