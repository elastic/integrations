#!/usr/bin/env bash
#
# Runs Python unit tests for CI scripts in an isolated venv.
# Intended for Buildkite (see pipeline.yml).
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
VENV_DIR="${REPO_ROOT}/.buildkite/.venv-ci-python-scripts"
REQ_FILE="${REPO_ROOT}/.buildkite/scripts/requirements-ci-python-scripts.txt"
FIND_OLDEST_SCRIPT="${REPO_ROOT}/.buildkite/scripts/find_oldest_supported_version.py"

if [[ ! -f "${VENV_DIR}/bin/activate" ]]; then
    rm -rf "${VENV_DIR}"
    if ! python3 -m venv "${VENV_DIR}"; then
        if command -v apt-get >/dev/null 2>&1 && [[ "$(id -u)" -eq 0 ]]; then
            echo "python3 -m venv unavailable; installing python3-venv"
            DEBIAN_FRONTEND=noninteractive apt-get update -qq
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-venv
        fi
        rm -rf "${VENV_DIR}"
        python3 -m venv "${VENV_DIR}"
    fi
fi
# shellcheck source=/dev/null
source "${VENV_DIR}/bin/activate"
pip install -q -r "${REQ_FILE}"
python "${FIND_OLDEST_SCRIPT}" --test
deactivate
