#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail

add_bin_path
with_mage

mage -v check

check_git_diff

use_elastic_package
${ELASTIC_PACKAGE_BIN} links check
