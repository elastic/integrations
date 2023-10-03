#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail

with_mage

mage -debug check
