#!/usr/bin/env bash

# shellcheck disable=SC1091
source /usr/local/bin/bash_standard_lib.sh

if [ -x "$(command -v docker)" ]; then
  IMAGE=docker.elastic.co/observability-ci/weblogic:12.2.1.3-dev
  (retry 2 docker pull "${IMAGE}") || echo "Error pulling ${IMAGE} Docker image, we continue"
  docker tag "${IMAGE}" container-registry.oracle.com/middleware/weblogic:12.2.1.3-dev
fi
