#!/bin/bash

# Ensure the committed CrowdStrike FDR ingest pipelines stay in sync with the
# Go generators under packages/crowdstrike/_dev/scripts/fdr-gen. If a pipeline
# YAML is hand-edited without updating the generators (or vice versa), this
# check fails so the drift is caught in CI instead of being silently reverted
# by the next ./generate.sh run.
set -euo pipefail

GEN_DIR="packages/crowdstrike/_dev/scripts/fdr-gen"
OUT_DIR="packages/crowdstrike/data_stream/fdr/elasticsearch/ingest_pipeline"

echo "--- [crowdstrike] Regenerate FDR ingest pipelines into a temp directory"
ORIG_DIR="$(mktemp -d)"
cp "${OUT_DIR}"/*.yml "${ORIG_DIR}/"
(cd "${GEN_DIR}" && ./generate.sh)

echo "--- [crowdstrike] Check FDR pipelines match their generators"
if ! diff -rq "${ORIG_DIR}" "${OUT_DIR}"; then
  echo "^^^ +++"
  echo "FDR ingest pipelines are out of sync with ${GEN_DIR}."
  echo "Edit the generators, run ./generate.sh in that directory, and commit the result."
  exit 1
fi
rm -rf "${ORIG_DIR}"
