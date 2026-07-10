#!/bin/bash

set -euo pipefail

system_pipeline="packages/system/data_stream/security/elasticsearch/ingest_pipeline/scheduled_task.yml"
windows_pipeline="packages/windows/data_stream/forwarded/elasticsearch/ingest_pipeline/security_scheduled_task.yml"

if ! cmp -s "${system_pipeline}" "${windows_pipeline}"; then
  echo "Scheduled task normalization pipelines must remain byte-identical."
  diff -u "${system_pipeline}" "${windows_pipeline}"
fi

