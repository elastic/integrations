#!/bin/sh
set -eu

cd /package-registry
./package-registry &
EPR_PID=$!

until curl -sf http://localhost:8081 >/dev/null 2>&1; do
  if ! kill -0 "$EPR_PID" 2>/dev/null; then
    wait "$EPR_PID" || true
    exit 1
  fi
  sleep 1
done

WORKLOAD_STARTED=0
trap 'WORKLOAD_STARTED=1' HUP

echo "Waiting for SIGHUP to start workload..."
while [ "$WORKLOAD_STARTED" -eq 0 ]; do sleep 1; done

echo "SIGHUP received, starting registry API workload..."
while true; do
  curl -sf "http://localhost:8081/search?package=test_package" >/dev/null || true
  curl -sf "http://localhost:8081/package/test_package/0.0.1/" >/dev/null || true
  curl -sf "http://localhost:8081/categories" >/dev/null || true
  # Exercise storage_requests_total: artifact download, signature lookup and static resource.
  curl -sf "http://localhost:8081/epr/test_package/test_package-0.0.1.zip" >/dev/null || true
  curl -sf "http://localhost:8081/epr/test_package/test_package-0.0.1.zip.sig" >/dev/null || true
  curl -sf "http://localhost:8081/package/test_package/0.0.1/docs/README.md" >/dev/null || true
  sleep 5
done
