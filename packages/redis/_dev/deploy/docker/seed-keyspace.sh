#!/bin/sh
set -eu

# Minimal seeding script for local Redis inside the container.
# Uses only redis-cli defaults (local unix socket / localhost). No host/port flags.

MAX_WAIT_SECONDS="${MAX_WAIT_SECONDS:-30}"
SLEEP_SECONDS="${SLEEP_SECONDS:-0.2}"

KEY_PREFIX="${KEY_PREFIX:-test:keyspace}"
KEY_COUNT="${KEY_COUNT:-3}"

log() {
  printf '%s\n' "$*" >&2
}

if ! command -v redis-cli >/dev/null 2>&1; then
  log "seed-keyspace: redis-cli not found"
  exit 1
fi

log "seed-keyspace: waiting for local redis (max ${MAX_WAIT_SECONDS}s)"
end=$(( $(date +%s) + MAX_WAIT_SECONDS ))

until redis-cli PING >/dev/null 2>&1; do
  if [ "$(date +%s)" -ge "${end}" ]; then
    log "seed-keyspace: timed out waiting for redis"
    # Print one last attempt output to help debugging.
    redis-cli PING >&2 || true
    exit 1
  fi
  sleep "${SLEEP_SECONDS}"
done

log "seed-keyspace: redis is up; seeding ${KEY_COUNT} keys"

i=1
while [ "${i}" -le "${KEY_COUNT}" ]; do
  redis-cli SET "${KEY_PREFIX}:${i}" "value-${i}" >/dev/null
  i=$((i + 1))
done

# Optional: ensure it shows up in INFO keyspace.
if [ "${VERIFY_KEYSPACE:-1}" != "0" ]; then
  redis-cli INFO keyspace | grep -E '^db0:' >/dev/null 2>&1 || {
    log "seed-keyspace: seed done but INFO keyspace doesn't contain db0"
    redis-cli INFO keyspace >&2 || true
    exit 1
  }
  log "seed-keyspace: verified db0 present"
fi

