#!/usr/bin/env bash
set -euo pipefail

# The official Postgres image entrypoint will drop privileges to the `postgres` user
# before starting the server. If /var/log/postgresql is a host bind-mount, the
# permissions from the host win over whatever we set at build time.
#
# We try a best-effort fix from inside the container:
# - ensure the directory exists
# - if it's not writable, loosen permissions (works for many bind-mount setups)
#
# If the host mount is root-squashed or has restrictive ACLs, no container-side fix
# can override that; in that case you must adjust host perms or mount options.

LOG_DIR="/var/log/postgresql"

mkdir -p "${LOG_DIR}" || true

# If the directory isn't writable, try to make it writable for postgres.
# We avoid chown to a fixed uid/gid (varies across distros / image versions).
# Making it world-writable is acceptable for dev containers (this is under _dev/).
if ! su -s /bin/sh -c "test -w '${LOG_DIR}'" postgres 2>/dev/null; then
  chmod 0777 "${LOG_DIR}" 2>/dev/null || true
fi

# Preserve the original image behavior: when no args are provided, run `postgres`.
if [ "$#" -eq 0 ]; then
  set -- postgres
fi

# Use the original entrypoint and preserve its init logic.
exec /usr/local/bin/docker-entrypoint.sh "$@"
