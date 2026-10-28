#!/bin/sh
set -eu

# Run seeding in background (it will wait for Redis to be ready)
/usr/local/bin/seed-keyspace.sh &

# Hand off to the original entrypoint/command in the foreground (PID 1)
exec docker-entrypoint.sh "$@"
