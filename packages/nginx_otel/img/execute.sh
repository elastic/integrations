#!/usr/bin/env bash

# required by file_storage data
mkdir -p data
# required by nginx logs
mkdir -p logs

export NGINX_LOGS_DIR="$(pwd)/logs"

# run nginx service
docker-compose up -v -d

~/Coding/work/opentelemetry-collector-components/_build/elastic-collector-components --config nginx-otel.yml
