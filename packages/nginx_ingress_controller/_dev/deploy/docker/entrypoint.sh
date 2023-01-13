#!/bin/sh

set -e

cp /sample_logs/*.log /var/log/nginx/

/nginx-ingress-controller --log_file=/var/log/nginx/error.log -v=10 2>&1 | tee /var/log/nginx/error.log