#!/bin/bash

set -m

gcloud beta emulators pubsub start --host-port=127.0.0.1:8538 --project=system-tests &

$(gcloud beta emulators pubsub env-init --project=system-tests)

python3 publisher.py

fg