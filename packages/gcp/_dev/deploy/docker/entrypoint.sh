#!/bin/bash

set -m

gcloud beta emulators pubsub start --data-dir /data --host-port "0.0.0.0:8432" &

/publisher

fg