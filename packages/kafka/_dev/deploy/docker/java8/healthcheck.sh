#!/bin/bash
# Exit immediately if a command exits with a non-zero status.
set -e

# 1. Check for the Kafka Broker process
pgrep -f 'kafka.Kafka' > /dev/null || { echo "Healthcheck failed: Kafka broker not running."; exit 1; }

# 2. Check for the Console Producer process
pgrep -f 'kafka.tools.ConsoleProducer' > /dev/null || { echo "Healthcheck failed: Console producer not running."; exit 1; }

# 3. Check for the Console Consumer process
pgrep -f 'kafka.tools.ConsoleConsumer' > /dev/null || { echo "Healthcheck failed: Console consumer not running."; exit 1; }

# If all checks pass, exit with 0 to indicate the container is healthy.
exit 0