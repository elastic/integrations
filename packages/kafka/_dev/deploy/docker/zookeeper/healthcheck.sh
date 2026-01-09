#!/bin/bash
# Exit immediately if a command exits with a non-zero status.
set -e

# 1. Check for the Kafka Broker process
ps -ef | grep '[k]afka.Kafka' | awk '{print $2}' > /dev/null || { echo "Healthcheck failed: Kafka broker not running."; exit 1; }

# 2. Check for the Console Producer process
ps -ef | grep '[k]afka.tools.ConsoleProducer' | awk '{print $2}' > /dev/null || { echo "Healthcheck failed: Console producer not running."; exit 1; }

# 3. Check for the Console Consumer process
ps -ef | grep '[k]afka.tools.ConsoleConsumer' | awk '{print $2}' > /dev/null || { echo "Healthcheck failed: Console consumer not running."; exit 1; }

# If all checks pass, exit with 0 to indicate the container is healthy.
exit 0