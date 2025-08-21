#!/bin/bash
set -e

# This script waits for RabbitMQ to be fully started and then runs a Python consumer script
# to simulate a long-lived connection. It is compatible with RabbitMQ 3.7.4 and 4.x.

# Wait for RabbitMQ to be fully started (compatible with RabbitMQ 3.7.4 and 4.x)
# The loop checks the output of 'rabbitmqctl status' for several possible indicators of readiness.
# It breaks out of the loop once RabbitMQ is ready, otherwise it waits and retries.
while true; do
  if gosu rabbitmq rabbitmqctl status 2>&1 | grep -Eiq 'pid,|Pid|Status of node|RabbitMQ'; then
    break
  fi
  echo "Waiting for RabbitMQ to start..."
  sleep 2
done

# Check if Python 3 is available in the system
if command -v python3 &> /dev/null; then
  # If Python 3 is found, start the Python consumer script in the background
  echo "Starting Python consumer script to simulate long-lived connection..."
  python3 /usr/local/bin/simulate_queue_connection.py &
else
  # If Python 3 is not found, print a warning and skip the simulation
  echo "Python3 not found, skipping consumer simulation."
fi
