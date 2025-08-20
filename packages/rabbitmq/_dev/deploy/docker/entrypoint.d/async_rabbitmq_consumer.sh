#!/bin/bash
set -e

# Wait for RabbitMQ to be fully started (compatible with RabbitMQ 3.7.4 and 4.x)
while true; do
  if gosu rabbitmq rabbitmqctl status 2>&1 | grep -Eiq 'pid,|Pid|Status of node|RabbitMQ'; then
    break
  fi
  echo "Waiting for RabbitMQ to start..."
  sleep 2
done

# Run Python consumer to simulate long-lived connection
if command -v python3 &> /dev/null; then
  echo "Starting Python consumer script to simulate long-lived connection..."
  python3 /usr/local/bin/simulate_queue_connection.py &
else
  echo "Python3 not found, skipping consumer simulation."
fi
