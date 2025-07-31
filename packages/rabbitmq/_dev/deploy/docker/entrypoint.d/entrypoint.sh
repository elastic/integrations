#!/bin/bash
set -e

# Start RabbitMQ server in the background
rabbitmq-server &
RABBITMQ_PID=$!

# Wait for RabbitMQ to be fully started
until rabbitmq-diagnostics -q check_running; do
  echo "Waiting for RabbitMQ to start..."
  sleep 2
done

echo "RabbitMQ is running. Simulating connection..."

# Simulate a connection using rabbitmqadmin (requires rabbitmqadmin to be installed)
if ! command -v rabbitmqadmin &> /dev/null; then
  curl -s -o /usr/local/bin/rabbitmqadmin http://localhost:15672/cli/rabbitmqadmin
  chmod +x /usr/local/bin/rabbitmqadmin
fi

rabbitmqadmin -u guest -p guest -H localhost -V / list connections || echo "Connection simulation failed"

QUEUE_NAME="test-queue"

echo "Declaring test queue: $QUEUE_NAME"
rabbitmqadmin -u guest -p guest -H localhost -V / declare queue name=$QUEUE_NAME durable=true || echo "Queue declaration failed"

echo "Publishing multiple test messages to $QUEUE_NAME to keep connection active..."
for i in {1..100}; do
  rabbitmqadmin -u guest -p guest -H localhost -V / publish routing_key=$QUEUE_NAME payload="Test message $i" || echo "Message $i publish failed"
  sleep 1
done

# Run Python consumer to simulate long-lived connection
if command -v python3 &> /dev/null; then
  echo "Starting Python consumer script to simulate long-lived connection..."
  python3 /usr/local/bin/simulate_queue_connection.py &
else
  echo "Python3 not found, skipping consumer simulation."
fi

wait $RABBITMQ_PID
