#!/bin/bash
set -e

# Start async consumer logic in the background
/usr/local/bin/async_rabbitmq_consumer.sh &

# Start RabbitMQ using the original Docker entrypoint script in the foreground as PID 1
exec /usr/local/bin/docker-entrypoint.sh rabbitmq-server
