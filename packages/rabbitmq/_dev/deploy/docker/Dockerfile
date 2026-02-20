# Use build argument for RabbitMQ version
ARG SERVICE_VERSION
# Use RabbitMQ base image with management plugin
FROM rabbitmq:${SERVICE_VERSION}-management

# Healthcheck for RabbitMQ readiness
# Set the healthcheck for the container to ensure RabbitMQ is running and healthy
# Tries multiple commands for compatibility with different RabbitMQ versions
HEALTHCHECK --interval=10s --retries=6 \
  CMD gosu rabbitmq rabbitmq-diagnostics -q check_running 2>/dev/null || \
      gosu rabbitmq rabbitmqctl node_health_check >/dev/null 2>&1 || \
      gosu rabbitmq rabbitmqctl status >/dev/null 2>&1

# Copy entrypoint and helper scripts
COPY entrypoint.d/simulate_queue_connection.py entrypoint.d/entrypoint.sh entrypoint.d/async_rabbitmq_consumer.sh fix_debian_stretch_apt.sh /usr/local/bin/

# run it to fix APT issues for Debian 9
RUN /usr/local/bin/fix_debian_stretch_apt.sh

# Install Python 3 and pika for consumer simulation
RUN apt-get update && apt-get install -y python3 python3-pika

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
