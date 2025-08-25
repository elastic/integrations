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
# Copy the main entrypoint script to the container's /usr/local/bin directory
COPY entrypoint.d/entrypoint.sh /usr/local/bin/entrypoint.sh
# Copy the async RabbitMQ consumer script to the container's /usr/local/bin directory
COPY entrypoint.d/async_rabbitmq_consumer.sh /usr/local/bin/async_rabbitmq_consumer.sh
# Copy the Debian stretch APT fix script to the container's /usr/local/bin directory
COPY fix_debian_stretch_apt.sh /usr/local/bin/fix_debian_stretch_apt.sh

# Make fix_debian_stretch_apt.sh executable and run it to fix apt issues
# Make the Debian stretch APT fix script executable and run it to fix APT issues for Debian 9
RUN chmod +x /usr/local/bin/fix_debian_stretch_apt.sh && \
    /usr/local/bin/fix_debian_stretch_apt.sh
# Make the entrypoint and async consumer scripts executable
RUN chmod +x /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/async_rabbitmq_consumer.sh

# Install Python 3 and pika for consumer simulation
# Install Python 3 and the pika library for simulating a RabbitMQ consumer
RUN apt-get update && apt-get install -y python3 python3-pika

# Copy Python consumer script
# Copy the Python consumer simulation script to the container's /usr/local/bin directory
COPY entrypoint.d/simulate_queue_connection.py /usr/local/bin/simulate_queue_connection.py

# Set entrypoint
# Set the default entrypoint for the container to the entrypoint.sh script
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
