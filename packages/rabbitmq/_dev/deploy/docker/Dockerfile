# Use build argument for RabbitMQ version
ARG SERVICE_VERSION
# Use RabbitMQ base image with management plugin
FROM rabbitmq:${SERVICE_VERSION}-management

# Healthcheck for RabbitMQ readiness
# Try multiple commands for compatibility with different RabbitMQ versions
HEALTHCHECK --interval=10s --retries=6 \
  CMD gosu rabbitmq rabbitmq-diagnostics -q check_running 2>/dev/null || \
      gosu rabbitmq rabbitmqctl node_health_check >/dev/null 2>&1 || \
      gosu rabbitmq rabbitmqctl status >/dev/null 2>&1

# Copy entrypoint and helper scripts
COPY entrypoint.d/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY entrypoint.d/async_rabbitmq_consumer.sh /usr/local/bin/async_rabbitmq_consumer.sh
COPY fix_debian_stretch_apt.sh /usr/local/bin/fix_debian_stretch_apt.sh
# Make fix_debian_stretch_apt.sh executable and run it to fix apt issues
RUN chmod +x /usr/local/bin/fix_debian_stretch_apt.sh && \
    /usr/local/bin/fix_debian_stretch_apt.sh
# Make entrypoint scripts executable
RUN chmod +x /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/async_rabbitmq_consumer.sh

# Install Python 3 and pika for consumer simulation
RUN apt-get update && apt-get install -y python3 python3-pika

# Copy Python consumer script
COPY entrypoint.d/simulate_queue_connection.py /usr/local/bin/simulate_queue_connection.py

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
