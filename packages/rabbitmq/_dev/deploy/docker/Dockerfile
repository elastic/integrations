ARG SERVICE_VERSION
FROM rabbitmq:${SERVICE_VERSION}-management

#HEALTHCHECK --interval=10s --retries=6 CMD rabbitmq-diagnostics -q check_running

HEALTHCHECK --interval=10s --retries=6 \
  CMD rabbitmq-diagnostics -q check_running 2>/dev/null || \
      rabbitmqctl node_health_check >/dev/null 2>&1 || \
      rabbitmqctl status >/dev/null 2>&1


COPY entrypoint.d/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY fix_debian_stretch_apt.sh /usr/local/bin/fix_debian_stretch_apt.sh
RUN chmod +x /usr/local/bin/fix_debian_stretch_apt.sh && \
    /usr/local/bin/fix_debian_stretch_apt.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

RUN apt-get update && apt-get install -y python3 python3-pika

COPY entrypoint.d/simulate_queue_connection.py /usr/local/bin/simulate_queue_connection.py

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
