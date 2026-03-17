ARG SERVICE_VERSION=8.4.8
FROM mysql:${SERVICE_VERSION}
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
