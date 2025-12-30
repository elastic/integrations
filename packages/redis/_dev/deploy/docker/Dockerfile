ARG SERVICE_VERSION
FROM redis:${SERVICE_VERSION}-alpine
HEALTHCHECK --interval=1s --retries=90 CMD nc -z localhost 6379

RUN apk add --no-cache netcat-openbsd

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY seed-keyspace.sh /usr/local/bin/seed-keyspace.sh

# Override image entrypoint; keep default CMD (or set your own).
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["redis-server"]