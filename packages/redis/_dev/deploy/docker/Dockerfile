ARG SERVICE_VERSION
FROM redis:${SERVICE_VERSION}-alpine
HEALTHCHECK --interval=1s --retries=90 CMD nc -z localhost 6379
