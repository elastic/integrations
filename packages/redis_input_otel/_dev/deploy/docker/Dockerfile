ARG SERVICE_VERSION=7.2
FROM redis:${SERVICE_VERSION}-alpine
HEALTHCHECK --interval=1s --retries=90 CMD redis-cli ping || exit 1
