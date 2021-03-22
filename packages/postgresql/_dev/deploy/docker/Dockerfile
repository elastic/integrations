ARG SERVICE_VERSION=${SERVICE_VERSION:-9.5.3}
FROM postgres:${SERVICE_VERSION}
COPY docker-entrypoint-initdb.d /docker-entrypoint-initdb.d
HEALTHCHECK --interval=10s --retries=6 CMD psql -h localhost -U postgres -l
