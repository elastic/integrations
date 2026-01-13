ARG SERVICE_VERSION=${SERVICE_VERSION:-9.5.25}
FROM postgres:${SERVICE_VERSION}
COPY docker-entrypoint-initdb.d /docker-entrypoint-initdb.d
HEALTHCHECK --interval=10s --retries=6 CMD pg_isready -U postgres || exit 2
