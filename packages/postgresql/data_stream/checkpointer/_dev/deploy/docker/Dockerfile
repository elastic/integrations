ARG SERVICE_VERSION=${SERVICE_VERSION:-9.5.25}
FROM postgres:${SERVICE_VERSION}

COPY docker-entrypoint-initdb.d /docker-entrypoint-initdb.d

# Runtime fix for host-mounted /var/log/postgresql permissions.
# Runs before the official entrypoint drops privileges to the postgres user.
COPY docker-entrypoint-wrapper.sh /usr/local/bin/docker-entrypoint-wrapper.sh
ENTRYPOINT ["/usr/local/bin/docker-entrypoint-wrapper.sh"]

HEALTHCHECK --interval=10s --retries=6 CMD pg_isready -U postgres
