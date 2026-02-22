ARG SERVICE_VERSION=${SERVICE_VERSION:-5.0}
FROM mongo:${SERVICE_VERSION}
# remove the mongodb-org.list as the GPG key is expired and we don't need it.
RUN rm /etc/apt/sources.list.d/mongodb-org.list && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*
HEALTHCHECK --interval=1s --retries=90 CMD nc -z localhost 27017