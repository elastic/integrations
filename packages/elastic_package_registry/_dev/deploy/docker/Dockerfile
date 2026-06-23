ARG SERVICE_VERSION=${SERVICE_VERSION:-v1.11.0}
FROM docker.elastic.co/package-registry/package-registry:${SERVICE_VERSION}

COPY packages /packages
COPY config.yml /package-registry/config.yml
