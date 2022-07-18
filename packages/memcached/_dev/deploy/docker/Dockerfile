ARG MEMCACHED_VERSION=${MEMCACHED_VERSION:-1.6.15}
FROM memcached:${MEMCACHED_VERSION}-alpine

USER root
RUN apk update
RUN apk add netcat-openbsd
USER memcache

HEALTHCHECK --interval=1s --retries=90 CMD nc -z localhost 11211
