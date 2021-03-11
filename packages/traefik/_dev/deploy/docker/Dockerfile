ARG TRAEFIK_VERSION
FROM traefik:${TRAEFIK_VERSION}-alpine

COPY ./traefik.toml /etc/traefik/traefik.toml

RUN apk add --no-cache curl
HEALTHCHECK --interval=1s --retries=90 CMD curl --header 'Host:backend.elastic-package-service.docker.localhost' 'http://localhost:80/'
