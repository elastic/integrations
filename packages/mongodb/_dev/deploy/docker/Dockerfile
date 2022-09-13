ARG SERVICE_VERSION=${SERVICE_VERSION:-5.0}
FROM mongo:${SERVICE_VERSION}
RUN sed -i "/jessie-updates/d" /etc/apt/sources.list
RUN apt-get update && apt-get install -y netcat
COPY init.js .
COPY adduser.js .
HEALTHCHECK --interval=1s --retries=90 \
  CMD echo 'db.runCommand({serverStatus:1}).ok' | mongosh

COPY entrypoint.sh ./test-entrypoint.sh

RUN sh ./test-entrypoint.sh