ARG SERVICE_VERSION=${SERVICE_VERSION:-3.4}
FROM mongo:${SERVICE_VERSION}
RUN sed -i "/jessie-updates/d" /etc/apt/sources.list
RUN apt-get update && apt-get install -y netcat
HEALTHCHECK --interval=1s --retries=90 \
  CMD echo 'db.runCommand({serverStatus:1}).ok' | mongo