ARG SERVICE_VERSION=${SERVICE_VERSION:-5.0}
FROM mongo:${SERVICE_VERSION}
RUN sed -i "/jessie-updates/d" /etc/apt/sources.list
RUN apt-get update && apt-get install -y netcat
HEALTHCHECK --interval=1s --retries=90 CMD nc -z localhost 27017