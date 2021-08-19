ARG SERVICE_VERSION=${SERVICE_VERSION:-4.4.8}
FROM mongo:${SERVICE_VERSION}
HEALTHCHECK --interval=1s --retries=90 \
  CMD echo 'db.runCommand({serverStatus:1}).ok' | mongo
