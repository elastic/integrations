ARG SERVICE_VERSION=${SERVICE_VERSION:-5.0}
FROM mongo:${SERVICE_VERSION}

HEALTHCHECK --interval=1s --retries=90 CMD mongosh --eval 'db.adminCommand("ping")' || mongo --eval 'db.adminCommand("ping")' || exit 1

