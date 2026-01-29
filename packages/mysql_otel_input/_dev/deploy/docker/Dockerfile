ARG SERVICE_VERSION=${SERVICE_VERSION:-8.0}
FROM mysql:$SERVICE_VERSION
HEALTHCHECK --interval=1s --timeout=5s --retries=90 CMD mysqladmin ping -h localhost -u root -psecret
