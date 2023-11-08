ARG SERVICE_VERSION=${SERVICE_VERSION:-3.5.1}
FROM bitnami/etcd:${SERVICE_VERSION}
HEALTHCHECK --interval=15s --retries=90 CMD curl -f http://localhost:2379/metrics