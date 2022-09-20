ARG SERVICE_VERSION=${SERVICE_VERSION:-2.4.0}
FROM influxdb:${SERVICE_VERSION}
HEALTHCHECK --interval=15s --retries=90 CMD curl -f http://localhost:8086/metrics
