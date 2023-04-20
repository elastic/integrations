ARG SERVICE_VERSION=${SERVICE_VERSION:-2.4.0}
FROM influxdb:${SERVICE_VERSION}
COPY ./influxdb.conf /var/lib/influxdb2/influxdb.conf
COPY ./config.yml /etc/influxdb2/config.yml
HEALTHCHECK --interval=15s --retries=90 CMD curl -f http://localhost:8086/metrics