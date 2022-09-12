ARG SERVICE_VERSION=${SERVICE_VERSION:-2.4.0}
FROM influxdb:${SERVICE_VERSION}
# RUN sed -i "/jessie-updates/d" /etc/apt/sources.list
# RUN apt-get update && apt-get install -y curl
COPY ./influxdb.conf /var/lib/influxdb2/influxdb.conf
#COPY ./influxdb.conf /etc/influxdb2/influx-configs
COPY ./config.yml /etc/influxdb2/config.yml
HEALTHCHECK --interval=15s --retries=90 CMD curl -f http://localhost:8086/metrics
