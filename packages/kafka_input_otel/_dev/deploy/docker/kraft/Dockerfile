ARG KAFKA_VERSION=4.0.0

# Download jolokia JVM agent from Maven Central (no binary in repo)
FROM alpine:3.21 AS jolokia
RUN apk add --no-cache curl ca-certificates && \
    mkdir -p /opt/jolokia && \
    curl -sSL -o /opt/jolokia/jolokia-jvm.jar \
        "https://repo1.maven.org/maven2/org/jolokia/jolokia-agent-jvm/2.3.0/jolokia-agent-jvm-2.3.0-javaagent.jar"

FROM apache/kafka:${KAFKA_VERSION}

USER root

ENV KAFKA_NODE_ID=1
ENV KAFKA_PROCESS_ROLES="broker,controller"
ENV KAFKA_CONTROLLER_LISTENER_NAMES="CONTROLLER"
ENV KAFKA_LISTENERS="PLAINTEXT://:9092,CONTROLLER://:9093"
ENV KAFKA_ADVERTISED_LISTENERS="PLAINTEXT://localhost:9092"
ENV KAFKA_CONTROLLER_QUORUM_VOTERS="1@localhost:9093"
ENV KAFKA_LOG_DIRS="/tmp/kraft-combined-logs"
ENV KAFKA_JMX_PORT="9999"
ENV KAFKA_LISTENER_SECURITY_PROTOCOL_MAP="PLAINTEXT:PLAINTEXT,CONTROLLER:PLAINTEXT"
ENV KAFKA_JMX_OPTS="-Dcom.sun.management.jmxremote \
    -Dcom.sun.management.jmxremote.local.only=false \
    -Dcom.sun.management.jmxremote.authenticate=false \
    -Dcom.sun.management.jmxremote.ssl=false \
    -Djava.rmi.server.hostname=localhost \
    -Dcom.sun.management.jmxremote.port=${KAFKA_JMX_PORT:-9999} \
    -Dcom.sun.management.jmxremote.rmi.port=${KAFKA_JMX_PORT:-9999}"

# Copy jolokia agent from jolokia stage (downloaded from Maven Central)
COPY --from=jolokia /opt/jolokia/jolokia-jvm.jar /opt/jolokia/jolokia-jvm.jar

# Copy startup script
ADD startup.sh /opt/startup.sh
ADD healthcheck.sh /healthcheck.sh
ADD server.properties /opt/kafka/config/kraft/server_custom.properties
RUN chmod +x /opt/startup.sh /healthcheck.sh && chown -R 1001:0 /opt

USER 1001

ENTRYPOINT ["/opt/startup.sh"]