ARG SERVICE_VERSION=${SERVICE_VERSION:-3.2.0}
FROM docker.io/bitnami/spark:${SERVICE_VERSION}

ENV JOLOKIA_VERSION=1.6.0
USER root

COPY jolokia-configs /spark/conf/
RUN mkdir /usr/share/java && \
    curl -o /usr/share/java/jolokia-agent.jar https://repo1.maven.org/maven2/org/jolokia/jolokia-jvm/$JOLOKIA_VERSION/jolokia-jvm-$JOLOKIA_VERSION-agent.jar && \
    echo 'export SPARK_MASTER_OPTS="$SPARK_MASTER_OPTS -javaagent:/usr/share/java/jolokia-agent.jar=config=/spark/conf/jolokia-master.properties"' >> "/opt/bitnami/spark/conf/spark-env.sh" 

RUN echo '*.sink.jmx.class=org.apache.spark.metrics.sink.JmxSink' >> "/opt/bitnami/spark/conf/metrics.properties" && \
    echo '*.source.jvm.class=org.apache.spark.metrics.source.JvmSource' >> "/opt/bitnami/spark/conf/metrics.properties"

HEALTHCHECK --interval=1s --retries=90 CMD curl -f -s http://localhost:7777/jolokia/version
