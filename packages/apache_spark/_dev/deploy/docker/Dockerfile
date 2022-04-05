ARG SERVICE_VERSION=${SERVICE_VERSION:-3.2.0}
FROM docker.io/bitnami/spark:${SERVICE_VERSION}

ENV JOLOKIA_VERSION=1.6.0 SPARK_MAIN_URL=spark://apache-spark-main:7077 SPARK_RPC_AUTHENTICATION_ENABLED=no SPARK_RPC_ENCRYPTION_ENABLED=no SPARK_LOCAL_STORAGE_ENCRYPTION_ENABLED=no SPARK_SSL_ENABLED=no SPARK_WORKER_MEMORY=1024G SPARK_WORKER_CORES=8
USER root

COPY jolokia-configs /spark/conf/
RUN mkdir /usr/share/java && \
    curl -o /usr/share/java/jolokia-agent.jar https://repo1.maven.org/maven2/org/jolokia/jolokia-jvm/$JOLOKIA_VERSION/jolokia-jvm-$JOLOKIA_VERSION-agent.jar && \
    echo 'export SPARK_MASTER_OPTS="$SPARK_MASTER_OPTS -javaagent:/usr/share/java/jolokia-agent.jar=config=/spark/conf/jolokia-master.properties"' >> "/opt/bitnami/spark/conf/spark-env.sh" && \
    echo 'export SPARK_WORKER_OPTS="$SPARK_WORKER_OPTS -javaagent:/usr/share/java/jolokia-agent.jar=config=/spark/conf/jolokia-worker.properties"' >> "/opt/bitnami/spark/conf/spark-env.sh" 

RUN echo '*.sink.jmx.class=org.apache.spark.metrics.sink.JmxSink' >> "/opt/bitnami/spark/conf/metrics.properties" && \
    echo '*.source.jvm.class=org.apache.spark.metrics.source.JvmSource' >> "/opt/bitnami/spark/conf/metrics.properties"

RUN echo 'spark.driver.extraJavaOptions   -javaagent:/usr/share/java/jolokia-agent.jar=config=/spark/conf/jolokia-driver.properties' >> "/opt/bitnami/spark/conf/spark-defaults.conf" 

WORKDIR /opt/bitnami/spark/examples/src/main/python/
COPY wordcount.py /opt/bitnami/spark/examples/src/main/python
COPY docker-entrypoint /docker-entrypoint/
RUN chmod 755 /docker-entrypoint/docker-entrypoint.sh
ENTRYPOINT ["/docker-entrypoint/docker-entrypoint.sh","/opt/bitnami/scripts/spark/run.sh"]
HEALTHCHECK --interval=1s --retries=90 CMD curl -f -s http://localhost:7777/jolokia/version
