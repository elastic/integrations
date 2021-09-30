ARG SERVICE_VERSION=${SERVICE_VERSION:-3.11.11}
FROM cassandra:${SERVICE_VERSION}

ENV JOLOKIA_VERSION=1.6.0 JOLOKIA_HOST=0.0.0.0 JOLOKIA_PORT=8778

RUN cp -f $JAVA_HOME/lib/management/jmxremote.access $JAVA_HOME/lib/management/jmxremote.access.bak \
   &&  chown root:cassandra $JAVA_HOME/lib/management/jmxremote.access* \
   &&  chmod 664 $JAVA_HOME/lib/management/jmxremote.access*

ENV CASSANDRA_LIB=/var/lib/cassandra

RUN set -eux; \
    savedAptMark="$(apt-mark showmanual)"; \
    apt-get update; \
    apt-get install -y --no-install-recommends wget \
    &&  wget http://search.maven.org/remotecontent?filepath=org/jolokia/jolokia-jvm/${JOLOKIA_VERSION}/jolokia-jvm-${JOLOKIA_VERSION}-agent.jar -O jolokia-jvm-${JOLOKIA_VERSION}-agent.jar

ENV JMX_REMOTE=yes JOLOKIA_ENABLED=yes

COPY docker-entrypoint-initdb.d /docker-entrypoint-initdb.d

ENTRYPOINT ["/docker-entrypoint-initdb.d/docker-entrypoint.sh"]

# 7000: intra-node communication
# 7001: TLS intra-node communication
# 7199: JMX
# 9042: CQL
# 9160: thrift service
# 8778: jolokia
EXPOSE 7000 7001 7199 9042 9160 8778
CMD ["cassandra", "-f"]