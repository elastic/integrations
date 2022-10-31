FROM openjdk:11-jre

ARG SERVICE_VERSION=${SERVICE_VERSION:-5.17.1}
ENV ACTIVEMQ_VERSION=${SERVICE_VERSION}

ENV ACTIVEMQ_HOME /opt/activemq
ENV ACTIVEMQ apache-activemq-$ACTIVEMQ_VERSION
ENV ACTIVEMQ_STOMP=61613 ACTIVEMQ_REST=8161

RUN set -x && \
    mkdir -p /opt && \
    apt-get update && \
    apt-get install netcat-openbsd -y

RUN curl --fail https://archive.apache.org/dist/activemq/$ACTIVEMQ_VERSION/$ACTIVEMQ-bin.tar.gz -o $ACTIVEMQ-bin.tar.gz

RUN tar xvzf $ACTIVEMQ-bin.tar.gz -C  /opt && \
    ln -s /opt/$ACTIVEMQ $ACTIVEMQ_HOME && \
    rm $ACTIVEMQ-bin.tar.gz

WORKDIR $ACTIVEMQ_HOME

COPY entrypoint.d/ entrypoint.d/

RUN chmod -R 777 ./entrypoint.d/entrypoint.sh

WORKDIR $ACTIVEMQ_HOME

EXPOSE $ACTIVEMQ_STOMP $ACTIVEMQ_REST

HEALTHCHECK --interval=1s --retries=90 CMD nc -w 1 -v 127.0.0.1 $ACTIVEMQ_STOMP </dev/null && \
    nc -w 1 -v 127.0.0.1 $ACTIVEMQ_REST </dev/null

CMD ["/bin/sh", "-c", "bin/activemq console & ./entrypoint.d/entrypoint.sh"]