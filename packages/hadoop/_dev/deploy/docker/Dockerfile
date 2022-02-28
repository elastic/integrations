ARG SERVICE_VERSION=${SERVICE_VERSION:-3}
FROM apache/hadoop:${SERVICE_VERSION}

ENV JOLOKIA_VERSION=1.6.0 JOLOKIA_ENABLED='yes' JOLOKIA_HOST=0.0.0.0
RUN wget "http://search.maven.org/remotecontent?filepath=org/jolokia/jolokia-jvm/${JOLOKIA_VERSION}/jolokia-jvm-${JOLOKIA_VERSION}-agent.jar" -O "jolokia-jvm-${JOLOKIA_VERSION}-agent.jar"

USER root
RUN sudo yum -y install openssh-server openssh-clients
ADD ssh/config /root/.ssh/config
RUN sudo /etc/ssh start

ADD conf/*.xml /opt/hadoop/etc/hadoop/

ENV HADOOP_HOME=/opt/hadoop

ADD ./entrypoint.sh /entrypoint.sh
RUN sudo chmod 755 /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
