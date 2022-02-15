FROM ubuntu:latest
ARG SERVICE_VERSION=${SERVICE_VERSION:-3.3.1}
ARG HADOOP_VERSION=${SERVICE_VERSION} 
ENV HADOOP_VERSION_LATEST=${HADOOP_VERSION} 

ARG JAVA_VERSION=8
ARG JAVA_RELEASE=JDK
ENV HADOOP_HOME /opt/hadoop
ENV JAVA_HOME /usr/lib/jvm/java-8-openjdk-amd64

RUN \
  apt-get update && apt-get install -y \
  ssh \
  rsync \
  vim \
  openjdk-8-jdk

ENV JOLOKIA_VERSION=1.6.0 JOLOKIA_HOST=0.0.0.0 JOLOKIA_ENABLED='yes'  

RUN \
  wget "http://search.maven.org/remotecontent?filepath=org/jolokia/jolokia-jvm/${JOLOKIA_VERSION}/jolokia-jvm-${JOLOKIA_VERSION}-agent.jar" -O "jolokia-jvm-${JOLOKIA_VERSION}-agent.jar" && \
  wget "http://archive.apache.org/dist/hadoop/common/hadoop-${HADOOP_VERSION}/hadoop-$HADOOP_VERSION.tar.gz" || \
  ls && \
  tar -xzf "hadoop-${HADOOP_VERSION}.tar.gz" && \
  mv hadoop-${HADOOP_VERSION} $HADOOP_HOME && \
  echo "export JAVA_HOME=$JAVA_HOME" >> $HADOOP_HOME/etc/hadoop/hadoop-env.sh && \
  echo "PATH=$PATH:$HADOOP_HOME/bin" >> ~/.bashrc

ADD conf/*.xml $HADOOP_HOME/etc/hadoop/
ADD ssh/config /root/.ssh/config

RUN \
  ssh-keygen -t rsa -P '' -f ~/.ssh/id_rsa && \
  cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys && \
  chmod 0600 ~/.ssh/authorized_keys

ENV HDFS_NAMENODE_USER="root"
ENV HDFS_DATANODE_USER="root"
ENV HDFS_SECONDARYNAMENODE_USER="root"
ENV YARN_RESOURCEMANAGER_USER="root"
ENV YARN_NODEMANAGER_USER="root"

ADD entrypoint.sh entrypoint.sh
CMD bash entrypoint.sh