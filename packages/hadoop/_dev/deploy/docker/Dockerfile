FROM centos:latest
ARG SERVICE_VERSION=${SERVICE_VERSION:-3.3.1}
ARG HADOOP_VERSION=${SERVICE_VERSION} 

ARG JAVA_VERSION=8
ARG JAVA_RELEASE=JDK

RUN set -eux && \
    pkg="java-1.$JAVA_VERSION.0-openjdk" && \
    if [ "$JAVA_RELEASE" = "JDK" ]; then \
        pkg="$pkg-devel"; \
    else \
        pkg="$pkg-headless"; \
    fi; \
    yum install -y "$pkg" && \
    yum clean all && \
    rm -rf /var/cache/yum

COPY profile.d/java.sh /etc/profile.d/

ENV JAVA_HOME=/usr

ARG TAR=hadoop-$HADOOP_VERSION.tar.gz

ENV PATH $PATH:/hadoop/bin

LABEL Description="Hadoop Dev" \
      "Hadoop Version"="$HADOOP_VERSION"

WORKDIR /

RUN set -eux && \
    yum install -y openssh-server openssh-clients tar which

ENV JOLOKIA_VERSION=1.6.0 JOLOKIA_HOST=0.0.0.0 JOLOKIA_PORT=7778
ENV HADOOP_LATEST_VERSION=${SERVICE_VERSION} 

RUN set -eux && \
    yum install -y wget hostname && \

    wget "http://search.maven.org/remotecontent?filepath=org/jolokia/jolokia-jvm/${JOLOKIA_VERSION}/jolokia-jvm-${JOLOKIA_VERSION}-agent.jar" -O "jolokia-jvm-${JOLOKIA_VERSION}-agent.jar" && \
    wget -t 10 --max-redirect 1 --retry-connrefused -O "$TAR" "http://www.apache.org/dyn/closer.lua?filename=hadoop/common/hadoop-${HADOOP_VERSION}/hadoop-$HADOOP_VERSION.tar.gz&action=download" || \
    wget -t 10 --max-redirect 1 --retry-connrefused -O "$TAR" "http://archive.apache.org/dist/hadoop/common/hadoop-${HADOOP_VERSION}/hadoop-$HADOOP_VERSION.tar.gz" && \
    tar zxf "$TAR" && \

    test -d "hadoop-$HADOOP_VERSION" && \
    ln -sv "hadoop-$HADOOP_VERSION" hadoop && \
    mkdir /etc/hadoop && \
    ln -s /hadoop/etc/hadoop /etc/hadoop/conf && \
    rm -fv "$TAR" && \
    { rm -rf hadoop/share/doc; : ; } && \
    yum autoremove -y && \
    # gets autoremoved, ensure it's added back as Hadoop scripts need it
    yum install -y hostname && \
    yum clean all && \
    rm -rf /var/cache/yum

ENV JMX_REMOTE=yes JOLOKIA_ENABLED=yes

COPY entrypoint.sh /
COPY conf/core-site.xml /hadoop/etc/hadoop/
COPY conf/hdfs-site.xml /hadoop/etc/hadoop/
COPY conf/yarn-site.xml /hadoop/etc/hadoop/
COPY conf/mapred-site.xml /hadoop/etc/hadoop/
COPY profile.d/hadoop.sh /etc/profile.d/
COPY ssh/config /root/.ssh/


RUN set -eux && \
    /hadoop/bin/hdfs namenode -format && \
    groupadd hadoop && \
    useradd -g hadoop hdfs && \
    useradd -g hadoop yarn && \
    mkdir -p /dfs/name && \
    mkdir -p /dfs/data && \
    mkdir -p /hadoop/logs && \
    chown -R hdfs:hadoop /dfs/name && \
    chown -R hdfs:hadoop /dfs/data && \
    chgrp -R hadoop /hadoop/logs && \
    chmod -R 0770 /hadoop/logs && \
    mkdir -p /root/.ssh \
          /home/hdfs/.ssh \
          /home/yarn/.ssh && \
    chown hdfs /home/hdfs/.ssh && \
    chown yarn /home/yarn/.ssh && \
    chmod 0700 /root/.ssh \
               /home/hdfs/.ssh \
               /home/yarn/.ssh

ENV HDFS_NAMENODE_USER=hdfs
ENV HDFS_SECONDARYNAMENODE_USER=hdfs
ENV HDFS_DATANODE_USER=hdfs
ENV YARN_RESOURCEMANAGER_USER=yarn
ENV YARN_NODEMANAGER_USER=yarn



RUN rm -rf /run/nologin
RUN chmod -R 600 /etc/crypto-policies/
CMD ["bash","/entrypoint.sh"]