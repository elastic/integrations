FROM apache/hadoop:3

COPY ./files/yml /opt/hadoop/etc/hadoop
COPY ./files/environment.sh environment.sh
COPY ./files/wordcount.jar wordcount.jar
COPY ./files/start.sh /opt/hadoop/start.sh
COPY ./files/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo

RUN sudo yum install openssh-server openssh-clients -y;\
    sudo ssh-keygen -t rsa -f /etc/ssh/ssh_host_rsa_key;\
    sudo ssh-keygen -t dsa -f /etc/ssh/ssh_host_dsa_key;\
    sudo ssh-keygen -t ecdsa -f /etc/ssh/ssh_host_ecdsa_key;\
    sudo ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key;\
    echo "/opt/hadoop/.ssh/id_rsa" | ssh-keygen -t rsa;\
    cat /opt/hadoop/.ssh/id_rsa.pub >> /opt/hadoop/.ssh/authorized_keys;\
    mkdir -p /opt/hadoop/hadoop_store/hdfs/namenode; \
    mkdir -p /opt/hadoop/hadoop_store/hdfs/datanode;\
    hdfs namenode -format -force;\
    cat environment.sh >> /opt/hadoop/etc/hadoop/hadoop-env.sh;\
    sudo chmod 0555 /opt/hadoop/start.sh


EXPOSE 8042 8088 9864 9870
ENTRYPOINT /opt/hadoop/start.sh
HEALTHCHECK --interval=1s --retries=90 CMD curl -f http://localhost:8042/jmx
