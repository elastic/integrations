set -euo pipefail
[ -n "${DEBUG:-}" ] && set -x

export JAVA_HOME="${JAVA_HOME:-/usr}"

export PATH="$PATH:/hadoop/sbin:/hadoop/bin"

if [ $# -gt 0 ]; then
    exec "$@"
else
    for x in root hdfs yarn; do
        if ! [ -f "$x/.ssh/id_rsa" ]; then
            su - "$x" <<-EOF
                [ -n "${DEBUG:-}" ] && set -x
                ssh-keygen -t rsa -f ~/.ssh/id_rsa -N ""
EOF
        fi
        if ! [ -f "$x/.ssh/authorized_keys" ]; then
            su - "$x" <<-EOF
                [ -n "${DEBUG:-}" ] && set -x
                cp -v ~/.ssh/id_rsa.pub ~/.ssh/authorized_keys
                chmod -v 0400 ~/.ssh/authorized_keys
EOF
        fi
    done

    # removed in newer versions of CentOS
    if ! [ -f /etc/ssh/ssh_host_rsa_key ] && [ -x /usr/sbin/sshd-keygen ]; then
        /usr/sbin/sshd-keygen || :
    fi
    if ! [ -f /etc/ssh/ssh_host_rsa_key ]; then
        ssh-keygen -q -t rsa -f /etc/ssh/ssh_host_rsa_key -C '' -N ''
        chmod 0600 /etc/ssh/ssh_host_rsa_key
        chmod 0644 /etc/ssh/ssh_host_rsa_key.pub
    fi

    if ! pgrep -x sshd &>/dev/null; then
        /usr/sbin/sshd
    fi
    echo
    SECONDS=0
    while true; do
        if ssh-keyscan localhost 2>&1 | grep -q OpenSSH; then
            echo "SSH is ready to rock"
            break
        fi
        if [ "$SECONDS" -gt 20 ]; then
            echo "FAILED: SSH failed to come up after 20 secs"
            exit 1
        fi
        echo "waiting for SSH to come up"
        sleep 1
    done
    echo
    if ! [ -f /root/.ssh/known_hosts ]; then
        ssh-keyscan localhost || :
        ssh-keyscan 0.0.0.0   || :
    fi | tee -a /root/.ssh/known_hosts
    hostname="$(hostname -f)"
    if ! grep -q "$hostname" /root/.ssh/known_hosts; then
        ssh-keyscan "$hostname" || :
    fi | tee -a /root/.ssh/known_hosts

    mkdir -pv /hadoop/logs


if [ "$JOLOKIA_ENABLED" = 'yes' ]; then

	echo "export HDFS_NAMENODE_OPTS="-javaagent\:`echo /jolokia-jvm-${JOLOKIA_VERSION}-agent.jar=host=${JOLOKIA_HOST},port=7777`"" >> "/hadoop-${HADOOP_LATEST_VERSION}/etc/hadoop/hadoop-env.sh"
    echo "export HDFS_DATANODE_OPTS="-javaagent\:`echo /jolokia-jvm-${JOLOKIA_VERSION}-agent.jar=host=${JOLOKIA_HOST},port=7779`"" >> "/hadoop-${HADOOP_LATEST_VERSION}/etc/hadoop/hadoop-env.sh"
    echo "export YARN_NODEMANAGER_OPTS="-javaagent\:`echo /jolokia-jvm-${JOLOKIA_VERSION}-agent.jar=host=${JOLOKIA_HOST},port=7782`"" >> "/${HADOOP_LATEST_VERSION}/etc/hadoop/hadoop-env.sh"
    echo "export YARN_RESOURCEMANAGER_OPTS="-javaagent\:`echo /jolokia-jvm-${JOLOKIA_VERSION}-agent.jar=host=${JOLOKIA_HOST},port=7781`"" >> "/${HADOOP_LATEST_VERSION}/etc/hadoop/hadoop-env.sh"
   
fi

    sed -i "s/localhost/$hostname/" /hadoop/etc/hadoop/core-site.xml
    echo 'Y' | hdfs namenode -format
    start-dfs.sh
    start-yarn.sh

    hdfs dfs -mkdir -p /user/root/input
    hdfs dfs -put /hadoop-${HADOOP_LATEST_VERSION}/LICENSE.txt /user/root/input/
    hadoop jar /hadoop-${HADOOP_LATEST_VERSION}/share/hadoop/mapreduce/hadoop-mapreduce-examples-${HADOOP_LATEST_VERSION}.jar wordcount input output
  
    tail -f /dev/null /hadoop/logs/*
    stop-yarn.sh
    stop-dfs.sh
fi