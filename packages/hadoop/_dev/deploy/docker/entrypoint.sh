#!/bin/bash
echo "export HDFS_NAMENODE_OPTS="-javaagent\:`echo /opt/hadoop/jolokia-jvm-${JOLOKIA_VERSION}-agent.jar=host=${JOLOKIA_HOST},port=7777`"" >> "/opt/hadoop/etc/hadoop/hadoop-env.sh"
echo "export HDFS_DATANODE_OPTS="-javaagent\:`echo /opt/hadoop/jolokia-jvm-${JOLOKIA_VERSION}-agent.jar=host=${JOLOKIA_HOST},port=7779`"" >> "/opt/hadoop/etc/hadoop/hadoop-env.sh"
echo "export YARN_NODEMANAGER_OPTS="-javaagent\:`echo /jolokia-jvm-${JOLOKIA_VERSION}-agent.jar=host=${JOLOKIA_HOST},port=7782`"" >> "/opt/hadoop/etc/hadoop/hadoop-env.sh"
echo "export YARN_RESOURCEMANAGER_OPTS="-javaagent\:`echo /jolokia-jvm-${JOLOKIA_VERSION}-agent.jar=host=${JOLOKIA_HOST},port=7781`"" >> "/opt/hadoop/etc/hadoop/hadoop-env.sh"
echo "export JAVA_HOME=$JAVA_HOME" >> /opt/hadoop/etc/hadoop/hadoop-env.sh
echo "export HDFS_NAMENODE_USER=root" >> /opt/hadoop/etc/hadoop/hadoop-env.sh
echo "export HDFS_DATANODE_USER=root" >> /opt/hadoop/etc/hadoop/hadoop-env.sh
echo "export HDFS_SECONDARYNAMENODE_USER=root" >> /opt/hadoop/etc/hadoop/hadoop-env.sh
echo "export YARN_RESOURCEMANAGER_USER=root" >> /opt/hadoop/etc/hadoop/hadoop-env.sh
echo "export YARN_NODEMANAGER_USER=root" >> /opt/hadoop/etc/hadoop/hadoop-env.sh

# sudo /etc/init.d/ssh start
sudo systemctl start sshd
sudo /opt/hadoop/bin/hdfs namenode
sudo /opt/hadoop/bin/hdfs namenode -format
sudo /opt/hadoop/sbin/start-dfs.sh
export PDSH_RCMD_TYPE=ssh
sudo /opt/hadoop/sbin/start-yarn.sh
sudo /opt/hadoop/bin/hdfs dfs -mkdir -p /user/root/input
sudo /opt/hadoop/bin/hdfs dfs -put /opt/hadoop/LICENSE.txt /user/root/input/
sudo /opt/hadoop/bin/hadoop jar /opt/hadoop/share/hadoop/mapreduce/hadoop-mapreduce-examples-3.3.1.jar wordcount input output
sudo /opt/hadoop/sbin/mr-jobhistory-daemon.sh start historyserver