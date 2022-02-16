/etc/init.d/ssh start

$HADOOP_HOME/bin/hdfs namenode -format

if [ "$JOLOKIA_ENABLED" = 'yes' ]; then
    echo "export HDFS_NAMENODE_OPTS="-javaagent\:`echo /jolokia-jvm-${JOLOKIA_VERSION}-agent.jar=host=${JOLOKIA_HOST},port=7777`"" >> "${HADOOP_HOME}/etc/hadoop/hadoop-env.sh"
    echo "export HDFS_DATANODE_OPTS="-javaagent\:`echo /jolokia-jvm-${JOLOKIA_VERSION}-agent.jar=host=${JOLOKIA_HOST},port=7779`"" >> "${HADOOP_HOME}/etc/hadoop/hadoop-env.sh"
    echo "export YARN_NODEMANAGER_OPTS="-javaagent\:`echo /jolokia-jvm-${JOLOKIA_VERSION}-agent.jar=host=${JOLOKIA_HOST},port=9010`"" >> "${HADOOP_HOME}/etc/hadoop/hadoop-env.sh"
    echo "export YARN_RESOURCEMANAGER_OPTS="-javaagent\:`echo /jolokia-jvm-${JOLOKIA_VERSION}-agent.jar=host=${JOLOKIA_HOST},port=9011`"" >> "${HADOOP_HOME}/etc/hadoop/hadoop-env.sh"
fi

$HADOOP_HOME/sbin/start-dfs.sh
$HADOOP_HOME/sbin/start-yarn.sh
$HADOOP_HOME/bin/hdfs dfs -mkdir -p /user/root/input
$HADOOP_HOME/bin/hdfs dfs -put /opt/hadoop/LICENSE.txt /user/root/input/
$HADOOP_HOME/bin/hadoop jar /opt/hadoop/share/hadoop/mapreduce/hadoop-mapreduce-examples-${HADOOP_VERSION_LATEST}.jar wordcount input output

$HADOOP_HOME/sbin/mr-jobhistory-daemon.sh start historyserver

tail -f /dev/null