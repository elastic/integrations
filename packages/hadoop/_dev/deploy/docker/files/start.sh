#! /bin/sh
sudo -i -u root bash << EOF
/usr/sbin/sshd -D &
EOF
sudo -i -u hadoop bash << EOF
/opt/hadoop/sbin/start-dfs.sh
/opt/hadoop/sbin/start-yarn.sh
/opt/hadoop/bin/mapred --daemon start historyserver
/opt/hadoop/bin/hadoop fs -mkdir -p /user/input
/opt/hadoop/bin/hadoop fs -put /opt/hadoop/start.sh /user/input
/opt/hadoop/bin/hadoop jar wordcount.jar WordCount /user/input /user/output
tail -F /opt/hadoop/start.sh
EOF
exec "$@"