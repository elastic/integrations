#!/bin/bash

chmod a+wx /var/log/mysql

# Immitate the default (/var/lib/mysql/<hostname>-slow.log, but in the shared log directory).
cat << EOF > /etc/mysql/conf.d/slow-log.cnf
[mysqld]
slow-query-log=ON
slow-query-log-file=/var/log/mysql/$HOSTNAME-slow.log
long-query-time=0
EOF

exec bash /entrypoint.sh mysqld
