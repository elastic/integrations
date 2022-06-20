#!/bin/bash
mkdir -p /u01/oracle/user_projects/domains/domain1/elasticlogs/adminserver/logs/
chmod a+rw -R /u01/oracle/user_projects/domains/domain1/elasticlogs
sleep 1m
cp /u01/oracle/user_projects/domains/domain1/servers/admin-server/domain1.log /u01/oracle/user_projects/domains/domain1/elasticlogs/adminserver -f
cp /u01/oracle/user_projects/domains/domain1/servers/admin-server/logs/access.log /u01/oracle/user_projects/domains/domain1/elasticlogs/adminserver/logs/ -f
cp /u01/oracle/user_projects/domains/domain1/servers/admin-server/logs/admin-server.log /u01/oracle/user_projects/domains/domain1/elasticlogs/adminserver/logs/ -f
chmod a+rw -R /u01/oracle/user_projects/domains/domain1/elasticlogs
