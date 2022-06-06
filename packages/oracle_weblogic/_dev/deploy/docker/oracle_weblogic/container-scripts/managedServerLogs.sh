#!/bin/bash
mkdir -p /u01/oracle/user_projects/domains/domain1/elasticlogs/managedserver
sleep 1m
cp /u01/oracle/user_projects/domains/domain1/servers/managed-server1/logs/managed-server1.log /u01/oracle/user_projects/domains/domain1/elasticlogs/managedserver -f
chmod a+rw -R /u01/oracle/user_projects/domains/domain1/elasticlogs
