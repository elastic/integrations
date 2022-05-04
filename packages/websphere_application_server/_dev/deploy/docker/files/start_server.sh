#!/bin/bash
PROFILE_NAME=${PROFILE_NAME:-"AppSrv01"}
SERVER_NAME=${SERVER_NAME:-"server1"}
/work/set_password.sh
echo "Starting server ..................."
/opt/IBM/WebSphere/AppServer/profiles/$PROFILE_NAME/bin/startServer.sh $SERVER_NAME
wsadmin.sh -lang jython -user wsadmin -password Welcome1 -f /home/scripts/init.jython
chmod -R a+w /opt/IBM/WebSphere/AppServer/profiles/AppSrv01/logs/server1
tail -f dev/null