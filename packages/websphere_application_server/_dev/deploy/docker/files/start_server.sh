#!/bin/bash
PROFILE_NAME=${PROFILE_NAME:-"AppSrv01"}
SERVER_NAME=${SERVER_NAME:-"server1"}
/work/set_password.sh
echo "Starting server ..................."
/opt/IBM/WebSphere/AppServer/profiles/$PROFILE_NAME/bin/startServer.sh $SERVER_NAME
yes | wsadmin.sh -lang jython -user wsadmin -password Welcome1 -f /home/scripts/init.jython
tail -f dev/null