#!bin/bash

mongo mongodb://localhost:27017 init.js
sleep 30 | echo Sleeping1
mongo mongodb://localhost:27017 adduser.js #adding the user with clusterMonitor role
sleep 30 | echo Sleeping2
