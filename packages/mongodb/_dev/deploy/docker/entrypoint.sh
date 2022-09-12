#!bin/bash

touch var/log/mongodb/mongod.log

chown mongodb:mongodb var/log/mongodb/mongod.log

chmod a+wx var/log/mongodb
chmod a+r -R var/log/mongodb