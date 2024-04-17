#!/bin/bash

# Simulate hacking attempt to put some entries in the error log
mysql -u root -pbad_password -hlocalhost -P 3306 > /dev/null

set -e
mysql -u root -p$MYSQL_ROOT_PASSWORD -h$HOSTNAME -P 3306 -e "SHOW STATUS" > /dev/null