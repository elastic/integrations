#!/bin/sh
$(elastic-package stack shellinit)
cd ./tychon
docker-compose -f /root/.elastic-package/profiles/default/stack/snapshot_fl.yml up -d &
sleep 20
docker-compose -f /root/.elastic-package/profiles/default/stack/snapshot_ag.yml up -d &
wait $!
docker container ls
