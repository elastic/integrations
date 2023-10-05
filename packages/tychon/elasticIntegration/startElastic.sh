#!/bin/sh
$(elastic-package stack shellinit)
cd ./tychon
docker-compose -f /root/.elastic-package/profiles/default/stack/snapshot_reg.yml up -d &
wait $!
docker-compose -f /root/.elastic-package/profiles/default/stack/snapshot_es.yml up -d &
wait $!
docker-compose -f /root/.elastic-package/profiles/default/stack/snapshot_kb.yml up -d &
wait $!
docker container ls
