#!/bin/sh
$(elastic-package stack shellinit)
cd ./tychon
docker-compose -f /root/.elastic-package/profiles/default/stack/snapshot_reg.yml -p elastic-package-stack up -d &
wait $!
docker container ls
