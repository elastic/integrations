#!/bin/sh
$(elastic-package stack shellinit)
cd ./tychon
docker ps -aq | xargs docker stop | xargs docker rm
wait $!
docker container ls
