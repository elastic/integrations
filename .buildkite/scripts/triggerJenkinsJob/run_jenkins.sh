#!/bin/bash

    # -it \
    # --entrypoint /bin/bash \

if ! docker volume ls | grep -q  jenkins-home ; then
    echo "Create volume"
    docker volume create jenkins-home
fi

docker run \
    --name jenkins \
    --rm  \
    --user 1000:1000 \
    -p 8081:8080 \
    -p 50000:50000 \
    -v jenkins-home:/var/jenkins_home \
    jenkins/jenkins:2.346.3
