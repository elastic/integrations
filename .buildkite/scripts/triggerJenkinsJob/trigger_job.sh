#!/bin/bash

export JENKINS_TOKEN=11c7b833b6ad3ed0328b80a0317774760f
export JENKINS_HOST_SECRET="http://localhost:8081"
export JENKINS_USERNAME_SECRET="admin"

go run main.go -jenkins-job test -retries 20 -waiting-time 5s -growth-factor 1.25 -max-waiting-time 60m

exit 0

CRUMB=$(curl -u "admin:admin" \
    -s 'http://localhost:8081/crumbIssuer/api/xml?xpath=concat(//crumbRequestField,":",//crumb)')

curl -v \
    -H "$CRUMB" \
    -XPOST \
    -u "${JENKINS_USERNAME_SECRET}:${JENKINS_TOKEN}" \
    "${JENKINS_HOST_SECRET}/job/test-job/buildWithParameters?dry_run=true&test=aaab"

exit 0
