#!/bin/bash

export JENKINS_TOKEN=11c7b833b6ad3ed0328b80a0317774760f
export JENKINS_HOST_SECRET="http://localhost:8081"
export JENKINS_USERNAME_SECRET="admin"

CRUMB=$(curl -u "admin:admin" \
    -s 'http://localhost:8081/crumbIssuer/api/xml?xpath=concat(//crumbRequestField,":",//crumb)')

curl -s \
    -H "$CRUMB" \
    -XPOST \
    -u "${JENKINS_USERNAME_SECRET}:${JENKINS_TOKEN}" \
    "${JENKINS_HOST_SECRET}/job/test-job/api/json" | jq -r '.inQueue'

exit 0
