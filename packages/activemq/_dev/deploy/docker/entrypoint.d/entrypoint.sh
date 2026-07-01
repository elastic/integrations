#!/bin/sh
# Install Jetty / Jolokia overrides that match the ActiveMQ major line before the broker starts.
case "${ACTIVEMQ_VERSION}" in
  5.*)
    cp /integration-templates/jetty-5.17.xml "${ACTIVEMQ_HOME}/conf/jetty.xml"
    cp /integration-templates/jolokia-5.17.xml "${ACTIVEMQ_HOME}/conf/jolokia-access.xml"
    ;;
  *)
    cp /integration-templates/jetty-6.2.xml "${ACTIVEMQ_HOME}/conf/jetty.xml"
    cp /integration-templates/jolokia-6.2.xml "${ACTIVEMQ_HOME}/conf/jolokia-access.xml"
    ;;
esac

# Whenever docker container is ran it will remove log files from SERVICE_LOGS_DIR, so to make them accessible again for the docker container to run system test,
# following commands will help to copy and accesses these files from SERVICE_LOGS_DIR again.
mkdir -p "${ACTIVEMQ_HOME}/logs"
cp /sample_logs/* "${ACTIVEMQ_HOME}/logs/" 2>/dev/null || true
chmod a+rw -R "${ACTIVEMQ_HOME}/logs/"

bin/activemq console &
sleep 10

while :
do
    curl -u admin:admin -d "body=message" http://localhost:8161/api/message/TEST?type=queue
    sleep 1
done
