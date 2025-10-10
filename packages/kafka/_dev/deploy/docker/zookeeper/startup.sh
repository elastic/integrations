#!/bin/bash

# --- Utility Functions ---

# Waits for a specified port to become available on localhost.
wait_for_port() {
    count=20
    port=$1
    echo "Waiting for port ${port} to become available..."
    while ! nc -z localhost $port && [[ $count -ne 0 ]]; do
        count=$(( $count - 1 ))
        # If the count reaches 0, exit with an error.
        [[ $count -eq 0 ]] && echo "Error: Port ${port} did not become available." && return 1
        sleep 0.5
    done
    echo "Port ${port} is now available."
    nc -z localhost $port
}

echo "Starting ZooKeeper"
${KAFKA_HOME}/bin/zookeeper-server-start.sh ${KAFKA_HOME}/config/zookeeper.properties &
wait_for_port 2181

# --- Kafka Setup ---

KAFKA_CLUSTER_ID="_ABcDEf1gHiJkLmNoPqRsT"

echo "Formatting storage directory..."
# Format the storage directory. This is a one-time operation for a new cluster.
# The --ignore-formatted flag prevents errors if it's already formatted.
${KAFKA_HOME}/bin/kafka-storage.sh format \
    --config ${KAFKA_HOME}/config/server_custom.properties \
    --cluster-id $KAFKA_CLUSTER_ID \
    --ignore-formatted

echo "Starting Kafka broker..."

export KAFKA_OPTS="-javaagent:/opt/jolokia-jvm-agent.jar=port=8780,host=0.0.0.0"

${KAFKA_HOME}/bin/kafka-server-start.sh ${KAFKA_HOME}/config/server_custom.properties &
# Store the Process ID (PID) of the Kafka server
kafka_pid=$!

# Wait for the Kafka broker and Jolokia agent ports to be available.
wait_for_port 9092
wait_for_port 8780

echo "Kafka broker started successfully."

echo "Creating 'test' topic..."
KAFKA_OPTS="" ${KAFKA_HOME}/bin/kafka-topics.sh --bootstrap-server localhost:9092 --create --if-not-exists --topic my-topic --partitions 1 --replication-factor 1

# --- Start Producer and Consumer ---

echo "Starting producer with Jolokia on port 8775..."
export KAFKA_OPTS="-javaagent:/opt/jolokia-jvm-agent.jar=port=8775,host=0.0.0.0"
(while true; do echo "Test msg"; sleep 5; done) | \
${KAFKA_HOME}/bin/kafka-console-producer.sh \
  --bootstrap-server localhost:9092 \
  --topic my-topic &

echo "Starting consumer with Jolokia on port 8774..."
export KAFKA_OPTS="-javaagent:/opt/jolokia-jvm-agent.jar=port=8774,host=0.0.0.0"
${KAFKA_HOME}/bin/kafka-console-consumer.sh \
  --bootstrap-server localhost:9092 \
  --topic my-topic \
  --from-beginning &

# --- Keep Container Running ---
echo "Kafka setup complete. The container will now run in the background."

# The 'wait' command blocks the script until the Kafka server process (kafka_pid) exits.
# This keeps the container running.
wait $kafka_pid