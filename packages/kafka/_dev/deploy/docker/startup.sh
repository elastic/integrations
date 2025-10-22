#!/bin/bash
set -e

# --- 1. CONFIGURE AND START KAFKA BROKER ---

# Add Jolokia agent to the broker's JMX options
export KAFKA_JMX_OPTS="
  -Dcom.sun.management.jmxremote
  -Dcom.sun.management.jmxremote.local.only=false
  -Dcom.sun.management.jmxremote.authenticate=false
  -Dcom.sun.management.jmxremote.ssl=false
  -Djava.rmi.server.hostname=0.0.0.0
  -Dcom.sun.management.jmxremote.port=${KAFKA_JMX_PORT:-9999}
  -Dcom.sun.management.jmxremote.rmi.port=${KAFKA_JMX_PORT:-9999}
  -javaagent:/opt/jolokia/jolokia-jvm.jar=port=8780,host=0.0.0.0
"

LOG_DIR="/tmp/kraft-combined-logs"
META_FILE="$LOG_DIR/meta.properties"
CLUSTER_ID=${KAFKA_CLUSTER_ID:-"_ABcDEf1gHiJkLmNoPqRsT"} # Using a default Base64 ID

# Ensure log directory exists and has correct permissions
mkdir -p "$LOG_DIR"
chown -R 1001:0 "$LOG_DIR"

# Initialize storage if not formatted yet
if [ ! -f "$META_FILE" ]; then
  echo "Formatting KRaft storage with Cluster ID: $CLUSTER_ID"
  /opt/kafka/bin/kafka-storage.sh format -t "$CLUSTER_ID" -c /opt/kafka/config/kraft/server.properties
else
  echo "KRaft storage already formatted."
fi

# Start the Kafka server in the background
echo "Starting Kafka server..."
/opt/kafka/bin/kafka-server-start.sh /opt/kafka/config/kraft/server.properties &
# Store the Process ID (PID) of the Kafka server
kafka_pid=$!

# --- 2. WAIT FOR BROKER AND CREATE TOPIC ---

# Wait for the broker to become available on port 9092
echo "Waiting for Kafka broker to be ready..."
until KAFKA_JMX_OPTS= /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list > /dev/null 2>&1; do
  echo "Broker not ready yet, sleeping..."
  sleep 2
done
echo "Broker is ready!"

# Create a topic for the producer and consumer
echo "Creating topic 'my-topic'..."
KAFKA_JMX_OPTS= /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --create --if-not-exists --topic my-topic --partitions 1 --replication-factor 1

# --- 3. START PRODUCER AND CONSUMER ---

# Start the console producer in the background
echo "Starting producer with Jolokia on port 8775..."
export KAFKA_OPTS="-javaagent:/opt/jolokia/jolokia-jvm.jar=port=8775,host=0.0.0.0"
(while true; do echo "Test msg"; sleep 5; done) | \
KAFKA_JMX_OPTS= /opt/kafka/bin/kafka-console-producer.sh \
  --bootstrap-server localhost:9092 \
  --topic my-topic &

# Start the console consumer in the background
echo "Starting consumer with Jolokia on port 8774..."
export KAFKA_OPTS="-javaagent:/opt/jolokia/jolokia-jvm.jar=port=8774,host=0.0.0.0"
KAFKA_JMX_OPTS= /opt/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server localhost:9092 \
  --topic my-topic \
  --from-beginning &

# --- 4. WAIT FOR KAFKA SERVER TO EXIT ---
echo "Startup complete. All processes are running."
# The 'wait' command blocks the script until the Kafka server process (kafka_pid) exits.
# This keeps the container running.
wait $kafka_pid