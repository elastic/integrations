#!/bin/bash
set -e
set -x

source /opt/example_metric.sh

KAFKA_TOPIC="${KAFKA_TOPIC:-otlp_metrics}"
KAFKA_BROKER="${KAFKA_BROKER:-kafka_service:9092}"

# Create a topic for the producer and consumer
echo "Creating topic '${KAFKA_TOPIC}'..."
KAFKA_JMX_OPTS= /opt/kafka/bin/kafka-topics.sh \
  --bootstrap-server "$KAFKA_BROKER" --create \
  --if-not-exists \
  --topic "$KAFKA_TOPIC" \
  --partitions 1 \
  --replication-factor 1

echo "Creating topic '${KAFKA_TOPIC}-2'..."
KAFKA_JMX_OPTS= /opt/kafka/bin/kafka-topics.sh \
  --bootstrap-server "$KAFKA_BROKER" --create \
  --if-not-exists \
  --topic "$KAFKA_TOPIC-2" \
  --partitions 1 \
  --replication-factor 1


# Start the console producer in the background
echo "Starting producer with Jolokia on port 8775..."
export KAFKA_OPTS="-javaagent:/opt/jolokia/jolokia-jvm.jar=port=8775,host=0.0.0.0"
(while true; do  create_metric_document "example" ; sleep 5; done) | \
KAFKA_JMX_OPTS= /opt/kafka/bin/kafka-console-producer.sh \
  --bootstrap-server "$KAFKA_BROKER" \
  --topic "$KAFKA_TOPIC" &

echo "Starting producer with Jolokia on port 8776..."
export KAFKA_OPTS="-javaagent:/opt/jolokia/jolokia-jvm.jar=port=8776,host=0.0.0.0"
(while true; do create_metric_document "foo-bar" ; sleep 2; done) | \
KAFKA_JMX_OPTS= /opt/kafka/bin/kafka-console-producer.sh \
  --bootstrap-server "$KAFKA_BROKER" \
  --topic "$KAFKA_TOPIC-2" &


while true; do sleep 1; done
