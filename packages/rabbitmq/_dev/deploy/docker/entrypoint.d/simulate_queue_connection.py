import os

import pika
import time
import socket

# Name of the test queue to use
QUEUE_NAME = "test-queue"
# Hostname where RabbitMQ is running
RABBITMQ_HOST = "localhost"
RABBITMQ_USER = os.getenv("RABBITMQ_USER", "guest")  # default if not set
RABBITMQ_PASS = os.getenv("RABBITMQ_PASS", "guest")

# Wait for RabbitMQ to be ready before connecting

def wait_for_rabbitmq(host, port, timeout=60):
    """
    Wait until a TCP connection to the given host/port can be established.
    Raises RuntimeError if timeout is exceeded.
    """
    start = time.time()
    while True:
        try:
            s = socket.create_connection((host, port), 2)
            s.close()
            return
        except Exception:
            if time.time() - start > timeout:
                raise RuntimeError("Timed out waiting for RabbitMQ")
            print("Waiting for RabbitMQ to be ready...")
            time.sleep(2)

# Wait for RabbitMQ server to be ready before proceeding
wait_for_rabbitmq(RABBITMQ_HOST, 5672)

# Establish connection with connection_attempts and retry_delay
credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
parameters = pika.ConnectionParameters(
    RABBITMQ_HOST,
    5672,
    '/',
    credentials,
    connection_attempts=5,
    retry_delay=3,
    socket_timeout=5
)
connection = pika.BlockingConnection(parameters)
channel = connection.channel()

# Declare queue
channel.queue_declare(queue=QUEUE_NAME, durable=True)
# Print confirmation that the queue was declared
print("Declared queue: {}".format(QUEUE_NAME))

# Publish 100 test messages to the queue, one per second
for i in range(1, 101):
    message = "Test message {}".format(i)  # Create the message string
    # Publish the message to the default exchange with the queue as the routing key
    channel.basic_publish(exchange='', routing_key=QUEUE_NAME, body=message)
    print("Published: {}".format(message))  # Print confirmation of published message
    time.sleep(1)  # Wait 1 second between messages

# Print that the script is about to start consuming messages
print("Consuming messages from the queue...")

def callback(ch, method, properties, body):
    # Callback function to process each received message
    print("Received: {}".format(body.decode()))  # Print the received message
    # Simulate message processing time
    time.sleep(1)
    # Acknowledge the message so it is removed from the queue
    ch.basic_ack(delivery_tag=method.delivery_tag)

# Start consuming messages from the queue using the callback function
debug_consume = channel.basic_consume(queue=QUEUE_NAME, on_message_callback=callback)
try:
    # Enter a loop that waits for and processes messages
    channel.start_consuming()
except KeyboardInterrupt:
    # Handle Ctrl+C gracefully
    print("Stopped consuming.")
finally:
    # Always close the connection when done
    connection.close()
