import pika
import time
import socket

QUEUE_NAME = "test-queue"
RABBITMQ_HOST = "localhost"
RABBITMQ_USER = "guest"
RABBITMQ_PASS = "guest"

# Wait for RabbitMQ to be ready before connecting

def wait_for_rabbitmq(host, port, timeout=60):
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
print("Declared queue: {}".format(QUEUE_NAME))

# Publish messages
for i in range(1, 101):
    message = "Test message {}".format(i)
    channel.basic_publish(exchange='', routing_key=QUEUE_NAME, body=message)
    print("Published: {}".format(message))
    time.sleep(1)

# Consume messages
print("Consuming messages from the queue...")
def callback(ch, method, properties, body):
    print("Received: {}".format(body.decode()))
    # Simulate processing time
    time.sleep(1)
    ch.basic_ack(delivery_tag=method.delivery_tag)

channel.basic_consume(queue=QUEUE_NAME, on_message_callback=callback)
try:
    channel.start_consuming()
except KeyboardInterrupt:
    print("Stopped consuming.")
finally:
    connection.close()
