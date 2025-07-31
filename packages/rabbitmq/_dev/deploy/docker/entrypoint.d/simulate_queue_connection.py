import pika
import time

QUEUE_NAME = "test-queue"
RABBITMQ_HOST = "localhost"
RABBITMQ_USER = "guest"
RABBITMQ_PASS = "guest"

# Establish connection
credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
parameters = pika.ConnectionParameters(RABBITMQ_HOST, 5672, '/', credentials)
connection = pika.BlockingConnection(parameters)
channel = connection.channel()

# Declare queue
channel.queue_declare(queue=QUEUE_NAME, durable=True)
print(f"Declared queue: {QUEUE_NAME}")

# Publish messages
for i in range(1, 101):
    message = f"Test message {i}"
    channel.basic_publish(exchange='', routing_key=QUEUE_NAME, body=message)
    print(f"Published: {message}")
    time.sleep(1)

# Consume messages
print("Consuming messages from the queue...")
def callback(ch, method, properties, body):
    print(f"Received: {body.decode()}")
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

