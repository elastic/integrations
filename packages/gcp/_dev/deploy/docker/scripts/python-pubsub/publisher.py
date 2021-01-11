#!/usr/bin/env python

from google.cloud import pubsub_v1

class EmulatorCreds(object):
    @staticmethod
    def create_scoped_required():
        return False


def publish_messages(project_id, topic_id):
    publisher = pubsub_v1.PublisherClient(
        credentials=EmulatorCreds(),
    )
    topic_path = publisher.topic_path(project_id, topic_id)

    file = open(f"/sample_logs/{topic_id}.log", 'r') 
    
    for line in file.readlines():
        data = line.strip().encode("utf-8")

        _ = publisher.publish(topic_path, data)

    print(f"Published messages to {topic_path}.")


def create_topic(project_id, topic_id):
    publisher = pubsub_v1.PublisherClient(
        credentials=EmulatorCreds(),
    )
    topic_path = publisher.topic_path(project_id, topic_id)

    topic = publisher.create_topic(request={"name": topic_path})

    print("Created topic: {}".format(topic.name))


def create_subscription(project_id, topic_id, subscription_id):
    publisher = pubsub_v1.PublisherClient(
        credentials=EmulatorCreds(),
    )
    subscriber = pubsub_v1.SubscriberClient(
        credentials=EmulatorCreds(),
    )
    topic_path = publisher.topic_path(project_id, topic_id)
    subscription_path = subscriber.subscription_path(project_id, subscription_id)

    with subscriber:
        subscription = subscriber.create_subscription(
            request={"name": subscription_path, "topic": topic_path}
        )

    print(f"Subscription created: {subscription}")


if __name__ == "__main__":
    topics = ["audit", "firewall", "vpcflow"]

    for topic in topics:
        print("Creating topic: {}".format(topic))
        create_topic("system-tests", topic)
        
        subscription = f"{topic}-sub"
        print("Creating subscription: {}".format(subscription))
        create_subscription("system-tests", topic, subscription)
        
        print("Publishing messages")
        publish_messages("system-tests", topic)
