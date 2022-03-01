# Custom Google PubSub Integration

The custom Google PubSub input integration is used to ingest data from a Google PubSub topic subscription.

This integration could for example be used to receive Stackdriver logs that have been exported to a Google Cloud Pub/Sub topic.

Multiple Elastic Agent instances can be configured to read from the same subscription to achieve high-availability or increased throughput.
