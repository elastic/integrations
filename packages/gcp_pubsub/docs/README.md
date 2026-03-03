# Custom Google Pub/Sub Integration

The custom Google Pub/Sub input package is used to ingest data from a Google Pub/Sub topic subscription that is not covered by our [GCP Integration](https://docs.elastic.co/en/integrations/gcp).

This integration could, for example, be used to receive Stackdriver logs that have been exported to a Google Pub/Sub topic.

Multiple Elastic Agent instances can be configured to read from the same subscription to achieve high availability or increased throughput.

## Configuring

1. Create a user-managed service account (you can skip this if Elastic Agent is running in a VM with a service account attached).  See: [Service Accounts](https://cloud.google.com/iam/docs/creating-managing-service-accounts)

2. Create a Pub/Sub topic and subscription.  See:[Topics and Subscriptions](https://cloud.google.com/pubsub/docs/admin)

3. Configure this integration to read from the Pub/Sub subscription using the service account credentials.

4. Write logs into the Pub/Sub topic yourself or configure a log sink to export GCP logs to the topic. See: [Managing Sinks](https://cloud.google.com/logging/docs/export/configure_export_v2)
