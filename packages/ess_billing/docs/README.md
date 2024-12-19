# Elasticsearch Service Billing

The Elasticsearch Service Billing integration allows you to monitor Elasticsearch Service usage and costs. It collects billing data from the [Elasticsearch Service billing API](https://www.elastic.co/guide/en/cloud/current/Billing_Costs_Analysis.html) and sends it to your target Elasticsearch cluster. Dashboards are provided out-of-the-box to help you visualize your Elasticsearch Service usage and costs.

Using this integration, you could for instance create alerts whenever a new deployment is created, or when your baseline spending exceeds a certain threshold.

## Data streams

The Elasticsearch Service Billing integration collects the following data streams:

* Your daily spending in the `metrics-ess_billing.billing` data stream.
* For customers with a yearly commitment with Elastic, your credit status in the `metrics-ess_billing.credit` data stream (__coming soon__).

By default, the last year of data of billing data is collected upon first execution of the integration. The data is then collected daily, the integration will automatically collect the latest data every day.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

You will need to recover the identifier of your organization, which can be seen in the [cloud organization page](https://cloud.elastic.co/account/members).

You will also need to provision an API key with the `Billing admin` role in the [API keys page](https://cloud.elastic.co/account/keys).

For private cloud, or admin users, the cloud endpoint can be altered to match your requirements.

## Setup

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Metrics reference

### `metrics-ess_billing.billing` data stream

The `metrics-ess_billing.billing` data stream collects daily billing data from the Elasticsearch Service billing API.

#### Example

An example event for `metrics-ess_billing.billing` looks as following:

```
{
  "@timestamp": "2023-10-29T00:00:00.000Z",
  "agent": {
    "ephemeral_id": "866f73b8-eab0-431b-9e2f-84a8f32c4ab6",
    "id": "d1ccee7f-72fd-4d80-8bbd-1a35ba2025fa",
    "name": "docker-fleet-agent",
    "type": "filebeat",
    "version": "8.15.1"
  },
  "cloud": {
    "account": {
      "id": "3166899605"
    },
    "availability_zone": "europe-west1",
    "instance": {
      "id": "2fd9e0131d7f40028e349f87dba42dab",
      "name": "test"
    },
    "machine": {
      "type": "gcp.es.datahot.n2.68x16x45"
    },
    "provider": "gcp"
  },
  "data_stream": {
    "dataset": "ess_billing.billing",
    "namespace": "default",
    "type": "metrics"
  },
  "ecs": {
    "version": "8.0.0"
  },
  "elastic_agent": {
    "id": "d1ccee7f-72fd-4d80-8bbd-1a35ba2025fa",
    "snapshot": false,
    "version": "8.15.1"
  },
  "ess": {
    "billing": {
      "deployment_id": "2fd9e0131d7f40028e349f87dba42dab",
      "deployment_name": "test",
      "display_quantity": {
        "formatted_value": "24 hours",
        "type": "default",
        "value": 24
      },
      "from": "2023-10-29T00:00:00.000Z",
      "kind": "elasticsearch",
      "name": "Cloud Standard, GCP europe-west1 (Belgium), gcp.es.datahot.n2.68x16x45, 8GB, 3AZ",
      "organization_id": "3166899605",
      "quantity": {
        "formatted_value": "24 hours",
        "value": 24
      },
      "ram_per_zone:int": "8192",
      "rate": {
        "formatted_value": "0.7992 per hour",
        "value": 0.7992
      },
      "sku": "gcp.es.datahot.n2.68x16x45_gcp-europe-west1_8192_3",
      "to": "2023-10-30T00:00:00.000Z",
      "total_ecu": 19.1808,
      "type": "capacity",
      "unit": "hour",
      "zone_count:int": "3"
    }
  },
  "event": {
    "agent_id_status": "verified",
    "created": "2024-10-20T19:39:46.583Z",
    "dataset": "ess_billing.billing",
    "ingested": "2024-10-20T19:39:46Z",
    "module": "ess_billing"
  },
  "input": {
    "type": "cel"
  },
  "tags": [
    "billing",
    "forwarded"
  ]
}
```


#### Exported fields

| Field                                          | Description                                                              | Type      |
|------------------------------------------------|--------------------------------------------------------------------------|-----------|
| `@timestamp`                                   | Date/time when the event was generated.                                  | `date`    |
| `agent.ephemeral_id`                           | Unique ID of the agent during this lifecycle.                            | `keyword` |
| `agent.id`                                     | Unique identifier of the agent.                                          | `keyword` |
| `agent.name`                                   | Name of the agent.                                                       | `keyword` |
| `agent.type`                                   | Type of agent (e.g., filebeat).                                          | `keyword` |
| `agent.version`                                | Version of the agent.                                                    | `keyword` |
| `cloud.account.id`                             | The cloud account ID in which the resource is located.                   | `keyword` |
| `cloud.availability_zone`                      | Availability zone in which this resource is located.                     | `keyword` |
| `cloud.instance.id`                            | ID of the cloud instance.                                                | `keyword` |
| `cloud.instance.name`                          | Name of the cloud instance.                                              | `keyword` |
| `cloud.machine.type`                           | The machine type of the instance (e.g., n2.68x16x45).                    | `keyword` |
| `cloud.provider`                               | Cloud service provider (e.g., gcp, aws).                                 | `keyword` |
| `data_stream.dataset`                          | Data stream dataset name (e.g., `ess_billing.billing`).                  | `keyword` |
| `data_stream.namespace`                        | Namespace of the data stream.                                            | `keyword` |
| `data_stream.type`                             | Data stream type (e.g., metrics).                                        | `keyword` |
| `ecs.version`                                  | ECS version used for the event.                                          | `keyword` |
| `elastic_agent.id`                             | ID of the Elastic Agent that generated this event.                       | `keyword` |
| `elastic_agent.snapshot`                       | Whether the agent is a snapshot version.                                 | `boolean` |
| `elastic_agent.version`                        | Version of the Elastic Agent.                                            | `keyword` |
| `ess.billing.deployment_id`                    | ID of the Elasticsearch Service deployment.                              | `keyword` |
| `ess.billing.deployment_name`                  | Name of the Elasticsearch Service deployment.                            | `keyword` |
| `ess.billing.display_quantity.formatted_value` | Human-readable representation of the quantity used (e.g., "24 hours").   | `keyword` |
| `ess.billing.display_quantity.type`            | Type of quantity displayed (default or custom).                          | `keyword` |
| `ess.billing.display_quantity.value`           | Actual quantity used (e.g., 24).                                         | `float`   |
| `ess.billing.from`                             | Start time of the billing period.                                        | `date`    |
| `ess.billing.kind`                             | Type of service being billed (e.g., elasticsearch, kibana).              | `keyword` |
| `ess.billing.name`                             | Description of the SKU or resource being billed.                         | `keyword` |
| `ess.billing.organization_id`                  | ID of the organization in Elastic Cloud.                                 | `keyword` |
| `ess.billing.quantity.formatted_value`         | Human-readable representation of the billed quantity (e.g., "24 hours"). | `keyword` |
| `ess.billing.quantity.value`                   | Billed quantity.                                                         | `float`   |
| `ess.billing.ram_per_zone`                     | RAM size per zone in megabytes.                                          | `integer` |
| `ess.billing.rate.formatted_value`             | Human-readable representation of the rate (e.g., "0.7992 per hour").     | `keyword` |
| `ess.billing.rate.value`                       | Billed rate per unit of usage.                                           | `float`   |
| `ess.billing.sku`                              | Unique identifier for the service or product (SKU).                      | `keyword` |
| `ess.billing.to`                               | End time of the billing period.                                          | `date`    |
| `ess.billing.total_ecu`                        | Total Elasticsearch Compute Units (ECU) used.                            | `float`   |
| `ess.billing.type`                             | Type of billing (e.g., capacity, usage).                                 | `keyword` |
| `ess.billing.unit`                             | Unit of the resource being billed (e.g., hour, GB).                      | `keyword` |
| `ess.billing.zone_count`                       | Number of availability zones.                                            | `integer` |
| `event.agent_id_status`                        | Status of the agent ID verification.                                     | `keyword` |
| `event.created`                                | Timestamp when the event was created.                                    | `date`    |
| `event.dataset`                                | Name of the event dataset.                                               | `keyword` |
| `event.ingested`                               | Timestamp when the event was ingested into Elasticsearch.                | `date`    |
| `event.module`                                 | Name of the module (e.g., `ess_billing`).                                | `keyword` |
| `input.type`                                   | Type of input used to collect data (e.g., `cel`).                        | `keyword` |
| `tags`                                         | User-defined tags.                                                       | `keyword` |
