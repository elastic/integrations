# Microsoft Defender for Cloud

The [Microsoft Defender for Cloud](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction) integration allows you to monitor security alert events. When integrated with Elastic Security, this valuable data can be leveraged within Elastic for analyzing the resources and services that users are protecting through Microsoft Defender.

Use the Microsoft Defender for Cloud integration to collect and parse data from **Azure Event Hub** and then visualize that data in Kibana.

## Data streams

The Microsoft Defender for Cloud integration collects one type of data: event.

**Event** allows users to preserve a record of security events that occurred on the subscription, which includes real-time events that affect the security of the user's environment. For further information connected to security alerts and type, Refer to the page [here](https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-reference).

## Requirements

- You must have a subscription to Microsoft Azure.
- Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host. You can install only one Elastic Agent per host.
Elastic Agent is required to stream data from the **Azure Event Hub** and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

The minimum **kibana.version** required is **8.3.0**.

## Setup

### Collect data from Microsoft Azure Event Hub

- Configure the Microsoft Defender for Cloud on Azure subscription. For more detail, refer to the link [here](https://learn.microsoft.com/en-us/azure/defender-for-cloud/get-started).

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search bar, type **Microsoft Defender for Cloud**.
3. Select the **Microsoft Defender for Cloud** integration and add it.
4. While adding the integration, to collect logs via **Azure Event Hub**, enter the following details:
   - eventhub
   - consumer_group
   - connection_string
   - storage_account
   - storage_account_key
   - storage_account_container (optional)
   - resource_manager_endpoint (optional)

## Alert severity mapping

The values used in `event.severity` are consistent with Elastic Detection Rules.

| Severity Name          | `event.severity` |
|------------------------|:----------------:|
| Low (or Informational) | 21               |
| Medium                 | 47               |
| High                   | 73               |
| Critical               | 99               |

## Logs reference

### Event

This is the `Event` dataset.

#### Example

{{fields "event"}}
