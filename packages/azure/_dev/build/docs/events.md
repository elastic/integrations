# Azure Logs Integration (v2 preview)

The Azure Logs integration (v2 preview) collects logs from selected Azure services, such as Microsoft Entra ID (Sign-in, Audit, Identity Protection, and Provisioning logs), Azure Spring Apps, Azure Firewall, Microsoft Graph Activity, and several others.

You can then visualize that data in Kibana, create alerts if something goes wrong, and reference data when troubleshooting an issue.

For example, to detect possible brute force sign-in attacks, you can install the Azure Logs integration to send Azure sign-in logs to Elastic. Then, by setting up a new rule in the Elastic Observability Logs app, you can be alerted when the number of failed sign-in attempts exceeds a certain threshold.

You may also want to plan your Azure capacity better. Send Azure Activity logs to Elastic to track and visualize when your virtual machines fail to start because they exceed the quota limit.

## What's new in the integration v2 preview?

The Azure Logs integration v2 preview introduces:

* A new architecture that allows you to collect all logs through a single event hub.
* Significant efficiency improvements.
* A new event hub processor (v2) that incorporates the latest Event Hubs SDK.

### Architecture

The Azure Logs integration (v2 preview) introduces a new architecture that allows you to forward logs from multiple Azure services to the same event hub.

```text
                                                             ┌─────────────────┐
                                                             │  activity logs  │
                                                          ┌─▶│ <<data stream>> │
                                                          │  └─────────────────┘
                                                          │                     
┌───────────────┐   ┌─────────────┐  ┌─────────────────┐  │  ┌─────────────────┐
│     logs      │   │   Elastic   │  │ events (router) │  │  │  firewall logs  │
│ <<event hub>> │──▶│    Agent    │─▶│ <<data stream>> │──┼─▶│ <<data stream>> │
└───────────────┘   └─────────────┘  └─────────────────┘  │  └─────────────────┘
                                                          │                     
                                                          │  ┌─────────────────┐
                                                          │  │   signin logs   │
                                                          └─▶│ <<data stream>> │
                                                             └─────────────────┘
```

The integration will automatically detect the log category and forward the logs to the appropriate data stream. When the integration v2 preview cannot find a matching data stream for a log category, it forwards the logs to the platform logs data stream.

IMPORTANT: **To use the integration v2 preview, you must turn off all the existing v1 integrations and turn on only the v2 preview integration.**

### Efficiency

The integration v2 preview avoids contention and inefficiencies from using multiple consumers per partition with the same event hub, problems that are typical of the v1 architecture. With the v2 preview, you can still assign the agent policy to multiple Elastic Agents to scale out the logs processing.

### Event Hub Processor v2 ✨

The integration v2 preview offers a new processor v2 starting with integration version 1.23.0.

The processor v2 introduces several changes:

* It uses the latest Event Hubs SDK from Azure.
* It uses a more efficient checkpoint store based on Azure Blob Storage metadata.

The processor v2 is in preview. Processor v1 is still the default and is recommended for typical use cases.

See the "Event Hub Processor v2 only" section in the integration settings for more details about enabling the processor v2.

## Data streams

The Azure Logs integration (v2 preview) collects logs.

**Logs** help you keep a record of events that happen on your Azure account.
Log data streams collected by the Azure Logs integration include Activity, Platform, Microsoft Entra ID (Sign-in, Audit, Identity Protection, Provisioning), Microsoft Graph Activity, and Spring Apps logs.

## Routing

The integration routes the logs to the most appropriate data stream based on the log category. 

Use the following table to identify the target data streams for each log category. For example, if the integration receives a log event with the `NonInteractiveUserSignInLogs` category, it will infer `azure.signinlogs` as dataset, indexing the log into `logs-azure.signinlogs-default` data stream. 

| Data Stream                        | Log Categories                                                                                                                                               |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `logs-azure.activitylogs-*`        | `Administrative`, `Security`, `ServiceHealth`, `Alert`, `Recommendation`, `Policy`, `Autoscale`, `ResourceHealth`                                            |
| `logs-azure.application_gateway-*` | `ApplicationGatewayFirewallLog`, `ApplicationGatewayAccessLog`                                                                                               |
| `logs-azure.auditlogs-*`           | `AuditLogs`                                                                                                                                                  |
| `logs-azure.firewall_logs-*`       | `AzureFirewallApplicationRule`, `AzureFirewallNetworkRule`, `AzureFirewallDnsProxy`, `AZFWApplicationRule`, `AZFWNetworkRule`, `AZFWNatRule`, `AZFWDnsQuery` |
| `logs-azure.graphactivitylog-*`    | `MicrosoftGraphActivityLogs`                                                                                                                                 |
| `logs-azure.identity_protection-*` | `RiskyUsers`, `UserRiskEvents`                                                                                                                               |
| `logs-azure.provisioning-*`        | `ProvisioningLogs`                                                                                                                                           |
| `logs-azure.signinlogs-*`          | `SignInLogs`, `NonInteractiveUserSignInLogs`, `ServicePrincipalSignInLogs`, `ManagedIdentitySignInLogs`                                                      |
| `logs-azure.springcloudlogs-*`     | `ApplicationConsole`, `SystemLogs`, `IngressLogs`, `BuildLogs`, `ContainerEventLogs`                                                                         |
| `logs-azure.platformlogs-*`        | All other log categories                                                                                                                                     |

### What about all other log categories?

The integration indexes all other Azure logs categories using the `logs-azure.platformlogs-*` data stream.

## Requirements

You need Elasticsearch to store and search for your data and Kibana to visualize and manage it.
You can use our recommended hosted Elasticsearch Service on Elastic Cloud or self-manage the Elastic Stack on your hardware.

Before using the Azure integration, you will need:

* One or more **diagnostic settings** to export logs from Azure services to Event Hubs.
* One **event hub** to store in-flight logs exported by Azure services and make them available to Elastic Agent.
* One **Storage Account container** to store the event hub checkpointing information for each partition.

### Diagnostic settings

Azure diagnostic settings allow you to export metrics and logs from a **source** service (or resource) to one **destination** for analysis and long-term storage.

```text
   ┌────────────────────┐      ┌──────────────┐     ┌─────────────────┐
   │ Microsoft Entra ID │      │  Diagnostic  │     │    Event Hub    │
   │    <<source>>      │─────▶│   settings   │────▶│ <<destination>> │
   └────────────────────┘      └──────────────┘     └─────────────────┘
```

Examples of source services:

* Azure Monitor
* Microsoft Entra ID
* Azure Firewall

The diagnostic settings support several destination types. The Elastic Agent requires diagnostic settings configured with an event hub as the destination.

### Event Hub

[Azure Event Hubs](https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-about) is a data streaming platform and event ingestion service that can receive and temporarily store millions of events.

Elastic Agent with the Azure Logs integration will consume logs published in the Event Hubs service.

```text
  ┌────────────────┐      ┌────────────┐
  │     adlogs     │      │  Elastic   │
  │ <<Event Hub>>  │─────▶│   Agent    │
  └────────────────┘      └────────────┘
```

To learn more about Event Hubs, refer to [Features and terminology in Azure Event Hubs](https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-features).

### Storage account container

The [Storage account](https://learn.microsoft.com/en-us/azure/storage/common/storage-account-overview) is a versatile Azure service that allows you to store data in various storage types, including blobs, file shares, queues, tables, and disks.

The Azure Logs integration requires a Storage Account container to work. The integration uses the Storage Account container for checkpointing; it stores data about the Consumer Group (state, position, or offset) and shares it among the Elastic Agents. Sharing such information allows multiple Elastic Agents assigned to the same agent policy to work together, enabling horizontal scaling of the logs processing when required.

```text
  ┌────────────────┐                     ┌────────────┐
  │     adlogs     │        logs         │  Elastic   │
  │ <<Event Hub>>  │────────────────────▶│   Agent    │
  └────────────────┘                     └────────────┘
                                                │      
                       consumer group info      │      
  ┌────────────────┐   (state, position, or     │      
  │   azurelogs    │         offset)            │      
  │ <<container>>  │◀───────────────────────────┘      
  └────────────────┘                                                                            
```

The Elastic Agent automatically creates one container for each enabled integration. In the container, the Agent will create one blob for each existing partition on the event hub.

For example, if you enable one integration to fetch data from an event hub with four partitions, the Agent will create the following:

* One Storage Account container.
* Four blobs in that container.

The information stored in the blobs is small (usually < 300 bytes per blob) and accessed relatively frequently. Elastic recommends using the Hot storage tier.

You need to keep the Storage Account container as long as you need to run the integration with the Elastic Agent. If you delete a storage account container, the Elastic Agent will stop working and create a new one the next time it starts. By deleting a storage account container, the Elastic Agent will lose track of the last message processed and start processing messages from the beginning of the event hub retention period.

## Setup

With the Azure Logs integration (v2 preview), you can forward logs from multiple Azure services to the same event hub. The integration will automatically detect the log category and forward the logs to the appropriate data stream.

```text
                                                             ┌─────────────────┐
                                                             │  activity logs  │
                                                          ┌─▶│ <<data stream>> │
                                                          │  └─────────────────┘
                                                          │                     
┌───────────────┐   ┌─────────────┐  ┌─────────────────┐  │  ┌─────────────────┐
│     logs      │   │   Elastic   │  │ events (router) │  │  │  firewall logs  │
│ <<event hub>> │──▶│    Agent    │─▶│ <<data stream>> │──┼─▶│ <<data stream>> │
└───────────────┘   └─────────────┘  └─────────────────┘  │  └─────────────────┘
                                                          │                     
                                                          │  ┌─────────────────┐
                                                          │  │   signin logs   │
                                                          └─▶│ <<data stream>> │
                                                             └─────────────────┘
```

Before adding the integration, you must complete the following tasks.

### Create an Event Hub

The event hub receives the logs exported from the Azure service and makes them available for the Elastic Agent to read.

Here's a high-level overview of the required steps:

* Create a resource group, or select an existing one.
* Create an Event Hubs namespace.
* Create an event hub.

For a detailed step-by-step guide, check the quickstart [Create an event hub using Azure portal](https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-create).

Take note of the event hub **Name**, which you will use later when specifying an **eventhub** in the integration settings.

#### Event Hubs Namespace vs Event Hub

In the integration settings, you should use the event hub name (not the Event Hubs namespace name) as the value for the  **event hub ** option.

If you are new to Event Hubs, think of the Event Hubs namespace as the cluster and the event hub as the topic. You will typically have one cluster and multiple topics.

If you are familiar with Kafka, here's a conceptual mapping between the two:

| Kafka Concept  | Event Hub Concept |
|----------------|-------------------|
| Cluster        | Namespace         |
| Topic          | An event hub      |
| Partition      | Partition         |
| Consumer Group | Consumer Group    |
| Offset         | Offset            |

#### How many partitions?

The number of partitions is essential to balance the event hub cost and performance.

Here are a few examples with one or multiple agents, with recommendations on picking the correct number of partitions for your use case.

##### Single Agent

With a single Agent deployment, increasing the number of partitions on the event hub is the primary driver in scale-up performances. The Agent creates one worker for each partition.

```text
┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐    ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐

│                         │    │                         │

│   ┌─────────────────┐   │    │   ┌─────────────────┐   │
    │   partition 0   │◀───────────│    consumer     │
│   └─────────────────┘   │    │   └─────────────────┘   │
    ┌─────────────────┐            ┌─────────────────┐
│   │   partition 1   │◀──┼────┼───│    consumer     │   │
    └─────────────────┘            └─────────────────┘
│   ┌─────────────────┐   │    │   ┌─────────────────┐   │
    │   partition 2   │◀────────── │    consumer     │
│   └─────────────────┘   │    │   └─────────────────┘   │
    ┌─────────────────┐            ┌─────────────────┐
│   │   partition 3   │◀──┼────┼───│    consumer     │   │
    └─────────────────┘            └─────────────────┘
│                         │    │                         │

│                         │    │                         │

└ Event Hub ─ ─ ─ ─ ─ ─ ─ ┘    └ Agent ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘
```

##### Two or more Agents

With more than one Agent, setting the number of partitions is crucial. The agents share the existing partitions to scale out performance and improve availability.

The number of partitions must be at least the number of agents.

```text
┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐    ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐

│                         │    │   ┌─────────────────┐   │
                            ┌──────│    consumer     │
│   ┌─────────────────┐   │ │  │   └─────────────────┘   │
    │   partition 0   │◀────┘      ┌─────────────────┐
│   └─────────────────┘   │ ┌──┼───│    consumer     │   │
    ┌─────────────────┐     │      └─────────────────┘
│   │   partition 1   │◀──┼─┘  │                         │
    └─────────────────┘         ─Agent─ ─ ─ ─ ─ ─ ─ ─ ─ ─
│   ┌─────────────────┐   │    ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐
    │   partition 2   │◀────┐
│   └─────────────────┘   │ │  │  ┌─────────────────┐    │
    ┌─────────────────┐     └─────│    consumer     │
│   │   partition 3   │◀──┼─┐  │  └─────────────────┘    │
    └─────────────────┘     │     ┌─────────────────┐
│                         │ └──┼──│    consumer     │    │
                                  └─────────────────┘
│                         │    │                         │

└ Event Hub ─ ─ ─ ─ ─ ─ ─ ┘    └ Agent ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘
```

##### Recommendations

Create an event hub with at least two partitions. Two partitions allow low-volume deployment to support high availability with two agents. Consider creating four partitions or more to handle medium-volume deployments with availability.

To learn more about event hub partitions, read an in-depth guide from Microsoft at [Quickstart: Create an event hub using Azure portal](https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-create).

To learn more about event hub partition from the performance perspective, check the scalability-focused document at [Event Hubs scalability](https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-scalability#partitions).

#### How many Event Hubs?

With the Azure Logs integration (v2 preview), Elastic strongly recommends creating one event hub and using it for all Azure services.

For example, if you plan to collect Microsoft Entra ID and Azure Firewall logs, create one event hub and use it for both services.

Here's a high-level diagram of the solution:

```text
┌────────────────┐   ┌───────────────┐                                       
│  MS Entra ID   │   │  Diagnostic   │                                       
│  <<service>>   │──▶│   Settings    │─┐                                     
└────────────────┘   └───────────────┘ │                                     
                                       │  ┌───────────────┐   ┌─────────────┐
                                       │  │     logs      │   │   Elastic   │
                                       ├─▶│ <<event hub>> │──▶│    Agent    │
                                       │  └───────────────┘   └─────────────┘
┌────────────────┐   ┌───────────────┐ │                                     
│ Azure Firewall │   │  Diagnostic   │ │                                     
│  <<service>>   │──▶│   Settings    │─┘                                     
└────────────────┘   └───────────────┘                                       
```

The Azure Logs integration (v2 preview) will automatically detect the log category and forward the logs to the appropriate data stream.

#### Consumer Group

Like all other event hub clients, Elastic Agent needs a consumer group name to access the event hub.

A Consumer Group is an entire event hub's view (state, position, or offset). Consumer groups enable multiple agents to have a separate view of the event stream and to read the logs independently at their own pace and with their offsets.

Consumer groups allow multiple Elastic Agents assigned to the same agent policy to work together; this enables horizontal scaling of the logs processing when required.

In most cases, you can use the default consumer group named `$Default`. If `$Default` is already used by other applications, you can create a consumer group dedicated to the Azure Logs integration.

#### Connection string

The Elastic Agent requires a connection string to access the event hub and fetch the exported logs. The connection string contains details about the event hub used and the credentials required to access it.

To get the connection string for your Event Hubs namespace:

1. Visit the **Event Hubs namespace** you created in a previous step.
1. Select **Settings** > **Shared access policies**.

Create a new Shared Access Policy (SAS):

1. Select **Add** to open the creation panel.
1. Add a **Policy name** (for example, "ElasticAgent").
1. Select the **Listen** claim.
1. Select **Create**.

When the SAS Policy is ready, select it to display the information panel.

Take note of the **Connection string–primary key**, which you will use later when specifying a **connection_string** in the integration settings.

### Create a diagnostic settings

The diagnostic settings export the logs from Azure services to a destination and in order to use Azure Logs integration, it must be an event hub.

To create a diagnostic settings to export logs:

1. Locate the diagnostic settings for the service (for example, Microsoft Entra ID).
2. Select diagnostic settings in the **Monitoring** section of the service. Note that different services may place the diagnostic settings in various positions.
3. Select **Add diagnostic settings**.

In the diagnostic settings page you must select the source **log categories** you want to export and then select their **destination**.

#### Select log categories

Each Azure service exports a well-defined list of log categories. Check the individual integration doc to learn which log categories the integration supports.

#### Select the destination

Select the **subscription** and the **Event Hubs namespace** you previously created. Select the event hub dedicated to this integration.

```text
  ┌───────────────┐   ┌──────────────┐   ┌───────────────┐      ┌───────────┐
  │  MS Entra ID  │   │  Diagnostic  │   │     adlogs    │      │  Elastic  │
  │  <<service>>  ├──▶│   Settings   │──▶│ <<Event Hub>> │─────▶│   Agent   │
  └───────────────┘   └──────────────┘   └───────────────┘      └───────────┘
```

### Create a Storage Account container

The Elastic Agent stores the event hub checkpoint information in a storage account container. Storing checkpoint information in a container allows agents to share message processing and resume from the last processed message after a restart.

**Note**: Use the Storage Account as a checkpoint store only.

To create the storage account:

1. Sign in to the [Azure Portal](https://portal.azure.com/) and create your storage account.
2. While configuring your project details, make sure you select the following recommended default settings:
   * Hierarchical namespace: disabled
   * Minimum TLS version: Version 1.2
   * Access tier: Hot
   * Enable soft delete for blobs: disabled
   * Enable soft delete for containers: disabled

3. When the new storage account is ready, you need to take note of the storage account name and the Storage Account access keys, as you will use them later to authenticate your Elastic application’s requests to this storage account.

This is the final diagram of the setup for collecting Activity logs from the Azure Monitor service.

```text
 ┌───────────────┐   ┌──────────────┐   ┌────────────────┐         ┌───────────┐
 │  MS Entra ID  │   │  Diagnostic  │   │     adlogs     │  logs   │  Elastic  │
 │  <<service>>  ├──▶│   Settings   │──▶│ <<Event Hub>>  │────────▶│   Agent   │
 └───────────────┘   └──────────────┘   └────────────────┘         └───────────┘
                                                                          │     
                     ┌──────────────┐          consumer group info        │     
                     │  azurelogs   │          (state, position, or       │     
                     │<<container>> │◀───────────────offset)──────────────┘     
                     └──────────────┘                                           
```

#### How many Storage Accounts?

The Elastic Agent can use a single Storage Account to store the checkpoint information for multiple integrations.

**CRITICAL**: make sure to use a different **storage_account_container** for each integration. The Elastic Agent uses the **integration name** and the **event hub name** to uniquely identify the container that holds the blobs with the checkpoint information.

```text
┌─────────────────────────────────┐      ┌──────────────────────────────────────────┐
│                                 │      │                                          │
│    ┌─────────────────────┐      │      │  ┌────────────────────────────────────┐  │
│    │   azure-eventhub    │      │      │  │  filebeat-activitylogs-eventhub-1  │  │
│    │      <<input>>      │──────┼──────┼─▶│           <<container>>            │  │
│    └─────────────────────┘      │      │  └────────────────────────────────────┘  │
│    ┌─────────────────────┐      │      │  ┌────────────────────────────────────┐  │
│    │   azure-eventhub    │      │      │  │   filebeat-signinlogs-eventhub-2   │  │
│    │      <<input>>      │──────┼──────┼─▶│           <<container>>            │  │
│    └─────────────────────┘      │      │  └────────────────────────────────────┘  │
│    ┌─────────────────────┐      │      │  ┌────────────────────────────────────┐  │
│    │   azure-eventhub    │      │      │  │   filebeat-auditlogs-eventhub-3    │  │
│    │      <<input>>      │──────┼──────┼─▶│           <<container>>            │  │
│    └─────────────────────┘      │      │  └────────────────────────────────────┘  │
│                                 │      │                                          │
└─Elastic Agent───────────────────┘      └─Storage Account──────────────────────────┘
```

### Running the integration behind a firewall

When you run the Elastic Agent behind a firewall, you must allow traffic on ports `5671` and `5672` for the event hub and port `443` for the Storage Account container to ensure proper communication with the necessary components.

```text
┌────────────────────────────────┐  ┌───────────────────┐  ┌───────────────────┐
│                                │  │                   │  │                   │
│ ┌────────────┐   ┌───────────┐ │  │  ┌──────────────┐ │  │ ┌───────────────┐ │
│ │ diagnostic │   │ event hub │ │  │  │azure-eventhub│ │  │ │ activity logs │ │
│ │  setting   │──▶│           │◀┼AMQP─│  <<input>>   │─┼──┼▶│<<data stream>>│ │
│ └────────────┘   └───────────┘ │  │  └──────────────┘ │  │ └───────────────┘ │
│                                │  │          │        │  │                   │
│                                │  │          │        │  │                   │
│                                │  │          │        │  │                   │
│         ┌─────────────┬─────HTTPS─┼──────────┘        │  │                   │
│ ┌───────┼─────────────┼──────┐ │  │                   │  │                   │
│ │       │             │      │ │  │                   │  │                   │
│ │       ▼             ▼      │ │  └─Agent─────────────┘  └─Elastic Cloud─────┘
│ │ ┌──────────┐  ┌──────────┐ │ │
│ │ │    0     │  │    1     │ │ │
│ │ │ <<blob>> │  │ <<blob>> │ │ │
│ │ └──────────┘  └──────────┘ │ │
│ │                            │ │
│ │                            │ │
│ └─Storage Account Container──┘ │
│                                │
│                                │
└─Azure──────────────────────────┘
```

#### Event Hub

Port `5671` and `5672` are commonly used for secure communication with the event hub. These ports are used to receive events. The Elastic Agent can establish a secure connection with the event hub by allowing traffic on these ports. 

For more information, check the following documents:

* [What ports do I need to open on the firewall?](https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-faq#what-ports-do-i-need-to-open-on-the-firewall) from the [Event Hubs frequently asked questions](https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-faq#what-ports-do-i-need-to-open-on-the-firewall).
* [AMQP outbound port requirements](https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-amqp-protocol-guide#amqp-outbound-port-requirements)

#### Storage Account container

The Elastic Agent uses port `443` for secure communication with the Storage Account container. By allowing traffic on port 443, the Elastic Agent can securely access and interact with the Storage Account container, essential for storing and retrieving checkpoint data for each event hub partition.

#### DNS

Optionally, you can restrict the traffic to the following domain names:

```text
*.servicebus.windows.net
*.blob.core.windows.net
*.cloudapp.net
```

## Settings

Use the following settings to configure the Azure Logs integration when you add it to Fleet.

`eventhub` :
_string_
A fully managed, real-time data ingestion service. Elastic recommends using only letters, numbers, and the hyphen (-) character for event hub names to maximize compatibility. You can use existing event hubs having underscores (_) in the event hub name; in this case, the integration will replace underscores with hyphens (-) when it uses the event hub name to create dependent Azure resources behind the scenes (e.g., the storage account container to store event hub consumer offsets). Elastic also recommends using a separate event hub for each log type as the field mappings of each log type differ.
Default value `insights-operational-logs`.

`consumer_group` :
_string_
Enable the publish/subscribe mechanism of Event Hubs with consumer groups. A consumer group is a view (state, position, or offset) of an entire event hub. Consumer groups enable multiple consuming applications to each have a separate view of the event stream, and to read the stream independently at their own pace and with their own offsets.
Default value: `$Default`

`connection_string` :
_string_

The connection string is required to communicate with Event Hubs. See [Get an Event Hubs connection string](https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-get-connection-string) for more information.

A Blob Storage account is required to store/retrieve/update the offset or state of the event hub messages. This allows the integration to start back up when it stopped processing messages.

`storage_account` :
_string_
The name of the storage account that the state/offsets will be stored and updated.

`storage_account_key` :
_string_
The storage account key. Used to authorize access to data in your storage account.

`storage_account_container` :
_string_
The storage account container where the integration stores the checkpoint data for the consumer group. It is an advanced option to use with extreme care. You MUST use a dedicated storage account container for each Azure log type (activity, sign-in, audit logs, and others). DO NOT REUSE the same container name for more than one Azure log type. See [Container Names](https://docs.microsoft.com/en-us/rest/api/storageservices/naming-and-referencing-containers--blobs--and-metadata#container-names) for details on naming rules from Microsoft. The integration generates a default container name if not specified.

`resource_manager_endpoint` :
_string_
Optional. By default, the integration uses the Azure public environment. To override this and use a different Azure environment, users can provide a specific resource manager endpoint

Examples:

* Azure ChinaCloud: `https://management.chinacloudapi.cn/`
* Azure GermanCloud: `https://management.microsoftazure.de/`
* Azure PublicCloud: `https://management.azure.com/`
* Azure USGovernmentCloud: `https://management.usgovcloudapi.net/`

This setting can also be used to define your own endpoints, like for hybrid cloud models.

### Event Hub Processor v2 only

The following settings are **event hub processor v2 only** and available in the advanced section of the integration.

`processor_version` :
_string_
(processor v2 only) The processor version that the integration should use. Possible values are `v1` and `v2` (preview). The processor v2 is in preview. Using the processor v1 is recommended for typical use cases. Default is `v1`.

`processor_update_interval` :
_string_
(processor v2 only) How often the processor should attempt to claim partitions. Default is `10s`.

`processor_start_position` :
_string_
(processor v2 only) Controls from which position in the event hub the processor should start processing messages for all partitions.

Possible values are `earliest` and `latest`.

* `earliest` (default): starts processing messages from the last checkpoint, or the beginning of the event hub if no checkpoint is available.
* `latest`: starts processing messages from the the latest event in the event hub and continues to process new events as they arrive.

`migrate_checkpoint` :
_boolean_
(processor v2 only) Flag to control whether the processor should perform the checkpoint information migration from v1 to v2 at startup. The checkpoint migration converts the checkpoint information from the v1 format to the v2 format.

Default is `false`, which means the processor will not perform the checkpoint migration.

`partition_receive_timeout` :
_string_
(processor v2 only) Maximum time to wait before processing the messages received from the event hub.

The partition consumer waits up to a "receive count" or a "receive timeout", whichever comes first. Default is `5` seconds.

`partition_receive_count` :
_string_
(processor v2 only) Maximum number of messages from the event hub to wait for before processing them.

The partition consumer waits up to a "receive count" or a "receive timeout", whichever comes first. Default is `100` messages.

## Handling Malformed JSON in Azure Logs

Azure services have been observed occasionally sending [malformed JSON](https://learn.microsoft.com/en-us/answers/questions/1001797/invalid-json-logs-produced-for-function-apps) documents. These logs can disrupt the expected JSON formatting and lead to parsing issues during processing.

To address this issue, the advanced settings section of each data stream offers two sanitization options:

* Sanitizes New Lines: removes new lines in logs.
* Sanitizes Single Quotes: replace single quotes with double quotes in logs, excluding single quotes occurring within double quotes.

Malformed logs can be identified by:

* The presence of a records array in the message field indicates a failure to unmarshal the byte slice.
* An `error.message` field contains the "Received invalid JSON from the Azure Cloud platform. Unable to parse the source log message" text.

Known data streams that might produce malformed logs:

* Platform Logs
* Spring Apps Logs

## Reference

Visit the page for each individual Azure Logs integration to see details about exported fields and sample events.
