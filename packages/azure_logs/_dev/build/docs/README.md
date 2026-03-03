# Custom Azure Logs

The Custom Azure Logs integration collects logs from Azure Event Hubs.

Use the integration to collect logs from:

* Azure services that support exporting logs to Event Hubs
* Any other source that can send logs to an Event Hubs

## Event Hub Processor v2

The Custom Azure Logs integration offers a new processor v2 starting with version 0.3.0.

The processor v2 introduces several changes:

* Azure's most recent Event Hubs SDK is utilized.
* It uses a more efficient checkpoint store based on Azure Blob Storage metadata.

The processor v2 is in preview. Processor v1 is still the default and is recommended for typical use cases.

Refer to the "Event Hub Processor Options" section in the integration settings for additional information on how to enable processor v2.

## Data streams

The Custom Azure Logs integration only supports logs data streams.

This custom integration does not use a predefined Elastic data stream like standard integrations do (for example, `logs-azure.activitylogs-default` for Activity logs). You can take control and build your own data stream by selecting your dataset and namespace of choice when configuring the integration.

For example, if you select `mydataset` as your dataset, and `default` as your namespace, the integration will send the data to the `logs-mydataset-default` data stream.

The integration sets up a dedicated index template named `logs-mydataset` with the `logs-mydataset-*` index pattern. You can then customize it using a custom pipeline and custom mappings.

Custom Logs integrations give you all the flexibility you need to configure the integration to your needs.

## Requirements

You need Elasticsearch to store and search for your data and Kibana to visualize and manage it.
You can use our recommended hosted Elasticsearch Service on Elastic Cloud or self-manage the Elastic Stack on your own hardware.

Before using the Custom Azure Logs, you will need:

* One **event hub** to store in-flight logs exported by Azure services (or other sources) and make them available to Elastic Agent.
* A **Storage Account** to store checkpoint information about logs the Elastic Agent consumes.

### Event hub

[Azure Event Hubs](https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-about) is a data streaming platform and event ingestion service that can receive and temporarily store millions of events.

Elastic Agent with the Custom Azure Logs integration will consume logs from the Event Hubs service.

```text
  ┌────────────────┐      ┌───────────┐
  │   myeventhub   │      │  Elastic  │
  │ <<Event Hub>>  │─────▶│   Agent   │
  └────────────────┘      └───────────┘
```

To learn more about Event Hubs, refer to [Features and terminology in Azure Event Hubs](https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-features).

### Storage Account Container

The [Storage Account](https://learn.microsoft.com/en-us/azure/storage/common/storage-account-overview) is a versatile Azure service that allows you to store data in various storage types, including blobs, file shares, queues, tables, and disks.

The Custom Azure Logs integration requires a Storage Account container to work.

The integration uses the Storage Account container for checkpointing. It stores data about the Consumer Group (state, position, or offset) and shares it among the Elastic Agents. Sharing such information allows multiple Elastic Agents assigned to the same agent policy to work together, enabling horizontal scaling of the logs processing when required.

```text
  ┌────────────────┐                     ┌───────────┐
  │   myeventhub   │        logs         │  Elastic  │
  │ <<event hub>>  │────────────────────▶│   Agent   │
  └────────────────┘                     └───────────┘
                                                │      
                       consumer group info      │      
  ┌────────────────┐   (state, position, or     │      
  │ log-myeventhub │         offset)            │      
  │ <<container>>  │◀───────────────────────────┘      
  └────────────────┘                                                                            
```

The Elastic Agent automatically creates one container for the Custom Azure Logs integration and one blob for each partition on the event hub.

For example, if the integration is configured to fetch data from an event hub with four partitions, the Agent will create the following:

* One Storage Account container.
* Four blobs in that container.

The information stored in the blobs is small (usually < 500 bytes per blob) and accessed frequently. Elastic recommends using the Hot storage tier.

You need to keep the Storage Account container as long as you need to run the integration with the Elastic Agent. If you delete a Storage Account container, the Elastic Agent will stop working and create a new one the next time it starts.

By deleting a Storage Account container, the Elastic Agent will lose track of the last message processed and start processing messages from the beginning of the event hub retention period.

## Setup

Before adding the integration, complete the following tasks.

### Create an event hub

The event hub receives the logs exported from the Azure service and makes them available for the Elastic Agent to read.

Here's a high-level overview of the required steps:

* Create a resource group, or select an existing one.
* Create an Event Hubs namespace.
* Create an event hub.

For a step-by-step guide, check the quickstart [Create an event hub using Azure portal](https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-create).

Take note of the event hub **Name**, which you will use later when specifying an **eventhub** in the integration settings.

#### Event Hubs namespace vs event hub

In the integration settings, you should use the event hub name (not the Event Hubs namespace name) as the value for the  **event hub** option.

If you are new to Event Hubs, think of the Event Hubs namespace as the cluster and the event hub as the topic. You will typically have one cluster and multiple topics.

If you are familiar with Kafka, here's a conceptual mapping between the two:

| Kafka Concept  | Event Hubs Concept  |
|----------------|---------------------|
| Cluster        | Namespace           |
| Topic          | Event hub           |
| Partition      | Partition           |
| Consumer Group | Consumer group      |
| Offset         | Offset              |

#### How many partitions?

The number of partitions is essential to balance the event hub cost and performance.

Here are a few examples with one or multiple agents, with recommendations on picking the correct number of partitions for your use case.

##### Single Agent

With a single Agent deployment, increasing the number of partitions on the event hub is the primary driver in scale-up performances. The Agent creates one worker for each partition.

```text
┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐    ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐

│                         │    │                         │

│   ┌─────────────────┐   │    │   ┌─────────────────┐   │
    │   partition 0   │◀───────────│     worker      │
│   └─────────────────┘   │    │   └─────────────────┘   │
    ┌─────────────────┐            ┌─────────────────┐
│   │   partition 1   │◀──┼────┼───│     worker      │   │
    └─────────────────┘            └─────────────────┘
│   ┌─────────────────┐   │    │   ┌─────────────────┐   │
    │   partition 2   │◀────────── │     worker      │
│   └─────────────────┘   │    │   └─────────────────┘   │
    ┌─────────────────┐            ┌─────────────────┐
│   │   partition 3   │◀──┼────┼───│     worker      │   │
    └─────────────────┘            └─────────────────┘
│                         │    │                         │

│                         │    │                         │

└ Event hub ─ ─ ─ ─ ─ ─ ─ ┘    └ Elastic Agent ─ ─ ─ ─ ─ ┘
```

##### Two or more Elastic Agents

With more than one Elastic Agent, setting the number of partitions is crucial. The agents share the existing partitions to scale out performance and improve availability.

The number of partitions must be at least the number of agents.

```text
┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐    ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐

│                         │    │   ┌─────────────────┐   │
                            ┌──────│     worker      │
│   ┌─────────────────┐   │ │  │   └─────────────────┘   │
    │   partition 0   │◀────┘      ┌─────────────────┐
│   └─────────────────┘   │ ┌──┼───│     worker      │   │
    ┌─────────────────┐     │      └─────────────────┘
│   │   partition 1   │◀──┼─┘  │                         │
    └─────────────────┘         ─Agent─ ─ ─ ─ ─ ─ ─ ─ ─ ─
│   ┌─────────────────┐   │    ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐
    │   partition 2   │◀────┐
│   └─────────────────┘   │ │  │  ┌─────────────────┐    │
    ┌─────────────────┐     └─────│     worker      │
│   │   partition 3   │◀──┼─┐  │  └─────────────────┘    │
    └─────────────────┘     │     ┌─────────────────┐
│                         │ └──┼──│     worker      │    │
                                  └─────────────────┘
│                         │    │                         │

└ Event hub ─ ─ ─ ─ ─ ─ ─ ┘    └ Elastic Agent ─ ─ ─ ─ ─ ┘
```

##### Recommendations

Create an event hub with at least two partitions. Two partitions allow low-volume deployment to support high availability with two agents. Consider creating four partitions or more to handle medium-volume deployments with availability.

To learn more about event hub partitions, check this guide from Microsoft at https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-create.

To learn more about event hub partition from the performance perspective, check the scalability-focused document at https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-scalability#partitions.

#### Consumer group

Like all other event hub clients, Elastic Agent needs a consumer group name to access the event hub.

A Consumer Group is a view (state, position, or offset) of an entire event hub. Consumer groups enable multiple agents to have a separate view of the event stream and to read the logs independently at their own pace and with their offsets.

Consumer groups allow multiple Elastic Agents assigned to the same agent policy to work together, enabling horizontal scaling of log processing when required.

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
1. Click **Create**.

When the SAS Policy is ready, select it to display the information panel.

Take note of the **Connection string–primary key**, which you will use later when specifying a **connection_string** in the integration settings.

### Create a diagnostic settings

The diagnostic settings export the logs from Azure services to a destination, and to use Azure Logs integration, it must be an event hub.

To create a diagnostic settings to export logs:

1. Locate the diagnostic settings for the service (for example, Microsoft Entra ID).
1. Select diagnostic settings in the **Monitoring** section of the service. Note that different services might place the diagnostic settings in various positions.
1. Select **Add diagnostic settings**.

In the diagnostic settings page, you must select the source log categories you want to export and then select their destination.

#### Select log categories

Each Azure service exports a well-defined list of log categories. Check the individual integration documentation to check the supported log categories.

#### Select the destination

Select the **subscription** and the **Event Hubs namespace** you previously created. Select the event hub dedicated to this integration.

```text
  ┌───────────────┐   ┌──────────────┐   ┌───────────────┐      ┌───────────┐
  │  MS Entra ID  │   │  Diagnostic  │   │     adlogs    │      │  Elastic  │
  │  <<service>>  ├──▶│   Settings   │──▶│ <<event hub>> │─────▶│   Agent   │
  └───────────────┘   └──────────────┘   └───────────────┘      └───────────┘
```

### Create a Storage Account Container

The Elastic Agent stores the consumer group information (state, position, or offset) in a Storage Account container. Making this information available to all agents allows them to share the logs processing and resume from the last processed logs after a restart.

NOTE: Use the Storage Account as a checkpoint store only.

To create the Storage Account:

1. Sign in to the [Azure Portal](https://portal.azure.com/) and create your Storage Account.
1. While configuring your project details, make sure you select the following recommended default settings:
   - Hierarchical namespace: disabled
   - Minimum TLS version: Version 1.2
   - Access tier: Hot
   - Enable soft delete for blobs: disabled
   - Enable soft delete for containers: disabled

1. When the new Storage Account is ready, take note of the Storage Account name and access keys, as you will use them later to authenticate your Elastic application's requests to this Storage Account.

This is the final diagram of the setup for collecting Activity logs from the Azure Monitor service.

```text
 ┌───────────────┐   ┌──────────────┐   ┌────────────────┐         ┌───────────┐
 │  MS Entra ID  │   │  Diagnostic  │   │     adlogs     │  logs   │  Elastic  │
 │  <<service>>  ├──▶│   Settings   │──▶│ <<event hub>>  │────────▶│   Agent   │
 └───────────────┘   └──────────────┘   └────────────────┘         └───────────┘
                                                                          │     
                     ┌──────────────┐          consumer group info        │     
                     │  azurelogs   │          (state, position, or       │     
                     │<<container>> │◀───────────────offset)──────────────┘     
                     └──────────────┘                                           
```

#### Storage Account containers?

The Elastic Agent can use one Storage Account (SA) for multiple integrations.

The Agent creates one SA container for the integration. The SA container name combines the event hub name and a prefix (`azure-eventhub-input-[eventhub]`).

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

#### Event hub

Port `5671` and `5672` are commonly used for secure communication with the event hub. These ports are used to receive events. The Elastic Agent can establish a secure connection with the event hub by allowing traffic on these ports. 

For more information, check the following documents:

* [What ports do I need to open on the firewall?](https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-faq#what-ports-do-i-need-to-open-on-the-firewall) from the [Event Hubs frequently asked questions](https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-faq#what-ports-do-i-need-to-open-on-the-firewall).
* [AMQP outbound port requirements](https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-amqp-protocol-guide#amqp-outbound-port-requirements)

#### Storage Account container

Port `443` is used for secure communication with the Storage Account container. This port is commonly used for HTTPS traffic. By allowing traffic on port 443, the Elastic Agent can securely access and interact with the Storage Account container, essential for storing and retrieving checkpoint data for each event hub partition.

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
A fully managed, real-time data ingestion service. Elastic recommends using only letters, numbers, and the hyphen (-) character for event hub names to maximize compatibility. You can use existing event hubs having underscores (_) in the event hub name; in this case, the integration will replace underscores with hyphens (-) when it uses the event hub name to create dependent Azure resources behind the scenes (e.g., the Storage Account container to store event hub consumer offsets). Elastic also recommends using a separate event hub for each log type as the field mappings of each log type differ.
Default value `insights-operational-logs`.

`consumer_group` :
_string_
Enable the publish/subscribe mechanism of Event Hubs with consumer groups. A consumer group is a view (state, position, or offset) of an entire event hub. Consumer groups enable multiple consuming applications to each have a separate view of the event stream, and to read the stream independently at their own pace and with their own offsets.
Default value: `$Default`

`connection_string` :
_string_

The connection string is required to communicate with Event Hubs. Check [Get an Event Hubs connection string](https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-get-connection-string) for more information.

A Blob Storage Account is required to store/retrieve/update the checkpoint information of the event hub messages. This allows the integration to resume processing messages left when the user stops it.

`storage_account` :
_string_
The name of the Storage Account that stores the checkpoint information.
`storage_account_key` :
_string_
The Storage Account key. Key to authorize access to data in your Storage Account.

`storage_account_container` :
_string_
The Storage Account container is where the integration stores the checkpoint data for the consumer group. It is an advanced option to use with extreme care. You MUST use a dedicated Storage Account container for each Azure log type (activity, sign-in, audit logs, and others). DO NOT REUSE the same container name for more than one Azure log type. Check [Container Names](https://docs.microsoft.com/en-us/rest/api/storageservices/naming-and-referencing-containers--blobs--and-metadata#container-names) for details on naming rules from Microsoft. The integration generates a default container name if not specified.

`pipeline` :
_string_
Optional. Overrides the default ingest pipeline for this integration.

`resource_manager_endpoint` :
_string_
Optional. By default, the integration uses the Azure public environment. To override this and use a different Azure environment, users can provide a specific resource manager endpoint.

Examples:

* Azure ChinaCloud: `https://management.chinacloudapi.cn/`
* Azure GermanCloud: `https://management.microsoftazure.de/`
* Azure PublicCloud: `https://management.azure.com/`
* Azure USGovernmentCloud: `https://management.usgovcloudapi.net/`

This setting can also define your endpoints, like for hybrid cloud models.

### Event Hub Processor Options

The following event hub processor options are available in the advanced section of the integration.

`processor_version` :
_string_
The processor version that the integration should use. Possible values are `v1` and `v2` (preview). The processor v2 is in preview. Using the processor v1 is recommended for typical use cases. Default is `v1`.

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
* Sanitizes Single Quotes: Replace single quotes with double quotes in logs, excluding single quotes occurring within double quotes.

Malformed logs can be identified by:

* The presence of a `records` array in the message field indicates a failure to unmarshal the byte slice.
* Existence of an `error.message` field containing the text "Received invalid JSON from the Azure Cloud platform. Unable to parse the source log message."

Known data streams that might produce malformed logs:

* Platform Logs
* Spring Apps Logs
* PostgreSQL Flexible Servers Logs
