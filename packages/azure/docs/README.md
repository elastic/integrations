# Azure Logs Integration

The Azure Logs integration collects logs for specific Azure services like Azure Active Directory (Sign-in, Audit, Identity Protection, and Provisioning logs), Azure Spring Cloud, Azure Firewall, and serveral others using the Activity and Platform logs.

You can then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference data when troubleshooting an issue.

For example, if you wanted to detect possible brute force sign-in attacks, you
could install the Azure Logs integration to send Azure sign-in logs to Elastic.
Then, set up a new rule in the Elastic Observability Logs app to alert you when the number of failed sign-in attempts exceeds a certain threshold.
Or, perhaps you want to better plan your Azure capacity.
Send Azure Activity logs to Elastic to track and visualize when your virtual machines
fail to start due to an exceed quota limit.

## Data streams

The Azure Logs integration collects logs.

**Logs** help you keep a record of events that happen on your Azure account.
Log data streams collected by the Azure Logs integration include Activity, Platform, Active Directory (Sign-in, Audit, Identity Protection, Provisioning), and Spring Cloud logs.

Check the [Logs reference](#logs-reference) for more details.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Before using the Azure integration you will need:

* One or more **Diagnostic setting** to export logs from Azure services to Event Hubs.
* One or more **Event Hub** to store in-flight logs exported by Azure services and make them available to Elastic Agent.
* One **Storage Account Container** to store information about logs consumed by the Elastic Agent.

### Diagnostic settings

Azure Diagnostic settings allow you to export metrics and logs from a **source** service, or resource, to one **destination** for analysis and long-term storage.

```text
   ┌──────────────────┐      ┌──────────────┐     ┌─────────────────┐
   │ Active Directory │      │  Diagnostic  │     │    Event Hub    │
   │    <<source>>    │─────▶│   settings   │────▶│ <<destination>> │
   └──────────────────┘      └──────────────┘     └─────────────────┘
```

Examples of source services:

* Active Directory
* Azure Monitor
* Spring Cloud

The Diagnostic settings support several destination types. The Elastic Agent requires a Diagnostic setting configured with Event Hub as the destination.

### Event Hub

[Azure Event Hubs](https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-about) is a data streaming platform and event ingestion service. It can receive and temporary store millions of events.

Elastic Agent with the Azure Logs integration will consume logs from the Event Hubs service.

```text
  ┌────────────────┐      ┌────────────┐
  │     adlogs     │      │  Elastic   │
  │ <<event hub>>  │─────▶│   Agent    │
  └────────────────┘      └────────────┘
```

To learn more about Event Hubs, refer to [Features and terminology in Azure Event Hubs](https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-features).

### Storage account container

The [Storage account](https://learn.microsoft.com/en-us/azure/storage/common/storage-account-overview) is a versatile Azure service that allows you to store data in various storage types, including blobs, file shares, queues, tables, and disks.

The Azure Logs integration uses a Storage account container to store and share information about the Consumer Group (state, position, or offset). Sharing such information allows multiple Elastic Agents assigned to the same agent policy to work together; this enables horizontal scaling of the logs processing when required.

```text
  ┌────────────────┐                     ┌────────────┐
  │     adlogs     │        logs         │  Elastic   │
  │ <<event hub>>  │────────────────────▶│   Agent    │
  └────────────────┘                     └────────────┘
                                                │      
                       consumer group info      │      
  ┌────────────────┐   (state, position, or     │      
  │   azurelogs    │         offset)            │      
  │ <<container>>  │◀───────────────────────────┘      
  └────────────────┘                                                                            
```

## Setup

Elastic strongly recommends installing the individual integrations ("Azure Active Directory" logs or "Azure Activity logs") instead of the collective ones ("Azure Logs"). This allows you to have a dedicated event hub for each Azure service or log group, the recommended approach for optimal performance.

Before adding the integration, you must complete the following tasks.

### Create an event hub

The event hub receives the logs exported from the Azure service and makes them available to the Elastic Agent to pick up.

Here's the high-level overview of the required steps:

* Create a resource group, or select an existing one.
* Create an event hubs namespace.
* Create an event hub.

For a detailed step-by-step guide, check the quickstart [Create an event hub using Azure portal](https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-create).

Take note of the event hub **Name**, which you will use later when specifying an **eventhub** in the integration settings.

#### Event hub namespace vs event hub

You should use the event hub name (not the event hub namespace name) as a value for the  **eventhub** option in the integration settings.

If you are new to Event Hub, think of the event hub namespace as the cluster and the event hub as the topic. You will typically have one cluster and multiple topics.

If you are familiar with Kafka, here's a conceptual mapping between the two:

| Kafka Concept  | Event Hub Concept |
|----------------|-------------------|
| Cluster        | Namespace         |
| Topic          | An event hub      |
| Partition      | Partition         |
| Consumer Group | Consumer Group    |
| Offset         | Offset            |

#### How many event hubs?

Elastic strongly recommends creating one event hub for each Azure service you collect data from.

For example, if you plan to collect Azure Active Directory (Azure AD) logs and Activity logs, create two event hubs: one for Azure AD and one for Activity logs.

Here's an high-level diagram of the solution:

```text
  ┌────────────────┐   ┌──────────────┐   ┌────────────────┐                    
  │    Azure AD    │   │  Diagnostic  │   │     adlogs     │                    
  │  <<service>>   │──▶│   settings   │──▶│ <<event hub>>  │──┐                 
  └────────────────┘   └──────────────┘   └────────────────┘  │   ┌────────────┐
                                                              │   │  Elastic   │
                                                              ├──▶│   Agent    │
  ┌────────────────┐   ┌──────────────┐   ┌────────────────┐  │   └────────────┘
  │ Azure Monitor  │   │  Diagnostic  │   │  activitylogs  │  │                 
  │  <<service>>   ├──▶│   settings   │──▶│ <<event hub>>  │──┘                 
  └────────────────┘   └──────────────┘   └────────────────┘                                    
```

Having one event hub for each Azure service is beneficial in terms of performance and easy of troubleshooting.

For high-volume deployments, we recommend one event hub for each data stream:

```text
                       ┌──────────────┐   ┌─────────────────────┐                   
                       │  Diagnostic  │   │   signin (adlogs)   │                   
                    ┌─▶│   settings   │──▶│    <<event hub>>    │──┐                
                    │  └──────────────┘   └─────────────────────┘  │                
                    │                                              │                
 ┌────────────────┐ │  ┌──────────────┐   ┌─────────────────────┐  │  ┌────────────┐
 │    Azure AD    │ │  │  Diagnostic  │   │   audit (adlogs)    │  │  │  Elastic   │
 │  <<service>>   │─┼─▶│   settings   │──▶│    <<event hub>>    │──┼─▶│   Agent    │
 └────────────────┘ │  └──────────────┘   └─────────────────────┘  │  └────────────┘
                    │                                              │                
                    │  ┌──────────────┐   ┌─────────────────────┐  │                
                    │  │  Diagnostic  │   │provisioning (adlogs)│  │                
                    └─▶│   settings   │──▶│    <<event hub>>    │──┘                
                       └──────────────┘   └─────────────────────┘                   
```

#### Consumer Group

Like all other event hub clients, Elastic Agent needs a consumer group name to access the event hub.

A Consumer Group is a view (state, position, or offset) of an entire event hub. Consumer groups enable multiple agents to each have a separate view of the event stream, and to read the logs independently at their own pace and with their own offsets.

Consumer groups allow multiple Elastic Agents assigned to the same agent policy to work together; this enables horizontal scaling of the logs processing when required.

In most cases, you can use the default consumer group named `$Default`. If `$Default` is already used by other applications, you can create a consumer group dedicated to the Azure Logs integration.

#### Connection string

The Elastic Agent requries a connection string to access the event hub and fetch the exported logs. The connection string contains details about the event hub used and the credentials required to access it.

To get the connection string for your event hub namespace:

1. Visit the **Event Hubs namespace** you created in a previous step.
1. Select **Settings** > **Shared access policies**.

Create a new Shared Access Policy (SAS):

1. Select **Add** to open the creation panel.
1. Add a **Policy name** (for example, "ElasticAgent").
1. Select the **Listen** claim.
1. Select **Create**.

When the SAS Policy is ready, select it to display the information panel.

Take note of the **Connection string–primary key**, which you will use later when specifying a **connection_string** in the integration settings.

### Create a Diagnostic settings

The Diagnostic settings export the logs from Azure services to a destination and in order to use Azure Logs integration, it must be an Event Hub.

To create a diagnostic settings to export logs:

1. Locate the Diagnostic settings for the service (for example, Azure Active Directory).
1. Select Diagnostic settings in the **Monitoring** section of the service. Note that different services may place the diagnostic settings in different positions.
1. Select **Add diagnostic setting**.

In the diagnostic settings page you have to select the source **log categories** you want to export and then select their **destination**.

#### Select log categories

Each Azure services exports a well-defined list of log categories. Check the individual integration doc to learn which log categories are supported by the integration.

#### Select the destination

Select the **subscription** and the **event hub namespace** you previously created. Select the event hub dedicated to this integration.

```text
  ┌────────────────┐   ┌──────────────┐   ┌────────────────┐      ┌────────────┐
  │    Azure AD    │   │  Diagnostic  │   │     adlogs     │      │  Elastic   │
  │  <<service>>   ├──▶│   settings   │──▶│ <<event hub>>  │─────▶│   Agent    │
  └────────────────┘   └──────────────┘   └────────────────┘      └────────────┘
```

### Create a Storage account container

The Elastic Agent stores the consumer group information (state, position, or offset) in a Storage account container. Making this information available to all agents allows them to share the logs processing and resume from the last processed logs after a restart.

To create the Storage account:

1. Sign in to the [Azure Portal](https://portal.azure.com/).
1. Search for and select **Storage accounts**.
1. Under **Project details**, select a subscription and a resource group.
1. Under **Instance details**, enter a **Storage account name**.
1. Select **Create**.

Take note of the **Storage account name**, which you will use later when specifying the **storage_account** in the integration settings.

When the new Storage account is ready, you can look for the access keys:

1. Select the Storage account.
1. In **Security + networking** select **Access keys**.
1. In the **key1** section, click on the **Show** button and copy the **Key** value.

Take note of the **Key** value, which you will use later when specifying the **storage_account_key** in the integration settings.

This is the final diagram of the a setup for collecting Activity logs from the Azure Monitor service.

```text
  ┌────────────────┐   ┌──────────────┐   ┌────────────────┐         ┌────────────┐
  │Active Directory│   │  Diagnostic  │   │     adlogs     │  logs   │  Elastic   │
  │  <<service>>   ├──▶│   settings   │──▶│ <<event hub>>  │────────▶│   Agent    │
  └────────────────┘   └──────────────┘   └────────────────┘         └────────────┘
                                                                            │      
                       ┌──────────────┐          consumer group info        │      
                       │  azurelogs   │          (state, position, or       │      
                       │<<container>> │◀───────────────offset)──────────────┘      
                       └──────────────┘                                                             
```

#### How many Storage account containers?

The Elastic Agent can use one Storage account container for all integrations.

The Agent will use the integration name and the event hub name to identify the blob to store the consumer group information uniquely.

## Settings

Use the following settings to configure the Azure Logs integration when you add it to Fleet.

`eventhub` :
_string_
A fully managed, real-time data ingestion service. Elastic recommends using only letters, numbers, and the hyphen (-) character for Event Hub names to maximize compatibility. You can use existing Event Hubs having underscores (_) in the Event Hub name; in this case, the integration will replace underscores with hyphens (-) when it uses the Event Hub name to create dependent Azure resources behind the scenes (e.g., the storage account container to store Event Hub consumer offsets). Elastic also recommends using a separate event hub for each log type as the field mappings of each log type differ.
Default value `insights-operational-logs`.

`consumer_group` :
_string_
Enable the publish/subscribe mechanism of Event Hubs with consumer groups. A consumer group is a view (state, position, or offset) of an entire event hub. Consumer groups enable multiple consuming applications to each have a separate view of the event stream, and to read the stream independently at their own pace and with their own offsets.
Default value: `$Default`

`connection_string` :
_string_

The connection string required to communicate with Event Hubs. See [Get an Event Hubs connection string](https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-get-connection-string) for more information.

A Blob Storage account is required to store/retrieve/update the offset or state of the Event Hub messages. This allows the integration to start back up at the spot that it stopped processing messages.

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

## Reference

Visit the page for each individual Azure Logs integration to see details about exported fields and sample events.
