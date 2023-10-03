# Azure Functions

The Azure Functions integration allows you to monitor Azure Functions. Azure Functions is an event-driven, serverless compute platform that helps you develop more efficiently using the programming language of your choice. Triggers cause a function to run. A trigger defines how a function is invoked and a function must have exactly one trigger. 

Use this integration to build web APIs, respond to database changes, process IoT streams, manage message queues, and more. Refer common [Azure Functions scenarios](https://learn.microsoft.com/en-us/azure/azure-functions/functions-scenarios?pivots=programming-language-csharp) for more information.


## Data streams
The Azure Functions integration contains two data streams: [Function App Logs](#logs) and [Metrics](#metrics)

### Logs

Supported log categories:

| Log Category                 | Description                                                                                                                          |
|:----------------------------:|:------------------------------------------------------------------------------------------------------------------------------------:|
| Functionapplogs | Function app logs.        |


#### Requirements and setup

Refer to the [Azure Logs](https://docs.elastic.co/integrations/azure) page for more information about setting up and using this integration.

#### Configuration options
`eventhub` :
  _string_
An Event Hub is a fully managed, real-time data ingestion service. Elastic recommends using only letters, numbers, and the hyphen (-) character for Event Hub names to maximize compatibility. You can use existing Event Hubs having underscores (_) in the Event Hub name; in this case, the integration will replace underscores with hyphens (-) when it uses the Event Hub name to create dependent Azure resources behind the scenes (e.g., the storage account container to store Event Hub consumer offsets). Elastic also recommends using a separate event hub for each log type as the field mappings of each log type differ.
Default value `insights-operational-logs`.

`consumer_group` :
_string_
 The publish/subscribe mechanism of Event Hubs is enabled through consumer groups. A consumer group is a view (state, position, or offset) of an entire event hub. Consumer groups enable multiple consuming applications to each have a separate view of the event stream, and to read the stream independently at their own pace and with their own offsets.
Default value: `$Default`

`connection_string` :
_string_
The connection string is required to communicate with Event Hubs, see steps [here](https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-get-connection-string).

A Blob Storage account is required in order to store/retrieve/update the offset or state of the eventhub messages. This means that after stopping the Azure logs package it can start back up at the spot that it stopped processing messages.

`storage_account` :
_string_
The name of the storage account where the state/offsets will be stored and updated.

`storage_account_key` :
_string_
The storage account key, this key will be used to authorize access to data in your storage account.

`storage_account_container` :
_string_
The storage account container where the integration stores the checkpoint data for the consumer group. It is an advanced option to use with extreme care. You MUST use a dedicated storage account container for each Azure log type (activity, sign-in, audit logs, and others). DO NOT REUSE the same container name for more than one Azure log type. See [Container Names](https://docs.microsoft.com/en-us/rest/api/storageservices/naming-and-referencing-containers--blobs--and-metadata#container-names) for details on naming rules from Microsoft. The integration generates a default container name if not specified.

`resource_manager_endpoint` :
_string_
Optional, by default we are using the Azure public environment, to override, users can provide a specific resource manager endpoint in order to use a different Azure environment.

Resource manager endpoints:

```text
# Azure ChinaCloud
https://management.chinacloudapi.cn/

# Azure GermanCloud
https://management.microsoftazure.de/

# Azure PublicCloud 
https://management.azure.com/

# Azure USGovernmentCloud
https://management.usgovcloudapi.net/
```

An example event for `functionapplogs` looks as following:

```json
{
    "@timestamp": "2023-05-23T20:11:59.000Z",
    "azure": {
        "category": "FunctionAppLogs",
        "function": {
            "app_name": "test-function",
            "category": "Function.hello",
            "event_name": "FunctionStarted",
            "invocation_id": "d878e365-b3d6-4796-9292-7500acd0c677",
            "name": "Functions.hello",
            "host_instance_id": "bb84c437-4c26-4d0b-a06d-7fc2f16976e3",
            "host_version": "4.19.2.2",
            "level": "Information",
            "level_id": 2,
            "message": "Executing Functions.hello (Reason=This function was programmatically called via the host APIs., Id=d878e365-b3d6-4796-9292-7500acd0c677)",
            "process_id": 67,
            "role_instance": "54108609-638204200593759681"
        },
        "operation_name": "Microsoft.Web/sites/functions/log",
        "resource": {
            "group": "TEST-RG",
            "id": "/SUBSCRIPTIONS/12CABCB4-86E8-404F-A3D2-1DC9982F45CA/RESOURCEGROUPS/TEST-RG/PROVIDERS/MICROSOFT.WEB/SITES/TEST-FUNCTION",
            "name": "TEST-FUNCTION",
            "provider": "MICROSOFT.WEB/SITES"
        },
        "subscription_id": "12CABCB4-86E8-404F-A3D2-1DC9982F45CA"
    },
    "cloud": {
        "account": {
            "id": "12CABCB4-86E8-404F-A3D2-1DC9982F45CA"
        },
        "provider": "azure"
    },
    "ecs": {
        "version": "8.7.0"
    },
    "event": {
        "original": "{\"time\":\"2023-05-23T20:11:59Z\",\"resourceId\":\"/SUBSCRIPTIONS/12CABCB4-86E8-404F-A3D2-1DC9982F45CA/RESOURCEGROUPS/TEST-RG/PROVIDERS/MICROSOFT.WEB/SITES/TEST-FUNCTION\",\"category\":\"FunctionAppLogs\",\"operationName\":\"Microsoft.Web/sites/functions/log\",\"level\":\"Informational\",\"location\":\"East US\",\"properties\":{\"appName\":\"test-function\",\"roleInstance\":\"54108609-638204200593759681\",\"message\":\"Executing Functions.hello (Reason=This function was programmatically called via the host APIs., Id=d878e365-b3d6-4796-9292-7500acd0c677)\",\"category\":\"Function.hello\",\"hostVersion\":\"4.19.2.2\",\"functionInvocationId\":\"d878e365-b3d6-4796-9292-7500acd0c677\",\"functionName\":\"Functions.hello\",\"hostInstanceId\":\"bb84c437-4c26-4d0b-a06d-7fc2f16976e3\",\"level\":\"Information\",\"levelId\":2,\"processId\":67,\"eventId\":1,\"eventName\":\"FunctionStarted\"}}"
    },
    "observer": {
        "product": "Azure Functions",
        "type": "functions",
        "vendor": "Azure"
    },
    "tags": [
        "preserve_original_event"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| azure.category | The log category name. | keyword |
| azure.function.app_name | The Function application name. | keyword |
| azure.function.category | The category of the operation. | keyword |
| azure.function.event_id | The event ID. | long |
| azure.function.event_name | The event name. | keyword |
| azure.function.exception_details | The exception details. This includes the exception type, message, and stack trace. | match_only_text |
| azure.function.exception_message | The exception message. | match_only_text |
| azure.function.exception_type | The exception type. | keyword |
| azure.function.host_instance_id | The host instance ID. | keyword |
| azure.function.host_version | The Functions host version. | keyword |
| azure.function.invocation_id | The invocation ID that logged the message. | keyword |
| azure.function.level | The log level. Valid values are Trace, Debug, Information, Warning, Error, or Critical. | keyword |
| azure.function.level_id | The integer value of the log level. Valid values are 0 (Trace), 1 (Debug), 2 (Information), 3 (Warning), 4 (Error), or 5 (Critical). | long |
| azure.function.message | The log message. | keyword |
| azure.function.name | The name of the function that logged the message. | keyword |
| azure.function.process_id | The process ID. | long |
| azure.function.role_instance | The role instance ID. | keyword |
| azure.operation_name | The operation name. | keyword |
| azure.resource.group | Azure Resource group | keyword |
| azure.resource.id | Resource ID | keyword |
| azure.resource.name | Name | keyword |
| azure.resource.provider | Resource type/namespace | keyword |
| azure.subscription_id | Azure subscription ID | keyword |
| azure.tenant_id | tenant ID | keyword |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| error.stack_trace | The stack trace of this error in plain text. | wildcard |
| error.stack_trace.text | Multi-field of `error.stack_trace`. | match_only_text |
| error.type | The type of the error, for example the class name of the exception. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| observer.name | Custom name of the observer. This is a name that can be given to an observer. This can be helpful for example if multiple firewalls of the same model are used in an organization. If no custom name is needed, the field can be left empty. | keyword |
| observer.product | The product name of the observer. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| tags | List of keywords used to tag each event. | keyword |


### Metrics
**Metrics** give you insight into the performance of your Azure Function Apps. The integration includes an out-of-the-box dashboard for visualising the monitoring data generated by apps hosted in Azure Functions.

#### Requirements

To use this integration you will need:

* **Azure App Registration**: You need to set up an Azure App Registration to allow the Agent to access the Azure APIs. The App Registration requires the Monitoring Reader role to access to be able to collect metrics from Function Apps. See more details in the Setup section.
* **Elasticsearch and Kibana**: You need Elasticsearch to store and search your data and Kibana to visualize and manage it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, the [Native Azure Integration](https://azuremarketplace.microsoft.com/en-us/marketplace/apps/elastic.elasticsearch?tab=Overview), or self-manage the Elastic Stack on your hardware.

#### Setup


```text
         ┌────────────────────┐       ┌─────────┐       ┌─-─────────────────────┐
         │                    │       │         │       │    azure.functions    │
         │     Azure APIs     │──────▶│  Agent  │──────▶│    <<data stream>>    │
         │                    │       │         │       │                       │
         └────────────────────┘       └─────────┘       └───-───────────────────┘                                              
```

Elastic Agent needs an App Registration to access Azure on your behalf to collect data using the Azure REST APIs. App Registrations are required to access Azure APIs programmatically.

To start collecting data with this integration, you need to:

* Set up a new Azure app registration by registering an app, adding credentials, and assigning an appropriate role.
* Specify integration [settings](#main-options) in Kibana, which will determine how the integration will access the Azure APIs.

#### Register a new app

To create a new app registration:

1. Sign in to the [Azure Portal](https://portal.azure.com/).
2. Search for and select **Azure Active Directory**.
3. Under **Manage**, select **App registrations** > **New registration**.
4. Enter a display _Name_ for your application (for example, "elastic-agent").
5. Specify who can use the application.
6. Don't enter anything for _Redirect URI_. This is optional and the agent doesn't use it.
7. Select **Register** to complete the initial app registration.

Take note of the **Application (client) ID**, which you will use later when specifying the **Client ID** in the integration settings.

#### Add credentials

Credentials allow your application to access Azure APIs and authenticate itself, requiring no interaction from a user at runtime.

This integration uses Client Secrets to prove its identity.

1. In the [Azure Portal](https://portal.azure.com/), select the application you created in the previous section.
2. Select **Certificates & secrets** > **Client secrets** > **New client secret**.
3. Add a description (for example, "Elastic Agent client secrets").
4. Select an expiration for the secret or specify a custom lifetime.
5. Select **Add**.

Take note of the content in the **Value** column in the **Client secrets** table, which you will use later when specifying a **Client Secret** in the integration settings. **This secret value is never displayed again after you leave this page.** Record the secret's value in a safe place.

#### Assign role

1. In the [Azure Portal](https://portal.azure.com/), search for and select **Subscriptions**.
2. Select the subscription to assign the application.
3. Select **Access control (IAM)**.
4. Select **Add** > **Add role assignment** to open the _Add role assignment page_.
5. In the **Role** tab, search and select the role **Monitoring Reader**.
6. Select the **Next** button to move to the **Members** tab.
7. Select **Assign access to** > **User, group, or service principal**, and select **Select members**. This page does not display Azure AD applications in the available options by default.
8. To find your application, search by name (for example, "elastic-agent") and select it from the list.
9. Click the **Select** button.
10. Then click the **Review + assign** button.

Take note of the following values, which you will use later when specifying settings.

* `Subscription ID`: use the content of the "Subscription ID" you selected.
* `Tenant ID`: use the "Tenant ID" from the Azure Active Directory you use.

Your App Registration is now ready to be used with the Elastic Agent.

#### Additional Resources

If you want to learn more about this process, you can read these two general guides from Microsoft:

* [Quickstart: Register an application with the Microsoft identity platform](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app) 
* [Use the portal to create an Azure AD application and service principal that can access resources](https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal)

#### Main options

The settings' main section contains all the options needed to access the Azure APIs and collect the Azure Functions metrics data. You will now use all the values from [App registration](#register-a-new-app) including:

`Client ID` _string_
: The unique identifier of the App Registration (sometimes referred to as Application ID).

`Client Secret` _string_
: The client secret for authentication.

`Subscription ID` _string_
: The unique identifier for the Azure subscription. You can provide just one subscription ID. The Agent uses this ID to access Azure APIs. 

`Tenant ID` _string_
: The unique identifier of the Azure Active Directory's Tenant ID.

#### Advanced options

There are two additional advanced options:

`Resource Manager Endpoint` _string_
: Optional. By default, the integration uses the Azure public environment. To override, users can provide a specific resource manager endpoint to use a different Azure environment.

Examples:

* `https://management.chinacloudapi.cn` for Azure ChinaCloud
* `https://management.microsoftazure.de` for Azure GermanCloud
* `https://management.azure.com` for Azure PublicCloud
* `https://management.usgovcloudapi.net` for Azure USGovernmentCloud

`Active Directory Endpoint`  _string_
: Optional. By default, the integration uses the associated Active Directory Endpoint. To override, users can provide a specific active directory endpoint to use a different Azure environment.

Examples:

* `https://login.chinacloudapi.cn` for Azure ChinaCloud
* `https://login.microsoftonline.de` for Azure GermanCloud
* `https://login.microsoftonline.com` for Azure PublicCloud
* `https://login.microsoftonline.us` for Azure USGovernmentCloud

#### Metrics Reference

An example event for `metrics` looks as following:

```json
{
    "agent": {
        "name": "docker-fleet-agent",
        "id": "ae16c4cf-2550-452a-860d-cef5e5182e94",
        "type": "metricbeat",
        "ephemeral_id": "7511408f-f109-4e34-a405-98ad479fc097",
        "version": "8.7.1"
    },
    "@timestamp": "2023-08-23T12:20:00.000Z",
    "ecs": {
        "version": "8.0.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "azure.function"
    },
    "service": {
        "type": "azure"
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "5.15.49-linuxkit",
            "codename": "focal",
            "name": "Ubuntu",
            "family": "debian",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)",
            "platform": "ubuntu"
        },
        "containerized": false,
        "ip": [
            "172.19.0.9"
        ],
        "name": "docker-fleet-agent",
        "id": "fd2c4b0943e444508c12855a04d117c7",
        "mac": [
            "02-42-AC-13-00-09"
        ],
        "architecture": "x86_64"
    },
    "elastic_agent": {
        "id": "ae16c4cf-2550-452a-860d-cef5e5182e94",
        "version": "8.7.1",
        "snapshot": false
    },
    "metricset": {
        "period": 300000,
        "name": "monitor"
    },
    "event": {
        "duration": 42827917228,
        "agent_id_status": "verified",
        "ingested": "2023-08-23T12:25:34Z",
        "module": "azure",
        "dataset": "azure.function"
    },
    "azure": {
        "subscription_id": "12hjkls-78tyu-404f-a3d2-1dc9982f45ds",
        "timegrain": "PT5M",
        "functions": {
            "handles": {
                "avg": 0
            },
            "app_connections": {
                "avg": 0
            },
            "total_app_domains": {
                "avg": 0
            },
            "http_response_time": {
                "avg": 0.02796875
            },
            "bytes_received": {
                "total": 28804
            },
            "average_memory_working_set": {
                "avg": 328533059.5
            },
            "requests": {
                "total": 32
            },
            "bytes_sent": {
                "total": 8192
            },
            "requests_inapplication_queue": {
                "avg": 0
            },
            "memory_working_set": {
                "avg": 328533059.5
            },
            "io_write_bytes_per_second": {
                "total": 0
            },
            "io_other_bytes_per_second": {
                "total": 0
            },
            "total_app_domains_unloaded": {
                "avg": 0
            },
            "io_other_operations_per_second": {
                "total": 0
            },
            "io_read_bytes_per_second": {
                "total": 31879
            },
            "function_execution_units": {
                "total": 0
            },
            "io_read_operations_per_second": {
                "total": 0
            },
            "http2xx": {
                "total": 16
            },
            "http3xx": {
                "total": 0
            },
            "http4xx": {
                "total": 0
            },
            "io_write_operations_per_second": {
                "total": 0
            },
            "function_execution_count": {
                "total": 0
            },
            "http5xx": {
                "total": 16
            }
        },
        "resource": {
            "name": "return-of-the-jedi",
            "id": "/subscriptions/12hjkls-78tyu-404f-a3d2-1dc9982f45ds/resourceGroups/test-rg/providers/Microsoft.Web/sites/return-of-the-jedi",
            "type": "Microsoft.Web/sites",
            "group": "test-rg",
            "tags": {
                "hidden-link: /app-insights-resource-id": "/subscriptions/12hjkls-78tyu-404f-a3d2-1dc9982f45ds/resourceGroups/test-rg/providers/Microsoft.Insights/components/return-of-the-jedi"
            }
        },
        "namespace": "Microsoft.Web/sites"
    }
}
```

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| azure.application_id | The application ID | keyword |  |  |
| azure.dimensions.\* | Azure metric dimensions. | object |  |  |
| azure.functions.app_connections.avg | The number of bound sockets existing in the sandbox (w3wp.exe and its child processes). A bound socket is created by calling bind()/connect() APIs and remains until said socket is closed with CloseHandle()/closesocket(). For WebApps and FunctionApps.. | long |  | counter |
| azure.functions.average_memory_working_set.avg | The average amount of memory used by the app, in MiB. For WebApps and FunctionApps. | long | byte | gauge |
| azure.functions.bytes_received.total | The amount of incoming bandwidth consumed by the app, in MiB. | long | byte | gauge |
| azure.functions.bytes_sent.total | The amount of outgoing bandwidth consumed by the app, in MiB. | long | byte | gauge |
| azure.functions.current_assemblies.avg | The current number of Assemblies loaded across all AppDomains in this application. | long |  | gauge |
| azure.functions.file_system_usage.avg | Percentage of filesystem quota consumed by the app. | long | byte | gauge |
| azure.functions.function_execution_count.total | Function Execution Count. For FunctionApps only. | long |  | counter |
| azure.functions.function_execution_units.total | Function Execution Units. For FunctionApps only. | long |  | counter |
| azure.functions.gen_0_collections.total | The number of times the generation 0 objects are garbage collected since the start of the app process. Higher generation GCs include all lower generation GCs. | long |  | counter |
| azure.functions.gen_1_collections.total | The number of times the generation 1 objects are garbage collected since the start of the app process. Higher generation GCs include all lower generation GCs. | long |  | counter |
| azure.functions.gen_2_collections.total | The number of times the generation 2 objects are garbage collected since the start of the app process. Higher generation GCs include all lower generation GCs. | long |  | counter |
| azure.functions.handles.avg | The total number of handles currently open by the app process. | long |  | counter |
| azure.functions.health_check_status.avg | Health check status. | long |  | gauge |
| azure.functions.http2xx.total | The count of requests resulting in an HTTP status code \>= 200 but \< 300. | long |  | counter |
| azure.functions.http3xx.total | The count of requests resulting in an HTTP status code \>= 300 but \< 400. | long |  | counter |
| azure.functions.http4xx.total | The count of requests resulting in an HTTP status code \>= 400 but \< 500. | long |  | counter |
| azure.functions.http5xx.total | The count of requests resulting in an HTTP status code \>= 500 but \< 600. | long |  | counter |
| azure.functions.http_response_time.avg | The time taken for the app to serve requests, in seconds. | long | s | gauge |
| azure.functions.io_other_bytes_per_second.total | The rate at which the app process is issuing bytes to I/O operations that don't involve data, such as control operations. Shown as bytespersecond. | long |  | gauge |
| azure.functions.io_other_operations_per_second.total | The rate at which the app process is issuing I/O operations that aren't read or write operations. Shown as bytespersecond. | long |  | gauge |
| azure.functions.io_read_bytes_per_second.total | The rate at which the app process is reading bytes from I/O operations. Shown as bytespersecond. | long |  | gauge |
| azure.functions.io_read_operations_per_second.total | The rate at which the app process is issuing read I/O operations. Shown as bytespersecond. | long |  | gauge |
| azure.functions.io_write_bytes_per_second.total | The rate at which the app process is writing bytes to I/O operations. Shown as bytespersecond. | long |  | gauge |
| azure.functions.io_write_operations_per_second.total | The rate at which the app process is issuing write I/O operations. Shown as bytespersecond. | long |  | gauge |
| azure.functions.memory_working_set.avg | The current amount of memory used by the app, in MiB. | long | byte | gauge |
| azure.functions.private_bytes.avg | Private Bytes is the current size, in bytes, of memory that the app process has allocated that can't be shared with other processes. | long | byte | gauge |
| azure.functions.requests.total | The total number of requests regardless of their resulting HTTP status code. | long |  | counter |
| azure.functions.requests_inapplication_queue.avg | The number of requests in the application request queue. | long |  | counter |
| azure.functions.threads.avg | The number of threads currently active in the app process. | long |  | gauge |
| azure.functions.total_app_domains.avg | The current number of AppDomains loaded in this application. | long |  | gauge |
| azure.functions.total_app_domains_unloaded.avg | The total number of AppDomains unloaded since the start of the application. | long |  | gauge |
| azure.namespace | The namespace selected | keyword |  |  |
| azure.resource.group | The resource group | keyword |  |  |
| azure.resource.id | The id of the resource | keyword |  |  |
| azure.resource.name | The name of the resource | keyword |  |  |
| azure.resource.tags.\* | Azure resource tags. | object |  |  |
| azure.resource.type | The type of the resource | keyword |  |  |
| azure.subscription_id | The subscription ID | keyword |  |  |
| azure.timegrain | The Azure metric timegrain | keyword |  |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |  |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |  |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |  |
| cloud.instance.id | Instance ID of the host machine. | keyword |  |  |
| cloud.instance.name | Instance name of the host machine. | keyword |  |  |
| cloud.machine.type | Machine type of the host machine. | keyword |  |  |
| cloud.project.id | Name of the project in Google Cloud. | keyword |  |  |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |  |  |
| cloud.region | Region in which this host is running. | keyword |  |  |
| container.id | Unique container id. | keyword |  |  |
| container.image.name | Name of the image the container was built on. | keyword |  |  |
| container.labels | Image labels. | object |  |  |
| container.name | Container name. | keyword |  |  |
| container.runtime | Runtime managing this container. | keyword |  |  |
| data_stream.dataset | Data stream dataset name. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| dataset.name | Dataset name. | constant_keyword |  |  |
| dataset.namespace | Dataset namespace. | constant_keyword |  |  |
| dataset.type | Dataset type. | constant_keyword |  |  |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |  |  |
| host | A host is defined as a general computing instance. ECS host.\* fields should be populated with details about the host on which the event happened, or from which the measurement was taken. Host types include hardware, virtual machines, Docker containers, and Kubernetes nodes. | group |  |  |
| host.architecture | Operating system architecture. | keyword |  |  |
| host.containerized | If the host is a container. | boolean |  |  |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |  |  |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |  |  |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |  |  |
| host.ip | Host ip addresses. | ip |  |  |
| host.mac | Host mac addresses. | keyword |  |  |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |  |  |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |  |  |
| host.os.name | Operating system name, without the version. | keyword |  |  |
| host.os.name.text | Multi-field of `host.os.name`. | text |  |  |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |  |  |
| host.os.version | Operating system version as a raw string. | keyword |  |  |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |  |  |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |  |  |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |  |  |

