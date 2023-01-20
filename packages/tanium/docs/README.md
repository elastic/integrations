# Tanium

The [Tanium](https://www.tanium.com/) integration allows you to monitor Action History, Client Status, Discover, Endpoint Config, Reporting, and Threat Response Logs. Tanium is an enterprise platform that's primarily used as an endpoint management tool. It empowers security and IT operations teams with quick visibility and control to secure and manage every endpoint on the network, scaling to millions of endpoints with limited infrastructure. Tanium Connect is used to capture accurate and complete endpoint data from Tanium.

The Tanium integration can be used in four different modes to collect data:
- TCP mode: Tanium pushes logs directly to a TCP port hosted by your Elastic Agent.
- HTTP Endpoint mode: Tanium pushes logs directly to an HTTP endpoint hosted by your Elastic Agent.
- AWS S3 polling mode: Tanium writes data to S3, and Elastic Agent polls the S3 bucket by listing its contents and reading new files.
- AWS S3 SQS mode: Tanium writes data to S3, S3 sends a notification of a new object to SQS, the Elastic Agent receives the notification from SQS, and then reads the S3 object. Multiple agents can be used in this mode.

## Compatibility

This module has been tested against the latest Tanium Instance version **7.5.5.1162**.
Versions above this are expected to work but have not been tested.

## Data streams

The Tanium integration collects logs for six types of events: action history, client status, discover, endpoint config, reporting, and threat response.

## Requirements

You need Elasticsearch to store and search your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended or self-manage the Elastic Stack on your hardware.

## Setup

### To collect data from an AWS S3 bucket, follow the below steps:
- Considering you already have an AWS S3 bucket setup, to create a connection for AWS S3 as a destination, follow this [link](https://docs.tanium.com/connect/connect/aws.html ).
- As we are always expecting data in JSON format, while creating the connection, select the format as JSON and deselect the `Generate Document option`.
- The default value of the field `Bucket List Prefix` is listed below.

  | Data Stream Name  | Bucket List Prefix     |
  | ----------------- | ---------------------- |
  | Action History    | action_history         |
  | Client Status     | client_status          |
  | Discover          | discover               |
  | Endpoint Config   | endpoint_config        |
  | Reporting         | reporting              |
  | Threat Response   | threat_response        |

**NOTE**: User can have any value which should match with bucket List Prefix.
### To collect data from AWS SQS, follow the below steps:
1. Assuming you've already set up a connection to push data into the AWS bucket; if not, see the section above.
2. To set up an SQS queue, follow "Step 1: Create an Amazon SQS Queue" mentioned in the [link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ways-to-add-notification-config-to-bucket.html).
  - While creating an Access Policy, use the bucket name configured to create a connection for AWS S3 in Tanium.
3. Configure event notifications for an S3 bucket. Follow this [link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-event-notifications.html).
  - It is recommended to configure separate `event notification` for each data stream using different bucket list prefixes.
  - While creating `event notification` select the event type as s3:ObjectCreated:*, destination type SQS Queue and select the queue name created in Step 2.

### To collect data from the Tanium HTTP Endpoint, follow the below steps:
- Considering you already have HTTP endpoint hosted, to create a connection for HTTP as destination follow this [link](https://docs.tanium.com/connect/connect/http.html).
- As we are always expecting data in JSON format so while Creating the Connection, Select the Format as Json and deselect the `Generate Document option`.
- Add some custom header and its value for additional security.

### To collect data from TCP, follow the below steps:
- While creating a connection, select the Socket Receiver as a destination.
- Choose the type of source you want to obtain.
- As we are always expecting data in JSON format so while Creating the Connection, Select the Format as Json and deselect the `Generate Document option`.
- Mention HTTP endpoint in the field Host
- Mention port in the field Port to create a TCP connection.
- Finally, select TCP as Network Protocol.

## Logs reference

### Action-History

This is the `action_history` dataset.
The HTTP Endpoint's default port is _9577_.
TCP's default port is _9578_.

#### Example

An example event for `action_history` looks as following:

```json
{
    "@timestamp": "2023-01-20T06:04:14.992Z",
    "agent": {
        "ephemeral_id": "8677a430-d2f8-4d4f-b056-41a57be452ac",
        "hostname": "docker-fleet-agent",
        "id": "0d1163ec-b01a-4f54-95ef-c4be662ebcdb",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.17.0"
    },
    "data_stream": {
        "dataset": "tanium.action_history",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.6.0"
    },
    "elastic_agent": {
        "id": "0d1163ec-b01a-4f54-95ef-c4be662ebcdb",
        "snapshot": false,
        "version": "7.17.0"
    },
    "event": {
        "action": "Deploy Client Configuration and Support [Mac](universal)",
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "dataset": "tanium.action_history",
        "end": "2022-10-04T17:38:42.000Z",
        "ingested": "2023-01-20T06:04:16Z",
        "kind": [
            "event"
        ],
        "original": "{\"Issuer\": \"tanium\",\"SourceId\": 10,\"Expiration\": \"2022-10-04T17:38:42\",\"ActionName\": \"Deploy Client Configuration and Support [Mac](universal)\",\"Command\": \"/bin/sh -c 'chmod u+x TaniumCX \u0026\u0026 ./TaniumCX bootstrap --zip bootstrap.zip'\",\"Approver\": \"tanium\",\"Status\": \"Closed\",\"DistributeOver\": \"1 minutes\",\"PackageName\": \"Client Configuration and Support [Mac](universal)\",\"Comment\": \"\",\"StartTime\": \"2022-10-04T16:38:42\",\"InsertTime\": \"2022-10-04T16:38:48\",\"ActionId\": 6058}",
        "provider": "tanium",
        "start": "2022-10-04T16:38:42.000Z",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "tcp"
    },
    "log": {
        "source": {
            "address": "192.168.16.1:52018"
        }
    },
    "process": {
        "command_line": "/bin/sh -c 'chmod u+x TaniumCX \u0026\u0026 ./TaniumCX bootstrap --zip bootstrap.zip'"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "tanium-action_history"
    ],
    "tanium": {
        "action_history": {
            "action": {
                "id": 6058,
                "name": "Deploy Client Configuration and Support [Mac](universal)"
            },
            "approver": "tanium",
            "command": "/bin/sh -c 'chmod u+x TaniumCX \u0026\u0026 ./TaniumCX bootstrap --zip bootstrap.zip'",
            "distribute_over": "1 minutes",
            "expiration": "2022-10-04T17:38:42.000Z",
            "insert_time": "2022-10-04T16:38:48.000Z",
            "issuer": "tanium",
            "package_name": "Client Configuration and Support [Mac](universal)",
            "source_id": 10,
            "start_time": "2022-10-04T16:38:42.000Z",
            "status": "Closed"
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type. | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.command_line.text | Multi-field of `process.command_line`. | match_only_text |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| tanium.action_history.action.id | Action Id. | long |
| tanium.action_history.action.name | Action Name. | keyword |
| tanium.action_history.approver | Approver of the action. | keyword |
| tanium.action_history.command | Command of the action. | keyword |
| tanium.action_history.comment | Comment on the action. | keyword |
| tanium.action_history.distribute_over | Distribution time of the action. | keyword |
| tanium.action_history.expiration | Expiration time of the action. | date |
| tanium.action_history.insert_time | Insert time of the action. | date |
| tanium.action_history.issuer | Issuer of the action. | keyword |
| tanium.action_history.package_name | Package name of the action. | keyword |
| tanium.action_history.source_id | Source Id of the action. | long |
| tanium.action_history.start_time | Start time of the action. | date |
| tanium.action_history.status | Status of the action. | keyword |


### Client-Status

This is the `client_status` dataset.
The HTTP Endpoint's default port is _9579_.
TCP's default port is _9580_.

#### Example

An example event for `client_status` looks as following:

```json
{
    "@timestamp": "2023-01-20T06:06:27.810Z",
    "agent": {
        "ephemeral_id": "62f56ef8-d3bc-456a-a1d2-df56dd293058",
        "hostname": "docker-fleet-agent",
        "id": "0d1163ec-b01a-4f54-95ef-c4be662ebcdb",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.17.0"
    },
    "data_stream": {
        "dataset": "tanium.client_status",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.6.0"
    },
    "elastic_agent": {
        "id": "0d1163ec-b01a-4f54-95ef-c4be662ebcdb",
        "snapshot": false,
        "version": "7.17.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "tanium.client_status",
        "ingested": "2023-01-20T06:06:28Z",
        "kind": [
            "state"
        ],
        "original": "{\"id\": 1,\"MacAddress\": \"00-51-58-91-62-41\",\"MacOrganization\": \"VMware, Inc.\",\"IpAddress\": \"89.160.20.112\",\"NatIpAddress\": \"\",\"HostName\": \"otelco7_46.test.local\",\"Labels\": \"\",\"Locations\": \"\",\"TaniumComputerId\": 1558885994,\"Ports\": \"22,41000\",\"Os\": \"linux\",\"OsGeneration\": null,\"Managed\": 1,\"Unmanageable\": 0,\"Arp\": 0,\"Nmap\": 0,\"Ping\": 0,\"Connected\": 0,\"AwsApi\": 0,\"CentralizedNmap\": 0,\"SatelliteNmap\": 0,\"CreatedAt\": \"2022-11-18 09:30:26 +00:00\",\"UpdatedAt\": \"2022-11-18 10:10:57 +00:00\",\"FirstManagedAt\": null,\"LastManagedAt\": \"2022-11-18 10:10:57 +00:00\",\"LastDiscoveredAt\": null,\"Profile\": null,\"SatelliteDecId\": null,\"SatelliteName\": null}",
        "type": [
            "info"
        ]
    },
    "host": {
        "hostname": "otelco7_46.test.local"
    },
    "input": {
        "type": "tcp"
    },
    "log": {
        "source": {
            "address": "192.168.16.1:42624"
        }
    },
    "related": {
        "hosts": [
            "otelco7_46.test.local"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "tanium-client_status"
    ],
    "tanium": {
        "client_status": {
            "host_name": "otelco7_46.test.local"
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type. | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
| tanium.client_status.client_network_location | Network location of client. | ip |
| tanium.client_status.computer_id | Computer ID of client. | keyword |
| tanium.client_status.full_version | Full version of client. | version |
| tanium.client_status.host_name | Host Name of client. | keyword |
| tanium.client_status.last_registration | Last registration date of client. | date |
| tanium.client_status.protocol_version | Protocol version of client. | version |
| tanium.client_status.receive_state | Receive state of client. | keyword |
| tanium.client_status.registered_with_tLS | Registered with TLS or not. | long |
| tanium.client_status.send_state | Send state of client. | keyword |
| tanium.client_status.server_network_location | Network location of server. | ip |
| tanium.client_status.valid_key | Valid Key or not. | long |
| tanium.client_status.value | Status of client. | keyword |


### Discover

This is the `discover` dataset.
The HTTP Endpoint's default port is _9581_.
TCP's default port is _9582_.

#### Example

An example event for `discover` looks as following:

```json
{
    "@timestamp": "2023-01-20T06:08:34.670Z",
    "agent": {
        "ephemeral_id": "560a82dd-c715-49f1-92b3-5c126c5e1c71",
        "hostname": "docker-fleet-agent",
        "id": "0d1163ec-b01a-4f54-95ef-c4be662ebcdb",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.17.0"
    },
    "data_stream": {
        "dataset": "tanium.discover",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.6.0"
    },
    "elastic_agent": {
        "id": "0d1163ec-b01a-4f54-95ef-c4be662ebcdb",
        "snapshot": false,
        "version": "7.17.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "tanium.discover",
        "ingested": "2023-01-20T06:08:35Z",
        "kind": [
            "event"
        ],
        "original": "{\"Status\": \"Leader\",\"LastRegistration\": \"2022-10-07T09:20:08\",\"ProtocolVersion\": 315,\"ValidKey\": 1,\"ComputerId\": \"4008511043\",\"HostName\": \"dhcp-client02.local\",\"ClientNetworkLocation\": \"67.43.156.0\",\"ServerNetworkLocation\": \"81.2.69.192\",\"RegisteredWithTLS\": 1,\"SendState\": \"None\",\"ReceiveState\": \"None\",\"FullVersion\": \"7.4.9.1046\"}",
        "type": [
            "info"
        ]
    },
    "host": {
        "hostname": "dhcp-client02.local"
    },
    "input": {
        "type": "tcp"
    },
    "log": {
        "source": {
            "address": "192.168.16.1:49738"
        }
    },
    "related": {
        "hosts": [
            "dhcp-client02.local"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "tanium-discover"
    ],
    "tanium": {
        "discover": {
            "host_name": "dhcp-client02.local"
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type. | keyword |
| labels | Custom key/value pairs. Can be used to add meta information to events. Should not contain nested objects. All values are stored as keyword. Example: `docker` and `k8s` labels. | object |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| observer.ingress.interface.name | Interface name as reported by the system. | keyword |
| os.full | Operating system name, including the version or code name. | keyword |
| os.full.text | Multi-field of `os.full`. | match_only_text |
| os.type | Use the `os.type` field to categorize the operating system into one of the broad commercial families. If the OS you're dealing with is not listed as an expected value, the field should not be populated. Please let us know by opening an issue with ECS, to propose its addition. | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.mac | MAC address of the source. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| source.nat.ip | Translated ip of source based NAT sessions (e.g. internal client to internet) Typically connections traversing load balancers, firewalls, or routers. | ip |
| tags | List of keywords used to tag each event. | keyword |
| tanium.discover.arp | Address Resolution Protocol. | double |
| tanium.discover.aws_api | Aws Api version. | double |
| tanium.discover.centralized_nmap | Centralized Nmap. | double |
| tanium.discover.computer_id | Tanium computer ID. | long |
| tanium.discover.connected | Connected Count. | long |
| tanium.discover.created_at | Created time of discovery. | date |
| tanium.discover.first_managed_at | First managed time. | date |
| tanium.discover.host_name | Host Name. | keyword |
| tanium.discover.id | Tanium Discover ID. | keyword |
| tanium.discover.ip_address | Ip Address. | ip |
| tanium.discover.labels | Labels. | keyword |
| tanium.discover.last.discovered_at | Last Discover time. | date |
| tanium.discover.last.managed_at | Last managed time. | date |
| tanium.discover.locations | Location. | keyword |
| tanium.discover.mac_address | MAC Address. | keyword |
| tanium.discover.mac_organization | Mac organization name. | keyword |
| tanium.discover.managed | Managed count. | long |
| tanium.discover.nat_ip_address | Nat Ip Address. | ip |
| tanium.discover.nmap | Nmap. | double |
| tanium.discover.os | OS type. | keyword |
| tanium.discover.os_generation | OS generation. | keyword |
| tanium.discover.ping | Ping count. | long |
| tanium.discover.ports | Port list. | keyword |
| tanium.discover.profile | Discover profile. | keyword |
| tanium.discover.satellite.dec_id | Satellite discovers the time. | keyword |
| tanium.discover.satellite.name | Satellite Name. | keyword |
| tanium.discover.satellite.nmap | Satellite Nmap. | long |
| tanium.discover.unmanageable | Unmanageable count. | long |
| tanium.discover.updated_at | Updated Time. | date |


### Endpoint-Config

This is the `endpoint_config` dataset.
The HTTP Endpoint's default port is _9583_.
TCP's default port is _9584_.

#### Example

An example event for `endpoint_config` looks as following:

```json
{
    "@timestamp": "2023-01-20T06:10:46.951Z",
    "agent": {
        "ephemeral_id": "7ee8fc4a-9234-4fbe-8531-3df8465bad13",
        "hostname": "docker-fleet-agent",
        "id": "0d1163ec-b01a-4f54-95ef-c4be662ebcdb",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.17.0"
    },
    "data_stream": {
        "dataset": "tanium.endpoint_config",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.6.0"
    },
    "elastic_agent": {
        "id": "0d1163ec-b01a-4f54-95ef-c4be662ebcdb",
        "snapshot": false,
        "version": "7.17.0"
    },
    "event": {
        "action": "AUDIT_ACTION_CREATED",
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "dataset": "tanium.endpoint_config",
        "ingested": "2023-01-20T06:10:48Z",
        "kind": [
            "state"
        ],
        "original": "{\"timestamp\":\"2022-11-02T13:49:03.993426735Z\",\"action\":\"AUDIT_ACTION_CREATED\",\"user\":{\"user_id\":1,\"persona_id\":0},\"config_item\":{\"id\":9,\"domain\":\"endpoint-config\",\"data_category\":\"tools\",\"description\":\"Threat Response Stream Toolset\"}}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "tcp"
    },
    "log": {
        "source": {
            "address": "192.168.16.1:60252"
        }
    },
    "related": {
        "user": [
            "1"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "tanium-endpoint_config"
    ],
    "tanium": {
        "endpoint_config": {
            "action": "AUDIT_ACTION_CREATED",
            "item": {
                "data_category": "tools",
                "domain": "endpoint-config",
                "id": 9
            },
            "timestamp": "2022-11-02T13:49:03.993Z",
            "user": {
                "id": "1",
                "persona_id": 0
            }
        }
    },
    "user": {
        "id": "1"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type. | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| tanium.endpoint_config.action | Name of event's action. | keyword |
| tanium.endpoint_config.item.data_category | Data category of the config item. | keyword |
| tanium.endpoint_config.item.domain | Domain of the config item. | keyword |
| tanium.endpoint_config.item.id | Id of the config item. | long |
| tanium.endpoint_config.manifest.item_count | Item count of the manifest. | long |
| tanium.endpoint_config.manifest.items.data_category | Data category of the items of manifest. | keyword |
| tanium.endpoint_config.manifest.items.domain | Items domain of the manifest. | keyword |
| tanium.endpoint_config.manifest.items.ids | Item Ids of the manifest. | long |
| tanium.endpoint_config.manifest.non_windows_saved_action_id | Non Windows saved action id of the user. | long |
| tanium.endpoint_config.manifest.revision | Revision of the manifest. | long |
| tanium.endpoint_config.manifest.service_uuid | Service UUID of the manifest. | keyword |
| tanium.endpoint_config.manifest.windows_saved_action_id | Windows saved action id of the user. | long |
| tanium.endpoint_config.module.solution_context_id | Solution Context Id of the user. | keyword |
| tanium.endpoint_config.module.solution_id | Solution Id of the user. | keyword |
| tanium.endpoint_config.timestamp | Timestamp of the endpoint config. | date |
| tanium.endpoint_config.user.id | Id of the user. | keyword |
| tanium.endpoint_config.user.persona_id | Persona id of the user. | long |
| user.id | Unique identifier of the user. | keyword |


### Reporting

This is the `reporting` dataset.
The HTTP Endpoint's default port is _9585_.
TCP's default port is _9586_.

#### Example

An example event for `reporting` looks as following:

```json
{
    "@timestamp": "2023-01-20T06:13:04.232Z",
    "agent": {
        "ephemeral_id": "928341a3-4503-423c-a2ed-e9c4e02647ce",
        "hostname": "docker-fleet-agent",
        "id": "0d1163ec-b01a-4f54-95ef-c4be662ebcdb",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.17.0"
    },
    "data_stream": {
        "dataset": "tanium.reporting",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.6.0"
    },
    "elastic_agent": {
        "id": "0d1163ec-b01a-4f54-95ef-c4be662ebcdb",
        "snapshot": false,
        "version": "7.17.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "tanium.reporting",
        "ingested": "2023-01-20T06:13:05Z",
        "kind": [
            "event"
        ],
        "original": "{\"Computer Name\":\"localhost\",\"OS Platform\":\"Linux\",\"Operating System\":\"CentOS Linux release 7.9.2009 (Core)\",\"Virtual Platform\":\"VMware Virtual Platform\",\"Is Virtual\":\"Yes\",\"Manufacturer\":\"VMware, Inc.\",\"Model\":\"VMware Virtual Platform\",\"Count\":3}",
        "type": [
            "info"
        ]
    },
    "host": {
        "hostname": "localhost"
    },
    "input": {
        "type": "tcp"
    },
    "log": {
        "source": {
            "address": "192.168.16.1:43472"
        }
    },
    "os": {
        "name": "CentOS Linux release 7.9.2009 (Core)",
        "platform": "Linux"
    },
    "related": {
        "hosts": [
            "localhost"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "tanium-reporting"
    ],
    "tanium": {
        "reporting": {
            "computer_name": "localhost",
            "count": 3,
            "is_virtual": "Yes",
            "manufacturer": "VMware, Inc.",
            "model": "VMware Virtual Platform",
            "os": {
                "name": "CentOS Linux release 7.9.2009 (Core)",
                "platform": "Linux"
            },
            "virtual_platform": "VMware Virtual Platform"
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type. | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| os.name | Operating system name, without the version. | keyword |
| os.name.text | Multi-field of `os.name`. | match_only_text |
| os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| tanium.reporting.computer_name | Name of the computer. | keyword |
| tanium.reporting.count | Count of report on the computer system. | long |
| tanium.reporting.is_virtual | Boolean flag mentions if computer is virtualise or not. | keyword |
| tanium.reporting.manufacturer | Name of the virtualised platform manufacturer. | keyword |
| tanium.reporting.model | Version of virtualisation software. | keyword |
| tanium.reporting.os.name | Operating system name and version. | keyword |
| tanium.reporting.os.platform | Operating system platform name. | keyword |
| tanium.reporting.virtual_platform | Name of the software used for virtulisation. | keyword |


### Threat-Response

This is the `threat_response` dataset.
The HTTP Endpoint's default port is _9587_.
TCP's default port is _9588_.

#### Example

An example event for `threat_response` looks as following:

```json
{
    "@timestamp": "2023-01-20T06:15:21.934Z",
    "agent": {
        "ephemeral_id": "c388961b-7ebc-4343-b2ad-f1bbd4e2b39d",
        "hostname": "docker-fleet-agent",
        "id": "0d1163ec-b01a-4f54-95ef-c4be662ebcdb",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.17.0"
    },
    "data_stream": {
        "dataset": "tanium.threat_response",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.6.0"
    },
    "elastic_agent": {
        "id": "0d1163ec-b01a-4f54-95ef-c4be662ebcdb",
        "snapshot": false,
        "version": "7.17.0"
    },
    "event": {
        "action": "create",
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "dataset": "tanium.threat_response",
        "id": "1199",
        "ingested": "2023-01-20T06:15:23Z",
        "kind": [
            "event"
        ],
        "original": "{\"id\":1199,\"table\":\"LiveConnection\",\"rowId\":null,\"revision\":null,\"state\":\"{\\\"connectionId\\\":\\\"remote:worker-1:2471612114:2\\\",\\\"target\\\":{\\\"hostname\\\":\\\"worker-1\\\",\\\"eid\\\":\\\"2\\\"},\\\"sessionId\\\":\\\"bdb90d9c-7165-48f0-b455-2876a12cbc06\\\"}\",\"userId\":1,\"userName\":\"tanium\",\"action\":\"create\",\"createdAt\":\"2022-12-27T09:49:16.002Z\",\"updatedAt\":\"2022-12-27T09:49:16.002Z\"}",
        "type": [
            "info"
        ]
    },
    "host": {
        "hostname": "worker-1"
    },
    "input": {
        "type": "tcp"
    },
    "log": {
        "source": {
            "address": "192.168.16.1:37222"
        }
    },
    "related": {
        "hosts": [
            "worker-1"
        ],
        "user": [
            "1",
            "tanium"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "tanium-threat_response"
    ],
    "tanium": {
        "threat_response": {
            "action": "create",
            "created_at": "2022-12-27T09:49:16.002Z",
            "id": "1199",
            "state": {
                "connection_id": "remote:worker-1:2471612114:2",
                "session_id": "bdb90d9c-7165-48f0-b455-2876a12cbc06",
                "target": {
                    "eid": "2",
                    "hostname": "worker-1"
                }
            },
            "table": "LiveConnection",
            "updated_at": "2022-12-27T09:49:16.002Z",
            "user": {
                "id": "1",
                "name": "tanium"
            }
        }
    },
    "user": {
        "id": "1",
        "name": "tanium"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type. | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| tanium.threat_response.action | Action for the threat response. | keyword |
| tanium.threat_response.created_at | Create time for the threat response. | date |
| tanium.threat_response.id | Threat response id. | keyword |
| tanium.threat_response.revision | Revision of the threat response. | keyword |
| tanium.threat_response.row_id | Row id for the threat response. | keyword |
| tanium.threat_response.state.connection_id | Connection id of the threat response state. | keyword |
| tanium.threat_response.state.session_id | Session id of the threat response state. | keyword |
| tanium.threat_response.state.target.eid | Target eid of the threat response state. | keyword |
| tanium.threat_response.state.target.hostname | Target hostname of the threat response state. | keyword |
| tanium.threat_response.table | Table for the threat response. | keyword |
| tanium.threat_response.updated_at | Threat response update time. | date |
| tanium.threat_response.user.id | User id for the threat response. | keyword |
| tanium.threat_response.user.name | User name for the threat response. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |

