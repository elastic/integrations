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
    "@timestamp": "2023-02-16T06:48:27.439Z",
    "agent": {
        "ephemeral_id": "b09b3fe4-45a1-4d81-b64d-075be6cac5d6",
        "id": "2cc42030-c8c1-410b-8cef-c2db3ff157ec",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.3.0"
    },
    "data_stream": {
        "dataset": "tanium.action_history",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "2cc42030-c8c1-410b-8cef-c2db3ff157ec",
        "snapshot": false,
        "version": "8.3.0"
    },
    "event": {
        "action": "Deploy Client Configuration and Support [Mac](universal)",
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "dataset": "tanium.action_history",
        "end": "2022-10-04T17:38:42.000Z",
        "ingested": "2023-02-16T06:48:28Z",
        "kind": [
            "event"
        ],
        "original": "{\"Issuer\": \"tanium\",\"SourceId\": 10,\"Expiration\": \"2022-10-04T17:38:42\",\"ActionName\": \"Deploy Client Configuration and Support [Mac](universal)\",\"Command\": \"/bin/sh -c 'chmod u+x TaniumCX && ./TaniumCX bootstrap --zip bootstrap.zip'\",\"Approver\": \"tanium\",\"Status\": \"Closed\",\"DistributeOver\": \"1 minutes\",\"PackageName\": \"Client Configuration and Support [Mac](universal)\",\"Comment\": \"\",\"StartTime\": \"2022-10-04T16:38:42\",\"InsertTime\": \"2022-10-04T16:38:48\",\"ActionId\": 6058}",
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
            "address": "192.168.32.4:39418"
        }
    },
    "process": {
        "command_line": "/bin/sh -c 'chmod u+x TaniumCX && ./TaniumCX bootstrap --zip bootstrap.zip'"
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
            "command": "/bin/sh -c 'chmod u+x TaniumCX && ./TaniumCX bootstrap --zip bootstrap.zip'",
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
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
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
    "@timestamp": "2023-02-16T06:50:20.629Z",
    "agent": {
        "ephemeral_id": "e74d0cdf-30ac-42e8-823d-ec02753950a5",
        "id": "2cc42030-c8c1-410b-8cef-c2db3ff157ec",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.3.0"
    },
    "data_stream": {
        "dataset": "tanium.client_status",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "2cc42030-c8c1-410b-8cef-c2db3ff157ec",
        "snapshot": false,
        "version": "8.3.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "tanium.client_status",
        "ingested": "2023-02-16T06:50:21Z",
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
            "address": "192.168.32.4:45582"
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
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
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
    "@timestamp": "2023-02-20T09:20:45.673Z",
    "agent": {
        "ephemeral_id": "2e16390e-7187-4f16-b2a9-597a20f08567",
        "id": "c43758c9-08d7-42f2-b258-f39e4373d45a",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.3.0"
    },
    "data_stream": {
        "dataset": "tanium.discover",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "c43758c9-08d7-42f2-b258-f39e4373d45a",
        "snapshot": false,
        "version": "8.3.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "tanium.discover",
        "ingested": "2023-02-20T09:20:46Z",
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
            "address": "172.24.0.5:43366"
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
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
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
    "@timestamp": "2023-02-28T11:55:45.989Z",
    "agent": {
        "ephemeral_id": "06f3036e-23f0-4d9d-a3c9-2d967e4878f1",
        "id": "7ac2bc6a-9f9b-4289-82db-ee2a0a7e6ef8",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.3.0"
    },
    "data_stream": {
        "dataset": "tanium.endpoint_config",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "7ac2bc6a-9f9b-4289-82db-ee2a0a7e6ef8",
        "snapshot": false,
        "version": "8.3.0"
    },
    "event": {
        "action": "AUDIT_ACTION_CREATED",
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "dataset": "tanium.endpoint_config",
        "ingested": "2023-02-28T11:55:47Z",
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
            "address": "172.20.0.6:44106"
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
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
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


### Reporting

This is the `reporting` dataset.
The HTTP Endpoint's default port is _9585_.
TCP's default port is _9586_.

#### Example

An example event for `reporting` looks as following:

```json
{
    "@timestamp": "2023-02-16T06:56:06.805Z",
    "agent": {
        "ephemeral_id": "3e94d921-228f-463b-9de4-4b217fc4a648",
        "id": "2cc42030-c8c1-410b-8cef-c2db3ff157ec",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.3.0"
    },
    "data_stream": {
        "dataset": "tanium.reporting",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "2cc42030-c8c1-410b-8cef-c2db3ff157ec",
        "snapshot": false,
        "version": "8.3.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "tanium.reporting",
        "ingested": "2023-02-16T06:56:07Z",
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
            "address": "192.168.32.4:37856"
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
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
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
    "@timestamp": "2023-01-18T10:13:28.000Z",
    "agent": {
        "ephemeral_id": "1bb8672f-7719-445c-8d9d-867a700f2c18",
        "id": "7ac2bc6a-9f9b-4289-82db-ee2a0a7e6ef8",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.3.0"
    },
    "data_stream": {
        "dataset": "tanium.threat_response",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "7ac2bc6a-9f9b-4289-82db-ee2a0a7e6ef8",
        "snapshot": false,
        "version": "8.3.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "dataset": "tanium.threat_response",
        "id": "00000000-0000-0000-5389-4a274d06f4ec",
        "ingested": "2023-02-28T11:58:39Z",
        "kind": [
            "event"
        ],
        "original": "{\"Computer IP\":\"81.2.69.192\",\"Computer Name\":\"worker-2\",\"Event Id\":\"00000000-0000-0000-5389-4a274d06f4ec\",\"Event Name\":\"detect.unmatch\",\"Other Parameters\":\"payload=eyJpbnRlbF9pZCI6MTM1LCJjb25maWdfaWQiOjMsImNvbmZpZ19yZXZfaWQiOjEsImZpbmRpbmciOnsid2hhdHMiOlt7ImludGVsX2ludHJhX2lkcyI6W3siaWQiOjg1MDM5NDU4Mn0seyJpZCI6OTgzOTYyMTkzfSx7ImlkIjoyNjY3MDYyMDA2fSx7ImlkIjozMzk4NDE2ODc4fSx7ImlkIjozOTk5MDE0NDY1fV0sInNvdXJjZV9uYW1lIjoicmVjb3JkZXIiLCJhcnRpZmFjdF9hY3Rpdml0eSI6eyJyZWxldmFudF9hY3Rpb25zIjpbeyJ2ZXJiIjo2LCJ0YXJnZXQiOnsiZmlsZSI6eyJwYXRoIjoiL3Zhci9saWIvZG9ja2VyL292ZXJsYXkyLzJiY2ZmYjdmMGQ2YTNmMzdhNjE5OWNhNjkxNjQ5ZWE0OTM1OGEyYzJlODdmMzkyMDI1NjJlNTBlYjVjZDI4MDUvZGlmZi9ldGMvaG9zdHMiLCJoYXNoIjp7Im1kNSI6IjRkMWYxMjU3Yjg0NmJkYTgyZDAzMzhmYjU0MWU3MzAxIiwic2hhMSI6IjA0M2ViMzI0YTY1MzQ1NmNhYTFhNzNlMmUyZDQ5Zjc3NzkyYmIwYzUiLCJzaGEyNTYiOiJlMzk5OGRiZTAyYjUxZGFkYTMzZGU4N2FlNDNkMThhOTNhYjY5MTViOWUzNGY1YTc1MWJmMmI5YjI1YTU1NDkyIn0sInNpemVfYnl0ZXMiOiI3OSIsIm1vZGlmaWNhdGlvbl90aW1lIjoiMjAyMi0wOS0xMVQyMDowODoyNi4wMDBaIiwiaW5zdGFuY2VfaGFzaF9zYWx0IjoiMzAxNDc2NyIsIm1hZ2ljX251bWJlcl9oZXgiOiIzMTMyMzcyZSJ9LCJpbnN0YW5jZV9oYXNoIjoiOTY2NzAxNzM0NTE1MDk2ODM0MiIsImFydGlmYWN0X2hhc2giOiIxMDUzODAwNDU2MTA2MjQ5MDYifSwidGltZXN0YW1wIjoiMjAyMy0wMS0xOFQxMDozNzoxOC4wMDBaIiwidGFuaXVtX3JlY29yZGVyX2V2ZW50X3RhYmxlX2lkIjoiNDYxMTY4NjAxODQ3NTg1NTY3MiIsInRhbml1bV9yZWNvcmRlcl9jb250ZXh0Ijp7ImZpbGUiOnsidW5pcXVlX2V2ZW50X2lkIjoiNDYxMTY4NjAxODQ3NTg1NTY3MiJ9LCJldmVudCI6eyJ0aW1lc3RhbXBfbXMiOiIxNjc0MDM4MjM4NzgwIiwiZmlsZV9jcmVhdGUiOnsicGF0aCI6Ii92YXIvbGliL2RvY2tlci9vdmVybGF5Mi8yYmNmZmI3ZjBkNmEzZjM3YTYxOTljYTY5MTY0OWVhNDkzNThhMmMyZTg3ZjM5MjAyNTYyZTUwZWI1Y2QyODA1L2RpZmYvZXRjL2hvc3RzIn19fX1dLCJhY3RpbmdfYXJ0aWZhY3QiOnsicHJvY2VzcyI6eyJoYW5kbGVzIjpbXSwicGlkIjo0MzE4MSwiYXJndW1lbnRzIjoiZG9ja2VyLXVudGFyIC8gL3Zhci9saWIvZG9ja2VyL292ZXJsYXkyLzJiY2ZmYjdmMGQ2YTNmMzdhNjE5OWNhNjkxNjQ5ZWE0OTM1OGEyYzJlODdmMzkyMDI1NjJlNTBlYjVjZDI4MDUvZGlmZiIsImZpbGUiOnsiZmlsZSI6eyJwYXRoIjoiL3Byb2Mvc2VsZi9leGUifSwiaW5zdGFuY2VfaGFzaCI6IjEzMTY0NjgzMDA4MzA4NzMzMjM2IiwiYXJ0aWZhY3RfaGFzaCI6IjEzMTY0NjgzMDA4MzA4NzMzMjM2In0sInVzZXIiOnsidXNlciI6eyJuYW1lIjoicm9vdCIsImRvbWFpbiI6InJvb3QiLCJ1c2VyX2lkIjoiMCIsImdyb3VwX2lkIjoiMCJ9fSwicGFyZW50Ijp7InByb2Nlc3MiOnsiaGFuZGxlcyI6W10sInBpZCI6MjA1OCwiYXJndW1lbnRzIjoiL3Vzci9iaW4vZG9ja2VyZCAtSCBmZDovLyAtLWNvbnRhaW5lcmQ9L3J1bi9jb250YWluZXJkL2NvbnRhaW5lcmQuc29jayIsImZpbGUiOnsiZmlsZSI6eyJwYXRoIjoiL3Vzci9iaW4vZG9ja2VyZCJ9LCJpbnN0YW5jZV9oYXNoIjoiMTY3ODgxMjYwMTcwOTA1NzEyOTEiLCJhcnRpZmFjdF9oYXNoIjoiMTY3ODgxMjYwMTcwOTA1NzEyOTEifSwidXNlciI6eyJ1c2VyIjp7Im5hbWUiOiJyb290IiwiZG9tYWluIjoicm9vdCIsInVzZXJfaWQiOiI2MDE4ODI2MzA1ODc2NzIzMjY5In19LCJwYXJlbnQiOnsicHJvY2VzcyI6eyJoYW5kbGVzIjpbXSwicGlkIjoxLCJhcmd1bWVudHMiOiIvc2Jpbi9pbml0IiwiZmlsZSI6eyJmaWxlIjp7InBhdGgiOiIvbGliL3N5c3RlbWQvc3lzdGVtZCIsImhhc2giOnsibWQ1IjoiYWM4YjI3Y2U2NjQxY2JhNGVkMmM1ZTc2MmYwNDE5ODYifX0sImluc3RhbmNlX2hhc2giOiIxMzE4Nzc2NjQ1NjAwNzA3MjAxOSIsImFydGlmYWN0X2hhc2giOiIxMzE4Nzc2NjQ1NjAwNzA3MjAxOSJ9LCJ1c2VyIjp7InVzZXIiOnsibmFtZSI6InJvb3QiLCJkb21haW4iOiJyb290IiwidXNlcl9pZCI6IjYwMTg4MjYzMDU4NzY3MjMyNjkifX0sInN0YXJ0X3RpbWUiOiIyMDIzLTAxLTExVDA4OjQ0OjAyLjAwMFoiLCJ0YW5pdW1fdW5pcXVlX2lkIjoiMTE1MjkyNTY2NDI4MjY3MzE1MjEifSwiaW5zdGFuY2VfaGFzaCI6IjMxOTY5NjQ4NTI4NTE4ODUzOSIsImFydGlmYWN0X2hhc2giOiI0NzE0OTAwMTk0MTgwNTMxODM2In0sInN0YXJ0X3RpbWUiOiIyMDIzLTAxLTExVDA4OjQ2OjI0LjAwMFoiLCJ0YW5pdW1fdW5pcXVlX2lkIjoiMTE1Mjk4NjQzMjkxNTk1MTAwMjYifSwiaW5zdGFuY2VfaGFzaCI6IjE3MTMyMTc2Mjk2OTI2MTcwMDY4IiwiYXJ0aWZhY3RfaGFzaCI6IjExNzE1NTUyOTUwODYxMDU3MTc3In0sInN0YXJ0X3RpbWUiOiIyMDIzLTAxLTE4VDEwOjM3OjE4LjAwMFoiLCJ0YW5pdW1fdW5pcXVlX2lkIjoiMTQxNTYwNDI1NzY5OTM0OTUyMTMifSwiaW5zdGFuY2VfaGFzaCI6IjExODg2MzgxNjYzMjk0ODAzMDg2IiwiYXJ0aWZhY3RfaGFzaCI6IjQwMDE0NTA1MTc3OTQzNzAzMjAiLCJpc19pbnRlbF90YXJnZXQiOnRydWV9fX1dLCJkb21haW4iOiJ0aHJlYXRyZXNwb25zZSIsImludGVsX2lkIjoiMTM1OjE6N2I4OWFjMzUtM2U5My00MGZjLWIxNDItYjE5OTk0ZjI4NDMwIiwiaHVudF9pZCI6IjQiLCJ0aHJlYXRfaWQiOiI4NTAzOTQ1ODIsOTgzOTYyNzY1LDI2NjcwNjIwMDYsMjY2NzA2Mjc2OCwyNjY3MDYyNDM1Iiwic291cmNlX25hbWUiOiJyZWNvcmRlcjEiLCJzeXN0ZW1faW5mbyI6eyJvcyI6IlwiVWJ1bnR1IDE4LjA0LjYgTFRTXCIiLCJiaXRzIjo2NCwicGxhdGZvcm0iOiJMaW51eCJ9LCJmaXJzdF9zZWVuIjoiMjAyMy0wMS0xOFQxMDozNzozNi4wMDBaIiwibGFzdF9zZWVuIjoiMjAyMy0wMS0xOFQxMDozNzozNi4wMDBaIiwiZmluZGluZ19pZCI6IjY3ODc5ODcwMTE1MzE3NTYxNjUiLCJyZXBvcnRpbmdfaWQiOiJyZXBvcnRpbmctaWQtcGxhY2Vob2xkZXIifSwibWF0Y2giOnsidmVyc2lvbiI6MSwidHlwZSI6InByb2Nlc3MiLCJzb3VyY2UiOiJyZWNvcmRlciIsImhhc2giOiI0MDAxNDUwNTE3Nzk0MzcwMzIwIiwicHJvcGVydGllcyI6eyJwaWQiOjQzMTgxLCJhcmdzIjoiZG9ja2VyLXVudGFyIC8gL3Zhci9saWIvZG9ja2VyL292ZXJsYXkyLzJiY2ZmYjdmMGQ2YTNmMzdhNjE5OWNhNjkxNjQ5ZWE0OTM1OGEyYzJlODdmMzkyMDI1NjJlNTBlYjVjZDI4MDUvZGlmZiIsInJlY29yZGVyX3VuaXF1ZV9pZCI6IjE0MTU2MDQyNTc2OTkzNDk1MjEzIiwic3RhcnRfdGltZSI6IjIwMjMtMDEtMThUMTA6Mzc6MTguMDAwWiIsInBwaWQiOjIwNTgsInVzZXIiOiJyb290XFxyb290IiwiZmlsZSI6eyJmdWxscGF0aCI6Ii9wcm9jL3NlbGYvZXhlIn0sIm5hbWUiOiIvcHJvYy9zZWxmL2V4ZSIsInBhcmVudCI6eyJwaWQiOjIwNTgsImFyZ3MiOiIvdXNyL2Jpbi9kb2NrZXJkIC1IIGZkOi8vIC0tY29udGFpbmVyZD0vcnVuL2NvbnRhaW5lcmQvY29udGFpbmVyZC5zb2NrIiwicmVjb3JkZXJfdW5pcXVlX2lkIjoiMTE1Mjk4NjQzMjkxNTk1MTAwMjYiLCJzdGFydF90aW1lIjoiMjAyMy0wMS0xMVQwODo0NjoyNC4wMDBaIiwicHBpZCI6MSwidXNlciI6InJvb3RcXHJvb3QiLCJmaWxlIjp7ImZ1bGxwYXRoIjoiL3Vzci9iaW4vZG9ja2VyZCJ9LCJuYW1lIjoiL3Vzci9iaW4vZG9ja2VyZCIsInBhcmVudCI6eyJwaWQiOjEsImFyZ3MiOiIvc2Jpbi9pbml0IiwicmVjb3JkZXJfdW5pcXVlX2lkIjoiMTE1MjkyNTY2NDI4MjY3MzE1MjEiLCJzdGFydF90aW1lIjoiMjAyMy0wMS0xMVQwODo0NDowMi4wMDBaIiwidXNlciI6InJvb3RcXHJvb3QiLCJmaWxlIjp7Im1kNSI6ImFjOGIyN2NlNjY0MWNiYTRlZDJjNWU3NjJmMDQxOTg2IiwiZnVsbHBhdGgiOiIvbGliL3N5c3RlbWQvc3lzdGVtZCJ9LCJuYW1lIjoiL2xpYi9zeXN0ZW1kL3N5c3RlbWQifX19LCJjb250ZXh0cyI6W3siZmlsZSI6eyJ1bmlxdWVFdmVudElkIjoiNDYxMTY4NjAxODQ3NTg1NTY3MiJ9LCJldmVudCI6eyJ0aW1lc3RhbXBNcyI6IjE2NzQwMzgyMzg3ODAiLCJmaWxlQ3JlYXRlIjp7InBhdGgiOiIvdmFyL2xpYi9kb2NrZXIvb3ZlcmxheTIvMmJjZmZiN2YwZDZhM2YzN2E2MTk5Y2E2OTE2NDllYTQ5MzU4YTJjMmU4N2YzOTIwMjU2MmU1MGViNWNkMjgwNS9kaWZmL2V0Yy9ob3N0cyJ9fX1dfX0=\",\"Priority\":\"high\",\"Severity\":\"info\",\"Timestamp\":\"2023-01-18T10:13:28.000Z\",\"User Domain\":\"xyz\",\"User Id\":\"\",\"User Name\":\"\"}",
        "type": [
            "info"
        ]
    },
    "host": {
        "hostname": "worker-2"
    },
    "input": {
        "type": "tcp"
    },
    "log": {
        "source": {
            "address": "172.20.0.6:60552"
        }
    },
    "os": {
        "platform": "\"Ubuntu",
        "type": "linux",
        "version": "18.04.6 LTS\""
    },
    "related": {
        "hash": [
            "4d1f1257b846bda82d0338fb541e7301",
            "043eb324a653456caa1a73e2e2d49f77792bb0c5",
            "e3998dbe02b51dada33de87ae43d18a93ab6915b9e34f5a751bf2b9b25a55492"
        ],
        "hosts": [
            "worker-2"
        ],
        "ip": [
            "81.2.69.192"
        ]
    },
    "source": {
        "ip": "81.2.69.192"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "tanium-threat_response"
    ],
    "tanium": {
        "threat_response": {
            "computer": {
                "ip": "81.2.69.192",
                "name": "worker-2"
            },
            "event": {
                "id": "00000000-0000-0000-5389-4a274d06f4ec",
                "name": "detect.unmatch"
            },
            "other_parameters": {
                "log_details": {
                    "payload": "eyJpbnRlbF9pZCI6MTM1LCJjb25maWdfaWQiOjMsImNvbmZpZ19yZXZfaWQiOjEsImZpbmRpbmciOnsid2hhdHMiOlt7ImludGVsX2ludHJhX2lkcyI6W3siaWQiOjg1MDM5NDU4Mn0seyJpZCI6OTgzOTYyMTkzfSx7ImlkIjoyNjY3MDYyMDA2fSx7ImlkIjozMzk4NDE2ODc4fSx7ImlkIjozOTk5MDE0NDY1fV0sInNvdXJjZV9uYW1lIjoicmVjb3JkZXIiLCJhcnRpZmFjdF9hY3Rpdml0eSI6eyJyZWxldmFudF9hY3Rpb25zIjpbeyJ2ZXJiIjo2LCJ0YXJnZXQiOnsiZmlsZSI6eyJwYXRoIjoiL3Zhci9saWIvZG9ja2VyL292ZXJsYXkyLzJiY2ZmYjdmMGQ2YTNmMzdhNjE5OWNhNjkxNjQ5ZWE0OTM1OGEyYzJlODdmMzkyMDI1NjJlNTBlYjVjZDI4MDUvZGlmZi9ldGMvaG9zdHMiLCJoYXNoIjp7Im1kNSI6IjRkMWYxMjU3Yjg0NmJkYTgyZDAzMzhmYjU0MWU3MzAxIiwic2hhMSI6IjA0M2ViMzI0YTY1MzQ1NmNhYTFhNzNlMmUyZDQ5Zjc3NzkyYmIwYzUiLCJzaGEyNTYiOiJlMzk5OGRiZTAyYjUxZGFkYTMzZGU4N2FlNDNkMThhOTNhYjY5MTViOWUzNGY1YTc1MWJmMmI5YjI1YTU1NDkyIn0sInNpemVfYnl0ZXMiOiI3OSIsIm1vZGlmaWNhdGlvbl90aW1lIjoiMjAyMi0wOS0xMVQyMDowODoyNi4wMDBaIiwiaW5zdGFuY2VfaGFzaF9zYWx0IjoiMzAxNDc2NyIsIm1hZ2ljX251bWJlcl9oZXgiOiIzMTMyMzcyZSJ9LCJpbnN0YW5jZV9oYXNoIjoiOTY2NzAxNzM0NTE1MDk2ODM0MiIsImFydGlmYWN0X2hhc2giOiIxMDUzODAwNDU2MTA2MjQ5MDYifSwidGltZXN0YW1wIjoiMjAyMy0wMS0xOFQxMDozNzoxOC4wMDBaIiwidGFuaXVtX3JlY29yZGVyX2V2ZW50X3RhYmxlX2lkIjoiNDYxMTY4NjAxODQ3NTg1NTY3MiIsInRhbml1bV9yZWNvcmRlcl9jb250ZXh0Ijp7ImZpbGUiOnsidW5pcXVlX2V2ZW50X2lkIjoiNDYxMTY4NjAxODQ3NTg1NTY3MiJ9LCJldmVudCI6eyJ0aW1lc3RhbXBfbXMiOiIxNjc0MDM4MjM4NzgwIiwiZmlsZV9jcmVhdGUiOnsicGF0aCI6Ii92YXIvbGliL2RvY2tlci9vdmVybGF5Mi8yYmNmZmI3ZjBkNmEzZjM3YTYxOTljYTY5MTY0OWVhNDkzNThhMmMyZTg3ZjM5MjAyNTYyZTUwZWI1Y2QyODA1L2RpZmYvZXRjL2hvc3RzIn19fX1dLCJhY3RpbmdfYXJ0aWZhY3QiOnsicHJvY2VzcyI6eyJoYW5kbGVzIjpbXSwicGlkIjo0MzE4MSwiYXJndW1lbnRzIjoiZG9ja2VyLXVudGFyIC8gL3Zhci9saWIvZG9ja2VyL292ZXJsYXkyLzJiY2ZmYjdmMGQ2YTNmMzdhNjE5OWNhNjkxNjQ5ZWE0OTM1OGEyYzJlODdmMzkyMDI1NjJlNTBlYjVjZDI4MDUvZGlmZiIsImZpbGUiOnsiZmlsZSI6eyJwYXRoIjoiL3Byb2Mvc2VsZi9leGUifSwiaW5zdGFuY2VfaGFzaCI6IjEzMTY0NjgzMDA4MzA4NzMzMjM2IiwiYXJ0aWZhY3RfaGFzaCI6IjEzMTY0NjgzMDA4MzA4NzMzMjM2In0sInVzZXIiOnsidXNlciI6eyJuYW1lIjoicm9vdCIsImRvbWFpbiI6InJvb3QiLCJ1c2VyX2lkIjoiMCIsImdyb3VwX2lkIjoiMCJ9fSwicGFyZW50Ijp7InByb2Nlc3MiOnsiaGFuZGxlcyI6W10sInBpZCI6MjA1OCwiYXJndW1lbnRzIjoiL3Vzci9iaW4vZG9ja2VyZCAtSCBmZDovLyAtLWNvbnRhaW5lcmQ9L3J1bi9jb250YWluZXJkL2NvbnRhaW5lcmQuc29jayIsImZpbGUiOnsiZmlsZSI6eyJwYXRoIjoiL3Vzci9iaW4vZG9ja2VyZCJ9LCJpbnN0YW5jZV9oYXNoIjoiMTY3ODgxMjYwMTcwOTA1NzEyOTEiLCJhcnRpZmFjdF9oYXNoIjoiMTY3ODgxMjYwMTcwOTA1NzEyOTEifSwidXNlciI6eyJ1c2VyIjp7Im5hbWUiOiJyb290IiwiZG9tYWluIjoicm9vdCIsInVzZXJfaWQiOiI2MDE4ODI2MzA1ODc2NzIzMjY5In19LCJwYXJlbnQiOnsicHJvY2VzcyI6eyJoYW5kbGVzIjpbXSwicGlkIjoxLCJhcmd1bWVudHMiOiIvc2Jpbi9pbml0IiwiZmlsZSI6eyJmaWxlIjp7InBhdGgiOiIvbGliL3N5c3RlbWQvc3lzdGVtZCIsImhhc2giOnsibWQ1IjoiYWM4YjI3Y2U2NjQxY2JhNGVkMmM1ZTc2MmYwNDE5ODYifX0sImluc3RhbmNlX2hhc2giOiIxMzE4Nzc2NjQ1NjAwNzA3MjAxOSIsImFydGlmYWN0X2hhc2giOiIxMzE4Nzc2NjQ1NjAwNzA3MjAxOSJ9LCJ1c2VyIjp7InVzZXIiOnsibmFtZSI6InJvb3QiLCJkb21haW4iOiJyb290IiwidXNlcl9pZCI6IjYwMTg4MjYzMDU4NzY3MjMyNjkifX0sInN0YXJ0X3RpbWUiOiIyMDIzLTAxLTExVDA4OjQ0OjAyLjAwMFoiLCJ0YW5pdW1fdW5pcXVlX2lkIjoiMTE1MjkyNTY2NDI4MjY3MzE1MjEifSwiaW5zdGFuY2VfaGFzaCI6IjMxOTY5NjQ4NTI4NTE4ODUzOSIsImFydGlmYWN0X2hhc2giOiI0NzE0OTAwMTk0MTgwNTMxODM2In0sInN0YXJ0X3RpbWUiOiIyMDIzLTAxLTExVDA4OjQ2OjI0LjAwMFoiLCJ0YW5pdW1fdW5pcXVlX2lkIjoiMTE1Mjk4NjQzMjkxNTk1MTAwMjYifSwiaW5zdGFuY2VfaGFzaCI6IjE3MTMyMTc2Mjk2OTI2MTcwMDY4IiwiYXJ0aWZhY3RfaGFzaCI6IjExNzE1NTUyOTUwODYxMDU3MTc3In0sInN0YXJ0X3RpbWUiOiIyMDIzLTAxLTE4VDEwOjM3OjE4LjAwMFoiLCJ0YW5pdW1fdW5pcXVlX2lkIjoiMTQxNTYwNDI1NzY5OTM0OTUyMTMifSwiaW5zdGFuY2VfaGFzaCI6IjExODg2MzgxNjYzMjk0ODAzMDg2IiwiYXJ0aWZhY3RfaGFzaCI6IjQwMDE0NTA1MTc3OTQzNzAzMjAiLCJpc19pbnRlbF90YXJnZXQiOnRydWV9fX1dLCJkb21haW4iOiJ0aHJlYXRyZXNwb25zZSIsImludGVsX2lkIjoiMTM1OjE6N2I4OWFjMzUtM2U5My00MGZjLWIxNDItYjE5OTk0ZjI4NDMwIiwiaHVudF9pZCI6IjQiLCJ0aHJlYXRfaWQiOiI4NTAzOTQ1ODIsOTgzOTYyNzY1LDI2NjcwNjIwMDYsMjY2NzA2Mjc2OCwyNjY3MDYyNDM1Iiwic291cmNlX25hbWUiOiJyZWNvcmRlcjEiLCJzeXN0ZW1faW5mbyI6eyJvcyI6IlwiVWJ1bnR1IDE4LjA0LjYgTFRTXCIiLCJiaXRzIjo2NCwicGxhdGZvcm0iOiJMaW51eCJ9LCJmaXJzdF9zZWVuIjoiMjAyMy0wMS0xOFQxMDozNzozNi4wMDBaIiwibGFzdF9zZWVuIjoiMjAyMy0wMS0xOFQxMDozNzozNi4wMDBaIiwiZmluZGluZ19pZCI6IjY3ODc5ODcwMTE1MzE3NTYxNjUiLCJyZXBvcnRpbmdfaWQiOiJyZXBvcnRpbmctaWQtcGxhY2Vob2xkZXIifSwibWF0Y2giOnsidmVyc2lvbiI6MSwidHlwZSI6InByb2Nlc3MiLCJzb3VyY2UiOiJyZWNvcmRlciIsImhhc2giOiI0MDAxNDUwNTE3Nzk0MzcwMzIwIiwicHJvcGVydGllcyI6eyJwaWQiOjQzMTgxLCJhcmdzIjoiZG9ja2VyLXVudGFyIC8gL3Zhci9saWIvZG9ja2VyL292ZXJsYXkyLzJiY2ZmYjdmMGQ2YTNmMzdhNjE5OWNhNjkxNjQ5ZWE0OTM1OGEyYzJlODdmMzkyMDI1NjJlNTBlYjVjZDI4MDUvZGlmZiIsInJlY29yZGVyX3VuaXF1ZV9pZCI6IjE0MTU2MDQyNTc2OTkzNDk1MjEzIiwic3RhcnRfdGltZSI6IjIwMjMtMDEtMThUMTA6Mzc6MTguMDAwWiIsInBwaWQiOjIwNTgsInVzZXIiOiJyb290XFxyb290IiwiZmlsZSI6eyJmdWxscGF0aCI6Ii9wcm9jL3NlbGYvZXhlIn0sIm5hbWUiOiIvcHJvYy9zZWxmL2V4ZSIsInBhcmVudCI6eyJwaWQiOjIwNTgsImFyZ3MiOiIvdXNyL2Jpbi9kb2NrZXJkIC1IIGZkOi8vIC0tY29udGFpbmVyZD0vcnVuL2NvbnRhaW5lcmQvY29udGFpbmVyZC5zb2NrIiwicmVjb3JkZXJfdW5pcXVlX2lkIjoiMTE1Mjk4NjQzMjkxNTk1MTAwMjYiLCJzdGFydF90aW1lIjoiMjAyMy0wMS0xMVQwODo0NjoyNC4wMDBaIiwicHBpZCI6MSwidXNlciI6InJvb3RcXHJvb3QiLCJmaWxlIjp7ImZ1bGxwYXRoIjoiL3Vzci9iaW4vZG9ja2VyZCJ9LCJuYW1lIjoiL3Vzci9iaW4vZG9ja2VyZCIsInBhcmVudCI6eyJwaWQiOjEsImFyZ3MiOiIvc2Jpbi9pbml0IiwicmVjb3JkZXJfdW5pcXVlX2lkIjoiMTE1MjkyNTY2NDI4MjY3MzE1MjEiLCJzdGFydF90aW1lIjoiMjAyMy0wMS0xMVQwODo0NDowMi4wMDBaIiwidXNlciI6InJvb3RcXHJvb3QiLCJmaWxlIjp7Im1kNSI6ImFjOGIyN2NlNjY0MWNiYTRlZDJjNWU3NjJmMDQxOTg2IiwiZnVsbHBhdGgiOiIvbGliL3N5c3RlbWQvc3lzdGVtZCJ9LCJuYW1lIjoiL2xpYi9zeXN0ZW1kL3N5c3RlbWQifX19LCJjb250ZXh0cyI6W3siZmlsZSI6eyJ1bmlxdWVFdmVudElkIjoiNDYxMTY4NjAxODQ3NTg1NTY3MiJ9LCJldmVudCI6eyJ0aW1lc3RhbXBNcyI6IjE2NzQwMzgyMzg3ODAiLCJmaWxlQ3JlYXRlIjp7InBhdGgiOiIvdmFyL2xpYi9kb2NrZXIvb3ZlcmxheTIvMmJjZmZiN2YwZDZhM2YzN2E2MTk5Y2E2OTE2NDllYTQ5MzU4YTJjMmU4N2YzOTIwMjU2MmU1MGViNWNkMjgwNS9kaWZmL2V0Yy9ob3N0cyJ9fX1dfX0=",
                    "payload_decoded": {
                        "config_id": "3",
                        "config_rev_id": "1",
                        "finding": {
                            "domain": "threatresponse",
                            "first_seen": "2023-01-18T10:37:36.000Z",
                            "hunt_id": "4",
                            "id": "6787987011531756165",
                            "intel_id": "135:1:7b89ac35-3e93-40fc-b142-b19994f28430",
                            "last_seen": "2023-01-18T10:37:36.000Z",
                            "reporting_id": "reporting-id-placeholder",
                            "source_name": "recorder1",
                            "system_info": {
                                "bits": 64,
                                "os": {
                                    "platform": "\"Ubuntu",
                                    "value": "\"Ubuntu 18.04.6 LTS\"",
                                    "version": "18.04.6 LTS\""
                                },
                                "platform": "linux"
                            },
                            "threat_id": "850394582,983962765,2667062006,2667062768,2667062435",
                            "whats": [
                                {
                                    "artifact_activity": {
                                        "acting_artifact": {
                                            "artifact_hash": "4001450517794370320",
                                            "instance_hash": "11886381663294803086",
                                            "is_intel_target": true,
                                            "process": {
                                                "arguments": "docker-untar / /var/lib/docker/overlay2/2bcffb7f0d6a3f37a6199ca691649ea49358a2c2e87f39202562e50eb5cd2805/diff",
                                                "file": {
                                                    "artifact_hash": "13164683008308733236",
                                                    "instance_hash": "13164683008308733236",
                                                    "path": "/proc/self/exe"
                                                },
                                                "parent": {
                                                    "artifact_hash": "11715552950861057177",
                                                    "instance_hash": "17132176296926170068",
                                                    "process": {
                                                        "arguments": "/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock",
                                                        "file": {
                                                            "artifact_hash": "16788126017090571291",
                                                            "instance_hash": "16788126017090571291",
                                                            "path": "/usr/bin/dockerd"
                                                        },
                                                        "parent": {
                                                            "artifact_hash": "4714900194180531836",
                                                            "instance_hash": "319696485285188539",
                                                            "process": {
                                                                "arguments": "/sbin/init",
                                                                "file": {
                                                                    "artifact_hash": "13187766456007072019",
                                                                    "hash": {
                                                                        "md5": "ac8b27ce6641cba4ed2c5e762f041986"
                                                                    },
                                                                    "instance_hash": "13187766456007072019",
                                                                    "path": "/lib/systemd/systemd"
                                                                },
                                                                "pid": "1",
                                                                "start_time": "2023-01-11T08:44:02.000Z",
                                                                "tanium_unique_id": "11529256642826731521",
                                                                "user": {
                                                                    "domain": "root",
                                                                    "id": "6018826305876723269",
                                                                    "name": "root"
                                                                }
                                                            }
                                                        },
                                                        "pid": "2058",
                                                        "start_time": "2023-01-11T08:46:24.000Z",
                                                        "tanium_unique_id": "11529864329159510026",
                                                        "user": {
                                                            "domain": "root",
                                                            "id": "6018826305876723269",
                                                            "name": "root"
                                                        }
                                                    }
                                                },
                                                "pid": "43181",
                                                "start_time": "2023-01-18T10:37:18.000Z",
                                                "tanium_unique_id": "14156042576993495213",
                                                "user": {
                                                    "domain": "root",
                                                    "group_id": "0",
                                                    "id": "0",
                                                    "name": "root"
                                                }
                                            }
                                        },
                                        "relevant_actions": [
                                            {
                                                "tanium_recorder_context": {
                                                    "event": {
                                                        "file_create": {
                                                            "path": "/var/lib/docker/overlay2/2bcffb7f0d6a3f37a6199ca691649ea49358a2c2e87f39202562e50eb5cd2805/diff/etc/hosts"
                                                        },
                                                        "timestamp_ms": "2023-01-18T10:37:18.780Z"
                                                    },
                                                    "file": {
                                                        "unique_event_id": "4611686018475855672"
                                                    }
                                                },
                                                "tanium_recorder_event_table_id": "4611686018475855672",
                                                "target": {
                                                    "artifact_hash": "105380045610624906",
                                                    "file": {
                                                        "hash": {
                                                            "md5": "4d1f1257b846bda82d0338fb541e7301",
                                                            "sha1": "043eb324a653456caa1a73e2e2d49f77792bb0c5",
                                                            "sha256": "e3998dbe02b51dada33de87ae43d18a93ab6915b9e34f5a751bf2b9b25a55492"
                                                        },
                                                        "instance_hash_salt": "3014767",
                                                        "magic_number_hex": "3132372e",
                                                        "modification_time": "2022-09-11T20:08:26.000Z",
                                                        "path": "/var/lib/docker/overlay2/2bcffb7f0d6a3f37a6199ca691649ea49358a2c2e87f39202562e50eb5cd2805/diff/etc/hosts",
                                                        "size_bytes": 79
                                                    },
                                                    "instance_hash": "9667017345150968342"
                                                },
                                                "timestamp": "2023-01-18T10:37:18.000Z",
                                                "verb": 6
                                            }
                                        ]
                                    },
                                    "intel_intra_ids": [
                                        {
                                            "id": 850394582
                                        },
                                        {
                                            "id": 983962193
                                        },
                                        {
                                            "id": 2667062006
                                        },
                                        {
                                            "id": 3398416878
                                        },
                                        {
                                            "id": 3999014465
                                        }
                                    ],
                                    "source_name": "recorder"
                                }
                            ]
                        },
                        "intel_id": "135",
                        "match": {
                            "contexts": [
                                {
                                    "event": {
                                        "file_create": {
                                            "path": "/var/lib/docker/overlay2/2bcffb7f0d6a3f37a6199ca691649ea49358a2c2e87f39202562e50eb5cd2805/diff/etc/hosts"
                                        },
                                        "timestampMs": "2023-01-18T10:37:18.780Z"
                                    },
                                    "file": {
                                        "unique_event_id": "4611686018475855672"
                                    }
                                }
                            ],
                            "hash": "4001450517794370320",
                            "properties": {
                                "args": "docker-untar / /var/lib/docker/overlay2/2bcffb7f0d6a3f37a6199ca691649ea49358a2c2e87f39202562e50eb5cd2805/diff",
                                "file": {
                                    "full_path": "/proc/self/exe"
                                },
                                "name": "/proc/self/exe",
                                "parent": {
                                    "args": "/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock",
                                    "file": {
                                        "full_path": "/usr/bin/dockerd"
                                    },
                                    "name": "/usr/bin/dockerd",
                                    "parent": {
                                        "args": "/sbin/init",
                                        "file": {
                                            "full_path": "/lib/systemd/systemd",
                                            "md5": "ac8b27ce6641cba4ed2c5e762f041986"
                                        },
                                        "name": "/lib/systemd/systemd",
                                        "pid": "1",
                                        "recorder_unique_id": "11529256642826731521",
                                        "start_time": "2023-01-11T08:44:02.000Z",
                                        "user": "root\\root"
                                    },
                                    "pid": "2058",
                                    "ppid": "1",
                                    "recorder_unique_id": "11529864329159510026",
                                    "start_time": "2023-01-11T08:46:24.000Z",
                                    "user": "root\\root"
                                },
                                "pid": "43181",
                                "ppid": "2058",
                                "recorder_unique_id": "14156042576993495213",
                                "start_time": "2023-01-18T10:37:18.000Z",
                                "user": "root\\root"
                            },
                            "source": "recorder",
                            "type": "process",
                            "version": 1
                        }
                    }
                },
                "original": "payload=eyJpbnRlbF9pZCI6MTM1LCJjb25maWdfaWQiOjMsImNvbmZpZ19yZXZfaWQiOjEsImZpbmRpbmciOnsid2hhdHMiOlt7ImludGVsX2ludHJhX2lkcyI6W3siaWQiOjg1MDM5NDU4Mn0seyJpZCI6OTgzOTYyMTkzfSx7ImlkIjoyNjY3MDYyMDA2fSx7ImlkIjozMzk4NDE2ODc4fSx7ImlkIjozOTk5MDE0NDY1fV0sInNvdXJjZV9uYW1lIjoicmVjb3JkZXIiLCJhcnRpZmFjdF9hY3Rpdml0eSI6eyJyZWxldmFudF9hY3Rpb25zIjpbeyJ2ZXJiIjo2LCJ0YXJnZXQiOnsiZmlsZSI6eyJwYXRoIjoiL3Zhci9saWIvZG9ja2VyL292ZXJsYXkyLzJiY2ZmYjdmMGQ2YTNmMzdhNjE5OWNhNjkxNjQ5ZWE0OTM1OGEyYzJlODdmMzkyMDI1NjJlNTBlYjVjZDI4MDUvZGlmZi9ldGMvaG9zdHMiLCJoYXNoIjp7Im1kNSI6IjRkMWYxMjU3Yjg0NmJkYTgyZDAzMzhmYjU0MWU3MzAxIiwic2hhMSI6IjA0M2ViMzI0YTY1MzQ1NmNhYTFhNzNlMmUyZDQ5Zjc3NzkyYmIwYzUiLCJzaGEyNTYiOiJlMzk5OGRiZTAyYjUxZGFkYTMzZGU4N2FlNDNkMThhOTNhYjY5MTViOWUzNGY1YTc1MWJmMmI5YjI1YTU1NDkyIn0sInNpemVfYnl0ZXMiOiI3OSIsIm1vZGlmaWNhdGlvbl90aW1lIjoiMjAyMi0wOS0xMVQyMDowODoyNi4wMDBaIiwiaW5zdGFuY2VfaGFzaF9zYWx0IjoiMzAxNDc2NyIsIm1hZ2ljX251bWJlcl9oZXgiOiIzMTMyMzcyZSJ9LCJpbnN0YW5jZV9oYXNoIjoiOTY2NzAxNzM0NTE1MDk2ODM0MiIsImFydGlmYWN0X2hhc2giOiIxMDUzODAwNDU2MTA2MjQ5MDYifSwidGltZXN0YW1wIjoiMjAyMy0wMS0xOFQxMDozNzoxOC4wMDBaIiwidGFuaXVtX3JlY29yZGVyX2V2ZW50X3RhYmxlX2lkIjoiNDYxMTY4NjAxODQ3NTg1NTY3MiIsInRhbml1bV9yZWNvcmRlcl9jb250ZXh0Ijp7ImZpbGUiOnsidW5pcXVlX2V2ZW50X2lkIjoiNDYxMTY4NjAxODQ3NTg1NTY3MiJ9LCJldmVudCI6eyJ0aW1lc3RhbXBfbXMiOiIxNjc0MDM4MjM4NzgwIiwiZmlsZV9jcmVhdGUiOnsicGF0aCI6Ii92YXIvbGliL2RvY2tlci9vdmVybGF5Mi8yYmNmZmI3ZjBkNmEzZjM3YTYxOTljYTY5MTY0OWVhNDkzNThhMmMyZTg3ZjM5MjAyNTYyZTUwZWI1Y2QyODA1L2RpZmYvZXRjL2hvc3RzIn19fX1dLCJhY3RpbmdfYXJ0aWZhY3QiOnsicHJvY2VzcyI6eyJoYW5kbGVzIjpbXSwicGlkIjo0MzE4MSwiYXJndW1lbnRzIjoiZG9ja2VyLXVudGFyIC8gL3Zhci9saWIvZG9ja2VyL292ZXJsYXkyLzJiY2ZmYjdmMGQ2YTNmMzdhNjE5OWNhNjkxNjQ5ZWE0OTM1OGEyYzJlODdmMzkyMDI1NjJlNTBlYjVjZDI4MDUvZGlmZiIsImZpbGUiOnsiZmlsZSI6eyJwYXRoIjoiL3Byb2Mvc2VsZi9leGUifSwiaW5zdGFuY2VfaGFzaCI6IjEzMTY0NjgzMDA4MzA4NzMzMjM2IiwiYXJ0aWZhY3RfaGFzaCI6IjEzMTY0NjgzMDA4MzA4NzMzMjM2In0sInVzZXIiOnsidXNlciI6eyJuYW1lIjoicm9vdCIsImRvbWFpbiI6InJvb3QiLCJ1c2VyX2lkIjoiMCIsImdyb3VwX2lkIjoiMCJ9fSwicGFyZW50Ijp7InByb2Nlc3MiOnsiaGFuZGxlcyI6W10sInBpZCI6MjA1OCwiYXJndW1lbnRzIjoiL3Vzci9iaW4vZG9ja2VyZCAtSCBmZDovLyAtLWNvbnRhaW5lcmQ9L3J1bi9jb250YWluZXJkL2NvbnRhaW5lcmQuc29jayIsImZpbGUiOnsiZmlsZSI6eyJwYXRoIjoiL3Vzci9iaW4vZG9ja2VyZCJ9LCJpbnN0YW5jZV9oYXNoIjoiMTY3ODgxMjYwMTcwOTA1NzEyOTEiLCJhcnRpZmFjdF9oYXNoIjoiMTY3ODgxMjYwMTcwOTA1NzEyOTEifSwidXNlciI6eyJ1c2VyIjp7Im5hbWUiOiJyb290IiwiZG9tYWluIjoicm9vdCIsInVzZXJfaWQiOiI2MDE4ODI2MzA1ODc2NzIzMjY5In19LCJwYXJlbnQiOnsicHJvY2VzcyI6eyJoYW5kbGVzIjpbXSwicGlkIjoxLCJhcmd1bWVudHMiOiIvc2Jpbi9pbml0IiwiZmlsZSI6eyJmaWxlIjp7InBhdGgiOiIvbGliL3N5c3RlbWQvc3lzdGVtZCIsImhhc2giOnsibWQ1IjoiYWM4YjI3Y2U2NjQxY2JhNGVkMmM1ZTc2MmYwNDE5ODYifX0sImluc3RhbmNlX2hhc2giOiIxMzE4Nzc2NjQ1NjAwNzA3MjAxOSIsImFydGlmYWN0X2hhc2giOiIxMzE4Nzc2NjQ1NjAwNzA3MjAxOSJ9LCJ1c2VyIjp7InVzZXIiOnsibmFtZSI6InJvb3QiLCJkb21haW4iOiJyb290IiwidXNlcl9pZCI6IjYwMTg4MjYzMDU4NzY3MjMyNjkifX0sInN0YXJ0X3RpbWUiOiIyMDIzLTAxLTExVDA4OjQ0OjAyLjAwMFoiLCJ0YW5pdW1fdW5pcXVlX2lkIjoiMTE1MjkyNTY2NDI4MjY3MzE1MjEifSwiaW5zdGFuY2VfaGFzaCI6IjMxOTY5NjQ4NTI4NTE4ODUzOSIsImFydGlmYWN0X2hhc2giOiI0NzE0OTAwMTk0MTgwNTMxODM2In0sInN0YXJ0X3RpbWUiOiIyMDIzLTAxLTExVDA4OjQ2OjI0LjAwMFoiLCJ0YW5pdW1fdW5pcXVlX2lkIjoiMTE1Mjk4NjQzMjkxNTk1MTAwMjYifSwiaW5zdGFuY2VfaGFzaCI6IjE3MTMyMTc2Mjk2OTI2MTcwMDY4IiwiYXJ0aWZhY3RfaGFzaCI6IjExNzE1NTUyOTUwODYxMDU3MTc3In0sInN0YXJ0X3RpbWUiOiIyMDIzLTAxLTE4VDEwOjM3OjE4LjAwMFoiLCJ0YW5pdW1fdW5pcXVlX2lkIjoiMTQxNTYwNDI1NzY5OTM0OTUyMTMifSwiaW5zdGFuY2VfaGFzaCI6IjExODg2MzgxNjYzMjk0ODAzMDg2IiwiYXJ0aWZhY3RfaGFzaCI6IjQwMDE0NTA1MTc3OTQzNzAzMjAiLCJpc19pbnRlbF90YXJnZXQiOnRydWV9fX1dLCJkb21haW4iOiJ0aHJlYXRyZXNwb25zZSIsImludGVsX2lkIjoiMTM1OjE6N2I4OWFjMzUtM2U5My00MGZjLWIxNDItYjE5OTk0ZjI4NDMwIiwiaHVudF9pZCI6IjQiLCJ0aHJlYXRfaWQiOiI4NTAzOTQ1ODIsOTgzOTYyNzY1LDI2NjcwNjIwMDYsMjY2NzA2Mjc2OCwyNjY3MDYyNDM1Iiwic291cmNlX25hbWUiOiJyZWNvcmRlcjEiLCJzeXN0ZW1faW5mbyI6eyJvcyI6IlwiVWJ1bnR1IDE4LjA0LjYgTFRTXCIiLCJiaXRzIjo2NCwicGxhdGZvcm0iOiJMaW51eCJ9LCJmaXJzdF9zZWVuIjoiMjAyMy0wMS0xOFQxMDozNzozNi4wMDBaIiwibGFzdF9zZWVuIjoiMjAyMy0wMS0xOFQxMDozNzozNi4wMDBaIiwiZmluZGluZ19pZCI6IjY3ODc5ODcwMTE1MzE3NTYxNjUiLCJyZXBvcnRpbmdfaWQiOiJyZXBvcnRpbmctaWQtcGxhY2Vob2xkZXIifSwibWF0Y2giOnsidmVyc2lvbiI6MSwidHlwZSI6InByb2Nlc3MiLCJzb3VyY2UiOiJyZWNvcmRlciIsImhhc2giOiI0MDAxNDUwNTE3Nzk0MzcwMzIwIiwicHJvcGVydGllcyI6eyJwaWQiOjQzMTgxLCJhcmdzIjoiZG9ja2VyLXVudGFyIC8gL3Zhci9saWIvZG9ja2VyL292ZXJsYXkyLzJiY2ZmYjdmMGQ2YTNmMzdhNjE5OWNhNjkxNjQ5ZWE0OTM1OGEyYzJlODdmMzkyMDI1NjJlNTBlYjVjZDI4MDUvZGlmZiIsInJlY29yZGVyX3VuaXF1ZV9pZCI6IjE0MTU2MDQyNTc2OTkzNDk1MjEzIiwic3RhcnRfdGltZSI6IjIwMjMtMDEtMThUMTA6Mzc6MTguMDAwWiIsInBwaWQiOjIwNTgsInVzZXIiOiJyb290XFxyb290IiwiZmlsZSI6eyJmdWxscGF0aCI6Ii9wcm9jL3NlbGYvZXhlIn0sIm5hbWUiOiIvcHJvYy9zZWxmL2V4ZSIsInBhcmVudCI6eyJwaWQiOjIwNTgsImFyZ3MiOiIvdXNyL2Jpbi9kb2NrZXJkIC1IIGZkOi8vIC0tY29udGFpbmVyZD0vcnVuL2NvbnRhaW5lcmQvY29udGFpbmVyZC5zb2NrIiwicmVjb3JkZXJfdW5pcXVlX2lkIjoiMTE1Mjk4NjQzMjkxNTk1MTAwMjYiLCJzdGFydF90aW1lIjoiMjAyMy0wMS0xMVQwODo0NjoyNC4wMDBaIiwicHBpZCI6MSwidXNlciI6InJvb3RcXHJvb3QiLCJmaWxlIjp7ImZ1bGxwYXRoIjoiL3Vzci9iaW4vZG9ja2VyZCJ9LCJuYW1lIjoiL3Vzci9iaW4vZG9ja2VyZCIsInBhcmVudCI6eyJwaWQiOjEsImFyZ3MiOiIvc2Jpbi9pbml0IiwicmVjb3JkZXJfdW5pcXVlX2lkIjoiMTE1MjkyNTY2NDI4MjY3MzE1MjEiLCJzdGFydF90aW1lIjoiMjAyMy0wMS0xMVQwODo0NDowMi4wMDBaIiwidXNlciI6InJvb3RcXHJvb3QiLCJmaWxlIjp7Im1kNSI6ImFjOGIyN2NlNjY0MWNiYTRlZDJjNWU3NjJmMDQxOTg2IiwiZnVsbHBhdGgiOiIvbGliL3N5c3RlbWQvc3lzdGVtZCJ9LCJuYW1lIjoiL2xpYi9zeXN0ZW1kL3N5c3RlbWQifX19LCJjb250ZXh0cyI6W3siZmlsZSI6eyJ1bmlxdWVFdmVudElkIjoiNDYxMTY4NjAxODQ3NTg1NTY3MiJ9LCJldmVudCI6eyJ0aW1lc3RhbXBNcyI6IjE2NzQwMzgyMzg3ODAiLCJmaWxlQ3JlYXRlIjp7InBhdGgiOiIvdmFyL2xpYi9kb2NrZXIvb3ZlcmxheTIvMmJjZmZiN2YwZDZhM2YzN2E2MTk5Y2E2OTE2NDllYTQ5MzU4YTJjMmU4N2YzOTIwMjU2MmU1MGViNWNkMjgwNS9kaWZmL2V0Yy9ob3N0cyJ9fX1dfX0="
            },
            "priority": "high",
            "severity": "info",
            "timestamp": "2023-01-18T10:13:28.000Z",
            "user": {
                "domain": "xyz"
            }
        }
    },
    "user": {
        "domain": "xyz"
    }
}

```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| tanium.threat_response.action | Action for the threat response. | keyword |
| tanium.threat_response.computer.ip | Computer ip of the threat response. | ip |
| tanium.threat_response.computer.name | Computer name of the threat response. | keyword |
| tanium.threat_response.created_at | Create time for the threat response. | date |
| tanium.threat_response.event.id | Event id of the threat response.. | keyword |
| tanium.threat_response.event.name | Event name of the threat response. | keyword |
| tanium.threat_response.id | Threat response id. | keyword |
| tanium.threat_response.other_parameters.log_details.name | Name of threat. | keyword |
| tanium.threat_response.other_parameters.log_details.payload | Decoded payload data. | match_only_text |
| tanium.threat_response.other_parameters.log_details.payload_decoded.config_id | Config id. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.config_rev_id | Config rev.iD. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.domain | Finding domain. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.first_seen | First seen. | date |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.hunt_id | Hunt id. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.id | Finding id. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.intel_id | Finding intel id. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.last_seen | Last seen. | date |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.reporting_id | Finding reporting id. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.source_name | Source name. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.system_info.bits | Bits. | long |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.system_info.os.platform | OS platform. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.system_info.os.value | OS value. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.system_info.os.version | OS version. | version |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.system_info.platform | OS type. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.threat_id | Threat id. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.artifact_hash | Artifact hash of activity. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.instance_hash | Instance hash of activity. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.is_intel_target | Intel target or not. | boolean |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.arguments | Process arguments. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.file.artifact_hash | Artifact hash of file. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.file.instance_hash | Instance hash of file. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.file.path | Path of file. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.handles | Process handles. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.parent.artifact_hash | Artifact hash. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.parent.instance_hash | Instance hash. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.parent.process.arguments | Process arguments. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.parent.process.file.artifact_hash | Artifact hash of file. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.parent.process.file.instance_hash | Instance hash of file. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.parent.process.file.path | Path of file. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.parent.process.handles | Process handles. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.parent.process.parent.artifact_hash | Artifact hash. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.parent.process.parent.instance_hash | Instance hash. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.parent.process.parent.process.arguments | Process arguments. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.parent.process.parent.process.file.artifact_hash | Artifact hash of file. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.parent.process.parent.process.file.hash.md5 | MD5 hash. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.parent.process.parent.process.file.instance_hash | Instance hash of file. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.parent.process.parent.process.file.path | Path of file. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.parent.process.parent.process.handles | Process handles. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.parent.process.parent.process.md5 | MD5 keyword. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.parent.process.parent.process.pid | Process id. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.parent.process.parent.process.start_time | Start time. | date |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.parent.process.parent.process.tanium_unique_id | Tanium unique id. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.parent.process.parent.process.user.domain | User domain. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.parent.process.parent.process.user.id | User id. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.parent.process.parent.process.user.name | User name. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.parent.process.pid | Process id. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.parent.process.start_time | Start time. | date |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.parent.process.tanium_unique_id | Tanium unique id. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.parent.process.user.domain | User domain. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.parent.process.user.group_id | User group id. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.parent.process.user.id | User id. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.parent.process.user.name | User name. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.pid | Parent id. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.start_time | Start time. | date |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.tanium_unique_id | Tanium unique id. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.user.domain | User domain. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.user.group_id | User group id. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.user.id | User id. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.acting_artifact.process.user.name | User name. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.relevant_actions.tanium_recorder_context.event.file_create.path | Path of file. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.relevant_actions.tanium_recorder_context.event.timestamp_ms | Timestamp in milliseconds. | date |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.relevant_actions.tanium_recorder_context.file.unique_event_id | Unique event id. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.relevant_actions.tanium_recorder_event_table_id | Tanium recorder event table id. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.relevant_actions.target.artifact_hash | Artifact hash of file. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.relevant_actions.target.file.hash.md5 | MD5 hash. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.relevant_actions.target.file.hash.sha1 | MD5 sha1. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.relevant_actions.target.file.hash.sha256 | MD5 sha256. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.relevant_actions.target.file.instance_hash | Instance hash. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.relevant_actions.target.file.instance_hash_salt | Instance hash salt. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.relevant_actions.target.file.magic_number_hex | Magic number. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.relevant_actions.target.file.modification_time | Modification time of file. | date |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.relevant_actions.target.file.path | Path of file. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.relevant_actions.target.file.size_bytes | File size in bytes. | long |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.relevant_actions.target.instance_hash | Instance hash. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.relevant_actions.timestamp | Timestamp. | date |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.artifact_activity.relevant_actions.verb | Verb. | long |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.intel_intra_ids.id | Array of intel intra id. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.finding.whats.source_name | Source name. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.intel_id | Intel id. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.match.contexts.event.file_create.path | Path of file. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.match.contexts.event.timestampMs | Timestamp in milliseconds. | date |
| tanium.threat_response.other_parameters.log_details.payload_decoded.match.contexts.file.unique_event_id | Unique event id of file. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.match.hash | Hash value. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.match.properties.args | Property arguments. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.match.properties.file.full_path | Full path of file. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.match.properties.name | Property name. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.match.properties.parent.args | Parent arguments. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.match.properties.parent.file.full_path | Full path of file. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.match.properties.parent.name | Parent name. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.match.properties.parent.parent.args | Parent arguments. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.match.properties.parent.parent.file.full_path | Full path of file. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.match.properties.parent.parent.file.md5 | MD5. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.match.properties.parent.parent.name | Parent name. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.match.properties.parent.parent.pid | Parent id. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.match.properties.parent.parent.recorder_unique_id | Recorder unique id. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.match.properties.parent.parent.start_time | Start time. | date |
| tanium.threat_response.other_parameters.log_details.payload_decoded.match.properties.parent.parent.user | User. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.match.properties.parent.pid | Process id. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.match.properties.parent.ppid | Parent process id. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.match.properties.parent.recorder_unique_id | Recorder unique id. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.match.properties.parent.start_time | Start time. | date |
| tanium.threat_response.other_parameters.log_details.payload_decoded.match.properties.parent.user | User. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.match.properties.pid | Process id. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.match.properties.ppid | Parent process id. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.match.properties.recorder_unique_id | Recorder unique id. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.match.properties.start_time | Start time. | date |
| tanium.threat_response.other_parameters.log_details.payload_decoded.match.properties.user | User. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.match.source | Finding source. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.match.type | Finding type. | keyword |
| tanium.threat_response.other_parameters.log_details.payload_decoded.match.version | Finding version. | version |
| tanium.threat_response.other_parameters.log_details.source | Source of threat. | keyword |
| tanium.threat_response.other_parameters.log_details.type | Type of threat. | keyword |
| tanium.threat_response.other_parameters.original |  | match_only_text |
| tanium.threat_response.priority | Priority of the threat response. | keyword |
| tanium.threat_response.revision | Revision of the threat response. | keyword |
| tanium.threat_response.row_id | Row id for the threat response. | keyword |
| tanium.threat_response.severity | Severity of the threat response. | keyword |
| tanium.threat_response.state.connection_id | Connection id of the threat response state. | keyword |
| tanium.threat_response.state.session_id | Session id of the threat response state. | keyword |
| tanium.threat_response.state.target.eid | Target eid of the threat response state. | keyword |
| tanium.threat_response.state.target.hostname | Target hostname of the threat response state. | keyword |
| tanium.threat_response.table | Table for the threat response. | keyword |
| tanium.threat_response.timestamp | Timestamp of the event. | date |
| tanium.threat_response.updated_at | Threat response update time. | date |
| tanium.threat_response.user.domain | User domain of the threat response. | keyword |
| tanium.threat_response.user.id | User id for the threat response. | keyword |
| tanium.threat_response.user.name | User name for the threat response. | keyword |

