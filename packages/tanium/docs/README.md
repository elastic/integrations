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
    "@timestamp": "2025-03-14T15:27:28.630Z",
    "agent": {
        "ephemeral_id": "2da37302-4f80-4c24-ada8-583e50a11fe7",
        "id": "613dde37-3274-4ac1-8b2b-4a85885c6622",
        "name": "elastic-agent-30062",
        "type": "filebeat",
        "version": "8.16.5"
    },
    "data_stream": {
        "dataset": "tanium.action_history",
        "namespace": "92264",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "613dde37-3274-4ac1-8b2b-4a85885c6622",
        "snapshot": false,
        "version": "8.16.5"
    },
    "event": {
        "action": "Deploy Client Configuration and Support [Mac](universal)",
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "dataset": "tanium.action_history",
        "end": "2022-10-04T17:38:42.000Z",
        "ingested": "2025-03-14T15:27:29Z",
        "kind": [
            "event"
        ],
        "original": "{\"ActionId\":6058,\"ActionName\":\"Deploy Client Configuration and Support [Mac](universal)\",\"Approver\":\"tanium\",\"Command\":\"/bin/sh -c 'chmod u+x TaniumCX \\u0026\\u0026 ./TaniumCX bootstrap --zip bootstrap.zip'\",\"Comment\":\"\",\"DistributeOver\":\"1 minutes\",\"Expiration\":\"2022-10-04T17:38:42\",\"InsertTime\":\"2022-10-04T16:38:48\",\"Issuer\":\"tanium\",\"PackageName\":\"Client Configuration and Support [Mac](universal)\",\"SourceId\":10,\"StartTime\":\"2022-10-04T16:38:42\",\"Status\":\"Closed\"}",
        "provider": "tanium",
        "start": "2022-10-04T16:38:42.000Z",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "http_endpoint"
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
    "@timestamp": "2025-03-14T15:30:29.725Z",
    "agent": {
        "ephemeral_id": "a2827411-593d-49b7-ad72-a5d557aaec37",
        "id": "ffee010e-0aca-45bf-9b02-b2466f8d575a",
        "name": "elastic-agent-76166",
        "type": "filebeat",
        "version": "8.16.5"
    },
    "client": {
        "ip": "67.43.156.0"
    },
    "data_stream": {
        "dataset": "tanium.client_status",
        "namespace": "81168",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "ffee010e-0aca-45bf-9b02-b2466f8d575a",
        "snapshot": false,
        "version": "8.16.5"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "tanium.client_status",
        "ingested": "2025-03-14T15:30:30Z",
        "kind": [
            "state"
        ],
        "original": "{\"ClientNetworkLocation\":\"67.43.156.0\",\"ComputerId\":\"4008511043\",\"FullVersion\":\"7.4.9.1046\",\"HostName\":\"dhcp-client02.local\",\"LastRegistration\":\"2022-10-07T09:20:08\",\"ProtocolVersion\":315,\"ReceiveState\":\"None\",\"RegisteredWithTLS\":1,\"SendState\":\"None\",\"ServerNetworkLocation\":\"81.2.69.192\",\"Status\":\"Leader\",\"ValidKey\":1}",
        "type": [
            "info"
        ]
    },
    "host": {
        "id": "4008511043",
        "name": "dhcp-client02.local"
    },
    "input": {
        "type": "http_endpoint"
    },
    "related": {
        "hosts": [
            "dhcp-client02.local",
            "4008511043"
        ],
        "ip": [
            "67.43.156.0",
            "81.2.69.192"
        ]
    },
    "server": {
        "ip": "81.2.69.192"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "tanium-client_status"
    ],
    "tanium": {
        "client_status": {
            "client_network_location": "67.43.156.0",
            "computer_id": "4008511043",
            "full_version": "7.4.9.1046",
            "host_name": "dhcp-client02.local",
            "last_registration": "2022-10-07T09:20:08.000Z",
            "protocol_version": 315,
            "receive_state": "None",
            "registered_with_tLS": 1,
            "send_state": "None",
            "server_network_location": "81.2.69.192",
            "valid_key": 1,
            "value": "Leader"
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
    "@timestamp": "2022-11-18T10:10:57.000Z",
    "agent": {
        "ephemeral_id": "84713cdb-5fa9-4fdd-a983-b0107bc77e85",
        "id": "4f7f2983-c7e6-4cd4-8e0c-ba2f48aef939",
        "name": "elastic-agent-74263",
        "type": "filebeat",
        "version": "8.16.5"
    },
    "data_stream": {
        "dataset": "tanium.discover",
        "namespace": "40617",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "4f7f2983-c7e6-4cd4-8e0c-ba2f48aef939",
        "snapshot": false,
        "version": "8.16.5"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "tanium.discover",
        "id": "1",
        "ingested": "2025-03-14T15:33:29Z",
        "kind": [
            "event"
        ],
        "original": "{\"Arp\":0,\"AwsApi\":0,\"CentralizedNmap\":0,\"Connected\":0,\"CreatedAt\":\"2022-11-18 09:30:26 +00:00\",\"FirstManagedAt\":null,\"HostName\":\"otelco7_46.test.local\",\"IpAddress\":\"89.160.20.112\",\"Labels\":\"\",\"LastDiscoveredAt\":null,\"LastManagedAt\":\"2022-11-18 10:10:57 +00:00\",\"Locations\":\"\",\"MacAddress\":\"00-51-58-91-62-41\",\"MacOrganization\":\"VMware, Inc.\",\"Managed\":1,\"NatIpAddress\":\"\",\"Nmap\":0,\"Os\":\"linux\",\"OsGeneration\":null,\"Ping\":0,\"Ports\":\"22,41000\",\"Profile\":null,\"SatelliteDecId\":null,\"SatelliteName\":null,\"SatelliteNmap\":0,\"TaniumComputerId\":1558885994,\"Unmanageable\":0,\"UpdatedAt\":\"2022-11-18 10:10:57 +00:00\",\"id\":1}",
        "start": "2022-11-18T09:30:26.000Z",
        "type": [
            "info"
        ]
    },
    "host": {
        "name": "otelco7_46.test.local"
    },
    "input": {
        "type": "http_endpoint"
    },
    "os": {
        "type": "linux"
    },
    "related": {
        "hosts": [
            "otelco7_46.test.local"
        ],
        "ip": [
            "89.160.20.112"
        ]
    },
    "source": {
        "ip": "89.160.20.112",
        "mac": "00-51-58-91-62-41"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "tanium-discover"
    ],
    "tanium": {
        "discover": {
            "arp": 0,
            "aws_api": 0,
            "centralized_nmap": 0,
            "computer_id": 1558885994,
            "connected": 0,
            "created_at": "2022-11-18T09:30:26.000Z",
            "host_name": "otelco7_46.test.local",
            "id": "1",
            "ip_address": "89.160.20.112",
            "last": {
                "managed_at": "2022-11-18T10:10:57.000Z"
            },
            "mac_address": "00-51-58-91-62-41",
            "mac_organization": "VMware, Inc.",
            "managed": 1,
            "nmap": 0,
            "os": "linux",
            "ping": 0,
            "ports": "22,41000",
            "satellite": {
                "nmap": 0
            },
            "unmanageable": 0,
            "updated_at": "2022-11-18T10:10:57.000Z"
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
    "@timestamp": "2025-03-14T15:34:51.887Z",
    "agent": {
        "ephemeral_id": "97f2c3df-5dc5-4f97-9223-fa1f5ac8c72b",
        "id": "2ab9e4ff-beb2-4dc4-9a0c-48c6a22fbd7a",
        "name": "elastic-agent-44696",
        "type": "filebeat",
        "version": "8.16.5"
    },
    "data_stream": {
        "dataset": "tanium.endpoint_config",
        "namespace": "13469",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "2ab9e4ff-beb2-4dc4-9a0c-48c6a22fbd7a",
        "snapshot": false,
        "version": "8.16.5"
    },
    "event": {
        "action": "AUDIT_ACTION_CREATED",
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "dataset": "tanium.endpoint_config",
        "ingested": "2025-03-14T15:34:52Z",
        "kind": [
            "state"
        ],
        "original": "{\"action\":\"AUDIT_ACTION_CREATED\",\"config_item\":{\"data_category\":\"tools\",\"description\":\"Threat Response Stream Toolset\",\"domain\":\"endpoint-config\",\"id\":9},\"timestamp\":\"2022-11-02T13:49:03.993426735Z\",\"user\":{\"persona_id\":0,\"user_id\":1}}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "http_endpoint"
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
| tanium.endpoint_config.manifest.items |  | nested |
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
    "@timestamp": "2025-03-14T15:36:29.944Z",
    "agent": {
        "ephemeral_id": "244333f0-5003-4cee-8448-d09828459c0b",
        "id": "11d08a69-cb83-48b8-8cab-3acd84d27b2a",
        "name": "elastic-agent-91112",
        "type": "filebeat",
        "version": "8.16.5"
    },
    "data_stream": {
        "dataset": "tanium.reporting",
        "namespace": "27499",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "11d08a69-cb83-48b8-8cab-3acd84d27b2a",
        "snapshot": false,
        "version": "8.16.5"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "tanium.reporting",
        "ingested": "2025-03-14T15:36:30Z",
        "kind": [
            "event"
        ],
        "original": "{\"Computer Name\":\"localhost\",\"Count\":3,\"Is Virtual\":\"Yes\",\"Manufacturer\":\"VMware, Inc.\",\"Model\":\"VMware Virtual Platform\",\"OS Platform\":\"Linux\",\"Operating System\":\"CentOS Linux release 7.9.2009 (Core)\",\"Virtual Platform\":\"VMware Virtual Platform\"}",
        "type": [
            "info"
        ]
    },
    "host": {
        "name": "localhost"
    },
    "input": {
        "type": "http_endpoint"
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
        "ephemeral_id": "7e8766b7-9e94-4b15-8535-99b9276327a3",
        "id": "26fcf138-4f2c-4d7f-a6bb-0bae76263446",
        "name": "elastic-agent-42606",
        "type": "filebeat",
        "version": "8.16.5"
    },
    "data_stream": {
        "dataset": "tanium.threat_response",
        "namespace": "13807",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "26fcf138-4f2c-4d7f-a6bb-0bae76263446",
        "snapshot": false,
        "version": "8.16.5"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "dataset": "tanium.threat_response",
        "id": "00000000-0000-0000-5389-4a274d06f4ec",
        "ingested": "2025-03-14T15:38:11Z",
        "kind": "event",
        "original": "{\"Computer IP\":\"81.2.69.192\",\"Computer Name\":\"worker-2\",\"Event Id\":\"00000000-0000-0000-5389-4a274d06f4ec\",\"Event Name\":\"detect.unmatch\",\"Other Parameters\":\"payload=eyJpbnRlbF9pZCI6MTM1LCJjb25maWdfaWQiOjMsImNvbmZpZ19yZXZfaWQiOjEsImZpbmRpbmciOnsid2hhdHMiOlt7ImludGVsX2ludHJhX2lkcyI6W3siaWQiOjg1MDM5NDU4Mn0seyJpZCI6OTgzOTYyMTkzfSx7ImlkIjoyNjY3MDYyMDA2fSx7ImlkIjozMzk4NDE2ODc4fSx7ImlkIjozOTk5MDE0NDY1fV0sInNvdXJjZV9uYW1lIjoicmVjb3JkZXIiLCJhcnRpZmFjdF9hY3Rpdml0eSI6eyJyZWxldmFudF9hY3Rpb25zIjpbeyJ2ZXJiIjo2LCJ0YXJnZXQiOnsiZmlsZSI6eyJwYXRoIjoiL3Zhci9saWIvZG9ja2VyL292ZXJsYXkyLzJiY2ZmYjdmMGQ2YTNmMzdhNjE5OWNhNjkxNjQ5ZWE0OTM1OGEyYzJlODdmMzkyMDI1NjJlNTBlYjVjZDI4MDUvZGlmZi9ldGMvaG9zdHMiLCJoYXNoIjp7Im1kNSI6IjRkMWYxMjU3Yjg0NmJkYTgyZDAzMzhmYjU0MWU3MzAxIiwic2hhMSI6IjA0M2ViMzI0YTY1MzQ1NmNhYTFhNzNlMmUyZDQ5Zjc3NzkyYmIwYzUiLCJzaGEyNTYiOiJlMzk5OGRiZTAyYjUxZGFkYTMzZGU4N2FlNDNkMThhOTNhYjY5MTViOWUzNGY1YTc1MWJmMmI5YjI1YTU1NDkyIn0sInNpemVfYnl0ZXMiOiI3OSIsIm1vZGlmaWNhdGlvbl90aW1lIjoiMjAyMi0wOS0xMVQyMDowODoyNi4wMDBaIiwiaW5zdGFuY2VfaGFzaF9zYWx0IjoiMzAxNDc2NyIsIm1hZ2ljX251bWJlcl9oZXgiOiIzMTMyMzcyZSJ9LCJpbnN0YW5jZV9oYXNoIjoiOTY2NzAxNzM0NTE1MDk2ODM0MiIsImFydGlmYWN0X2hhc2giOiIxMDUzODAwNDU2MTA2MjQ5MDYifSwidGltZXN0YW1wIjoiMjAyMy0wMS0xOFQxMDozNzoxOC4wMDBaIiwidGFuaXVtX3JlY29yZGVyX2V2ZW50X3RhYmxlX2lkIjoiNDYxMTY4NjAxODQ3NTg1NTY3MiIsInRhbml1bV9yZWNvcmRlcl9jb250ZXh0Ijp7ImZpbGUiOnsidW5pcXVlX2V2ZW50X2lkIjoiNDYxMTY4NjAxODQ3NTg1NTY3MiJ9LCJldmVudCI6eyJ0aW1lc3RhbXBfbXMiOiIxNjc0MDM4MjM4NzgwIiwiZmlsZV9jcmVhdGUiOnsicGF0aCI6Ii92YXIvbGliL2RvY2tlci9vdmVybGF5Mi8yYmNmZmI3ZjBkNmEzZjM3YTYxOTljYTY5MTY0OWVhNDkzNThhMmMyZTg3ZjM5MjAyNTYyZTUwZWI1Y2QyODA1L2RpZmYvZXRjL2hvc3RzIn19fX1dLCJhY3RpbmdfYXJ0aWZhY3QiOnsicHJvY2VzcyI6eyJoYW5kbGVzIjpbXSwicGlkIjo0MzE4MSwiYXJndW1lbnRzIjoiZG9ja2VyLXVudGFyIC8gL3Zhci9saWIvZG9ja2VyL292ZXJsYXkyLzJiY2ZmYjdmMGQ2YTNmMzdhNjE5OWNhNjkxNjQ5ZWE0OTM1OGEyYzJlODdmMzkyMDI1NjJlNTBlYjVjZDI4MDUvZGlmZiIsImZpbGUiOnsiZmlsZSI6eyJwYXRoIjoiL3Byb2Mvc2VsZi9leGUifSwiaW5zdGFuY2VfaGFzaCI6IjEzMTY0NjgzMDA4MzA4NzMzMjM2IiwiYXJ0aWZhY3RfaGFzaCI6IjEzMTY0NjgzMDA4MzA4NzMzMjM2In0sInVzZXIiOnsidXNlciI6eyJuYW1lIjoicm9vdCIsImRvbWFpbiI6InJvb3QiLCJ1c2VyX2lkIjoiMCIsImdyb3VwX2lkIjoiMCJ9fSwicGFyZW50Ijp7InByb2Nlc3MiOnsiaGFuZGxlcyI6W10sInBpZCI6MjA1OCwiYXJndW1lbnRzIjoiL3Vzci9iaW4vZG9ja2VyZCAtSCBmZDovLyAtLWNvbnRhaW5lcmQ9L3J1bi9jb250YWluZXJkL2NvbnRhaW5lcmQuc29jayIsImZpbGUiOnsiZmlsZSI6eyJwYXRoIjoiL3Vzci9iaW4vZG9ja2VyZCJ9LCJpbnN0YW5jZV9oYXNoIjoiMTY3ODgxMjYwMTcwOTA1NzEyOTEiLCJhcnRpZmFjdF9oYXNoIjoiMTY3ODgxMjYwMTcwOTA1NzEyOTEifSwidXNlciI6eyJ1c2VyIjp7Im5hbWUiOiJyb290IiwiZG9tYWluIjoicm9vdCIsInVzZXJfaWQiOiI2MDE4ODI2MzA1ODc2NzIzMjY5In19LCJwYXJlbnQiOnsicHJvY2VzcyI6eyJoYW5kbGVzIjpbXSwicGlkIjoxLCJhcmd1bWVudHMiOiIvc2Jpbi9pbml0IiwiZmlsZSI6eyJmaWxlIjp7InBhdGgiOiIvbGliL3N5c3RlbWQvc3lzdGVtZCIsImhhc2giOnsibWQ1IjoiYWM4YjI3Y2U2NjQxY2JhNGVkMmM1ZTc2MmYwNDE5ODYifX0sImluc3RhbmNlX2hhc2giOiIxMzE4Nzc2NjQ1NjAwNzA3MjAxOSIsImFydGlmYWN0X2hhc2giOiIxMzE4Nzc2NjQ1NjAwNzA3MjAxOSJ9LCJ1c2VyIjp7InVzZXIiOnsibmFtZSI6InJvb3QiLCJkb21haW4iOiJyb290IiwidXNlcl9pZCI6IjYwMTg4MjYzMDU4NzY3MjMyNjkifX0sInN0YXJ0X3RpbWUiOiIyMDIzLTAxLTExVDA4OjQ0OjAyLjAwMFoiLCJ0YW5pdW1fdW5pcXVlX2lkIjoiMTE1MjkyNTY2NDI4MjY3MzE1MjEifSwiaW5zdGFuY2VfaGFzaCI6IjMxOTY5NjQ4NTI4NTE4ODUzOSIsImFydGlmYWN0X2hhc2giOiI0NzE0OTAwMTk0MTgwNTMxODM2In0sInN0YXJ0X3RpbWUiOiIyMDIzLTAxLTExVDA4OjQ2OjI0LjAwMFoiLCJ0YW5pdW1fdW5pcXVlX2lkIjoiMTE1Mjk4NjQzMjkxNTk1MTAwMjYifSwiaW5zdGFuY2VfaGFzaCI6IjE3MTMyMTc2Mjk2OTI2MTcwMDY4IiwiYXJ0aWZhY3RfaGFzaCI6IjExNzE1NTUyOTUwODYxMDU3MTc3In0sInN0YXJ0X3RpbWUiOiIyMDIzLTAxLTE4VDEwOjM3OjE4LjAwMFoiLCJ0YW5pdW1fdW5pcXVlX2lkIjoiMTQxNTYwNDI1NzY5OTM0OTUyMTMifSwiaW5zdGFuY2VfaGFzaCI6IjExODg2MzgxNjYzMjk0ODAzMDg2IiwiYXJ0aWZhY3RfaGFzaCI6IjQwMDE0NTA1MTc3OTQzNzAzMjAiLCJpc19pbnRlbF90YXJnZXQiOnRydWV9fX1dLCJkb21haW4iOiJ0aHJlYXRyZXNwb25zZSIsImludGVsX2lkIjoiMTM1OjE6N2I4OWFjMzUtM2U5My00MGZjLWIxNDItYjE5OTk0ZjI4NDMwIiwiaHVudF9pZCI6IjQiLCJ0aHJlYXRfaWQiOiI4NTAzOTQ1ODIsOTgzOTYyNzY1LDI2NjcwNjIwMDYsMjY2NzA2Mjc2OCwyNjY3MDYyNDM1Iiwic291cmNlX25hbWUiOiJyZWNvcmRlcjEiLCJzeXN0ZW1faW5mbyI6eyJvcyI6IlwiVWJ1bnR1IDE4LjA0LjYgTFRTXCIiLCJiaXRzIjo2NCwicGxhdGZvcm0iOiJMaW51eCJ9LCJmaXJzdF9zZWVuIjoiMjAyMy0wMS0xOFQxMDozNzozNi4wMDBaIiwibGFzdF9zZWVuIjoiMjAyMy0wMS0xOFQxMDozNzozNi4wMDBaIiwiZmluZGluZ19pZCI6IjY3ODc5ODcwMTE1MzE3NTYxNjUiLCJyZXBvcnRpbmdfaWQiOiJyZXBvcnRpbmctaWQtcGxhY2Vob2xkZXIifSwibWF0Y2giOnsidmVyc2lvbiI6MSwidHlwZSI6InByb2Nlc3MiLCJzb3VyY2UiOiJyZWNvcmRlciIsImhhc2giOiI0MDAxNDUwNTE3Nzk0MzcwMzIwIiwicHJvcGVydGllcyI6eyJwaWQiOjQzMTgxLCJhcmdzIjoiZG9ja2VyLXVudGFyIC8gL3Zhci9saWIvZG9ja2VyL292ZXJsYXkyLzJiY2ZmYjdmMGQ2YTNmMzdhNjE5OWNhNjkxNjQ5ZWE0OTM1OGEyYzJlODdmMzkyMDI1NjJlNTBlYjVjZDI4MDUvZGlmZiIsInJlY29yZGVyX3VuaXF1ZV9pZCI6IjE0MTU2MDQyNTc2OTkzNDk1MjEzIiwic3RhcnRfdGltZSI6IjIwMjMtMDEtMThUMTA6Mzc6MTguMDAwWiIsInBwaWQiOjIwNTgsInVzZXIiOiJyb290XFxyb290IiwiZmlsZSI6eyJmdWxscGF0aCI6Ii9wcm9jL3NlbGYvZXhlIn0sIm5hbWUiOiIvcHJvYy9zZWxmL2V4ZSIsInBhcmVudCI6eyJwaWQiOjIwNTgsImFyZ3MiOiIvdXNyL2Jpbi9kb2NrZXJkIC1IIGZkOi8vIC0tY29udGFpbmVyZD0vcnVuL2NvbnRhaW5lcmQvY29udGFpbmVyZC5zb2NrIiwicmVjb3JkZXJfdW5pcXVlX2lkIjoiMTE1Mjk4NjQzMjkxNTk1MTAwMjYiLCJzdGFydF90aW1lIjoiMjAyMy0wMS0xMVQwODo0NjoyNC4wMDBaIiwicHBpZCI6MSwidXNlciI6InJvb3RcXHJvb3QiLCJmaWxlIjp7ImZ1bGxwYXRoIjoiL3Vzci9iaW4vZG9ja2VyZCJ9LCJuYW1lIjoiL3Vzci9iaW4vZG9ja2VyZCIsInBhcmVudCI6eyJwaWQiOjEsImFyZ3MiOiIvc2Jpbi9pbml0IiwicmVjb3JkZXJfdW5pcXVlX2lkIjoiMTE1MjkyNTY2NDI4MjY3MzE1MjEiLCJzdGFydF90aW1lIjoiMjAyMy0wMS0xMVQwODo0NDowMi4wMDBaIiwidXNlciI6InJvb3RcXHJvb3QiLCJmaWxlIjp7Im1kNSI6ImFjOGIyN2NlNjY0MWNiYTRlZDJjNWU3NjJmMDQxOTg2IiwiZnVsbHBhdGgiOiIvbGliL3N5c3RlbWQvc3lzdGVtZCJ9LCJuYW1lIjoiL2xpYi9zeXN0ZW1kL3N5c3RlbWQifX19LCJjb250ZXh0cyI6W3siZmlsZSI6eyJ1bmlxdWVFdmVudElkIjoiNDYxMTY4NjAxODQ3NTg1NTY3MiJ9LCJldmVudCI6eyJ0aW1lc3RhbXBNcyI6IjE2NzQwMzgyMzg3ODAiLCJmaWxlQ3JlYXRlIjp7InBhdGgiOiIvdmFyL2xpYi9kb2NrZXIvb3ZlcmxheTIvMmJjZmZiN2YwZDZhM2YzN2E2MTk5Y2E2OTE2NDllYTQ5MzU4YTJjMmU4N2YzOTIwMjU2MmU1MGViNWNkMjgwNS9kaWZmL2V0Yy9ob3N0cyJ9fX1dfX0=\",\"Priority\":\"high\",\"Severity\":\"info\",\"Timestamp\":\"2023-01-18T10:13:28.000Z\",\"User Domain\":\"xyz\",\"User Id\":\"\",\"User Name\":\"\"}",
        "type": [
            "info"
        ]
    },
    "host": {
        "name": "worker-2"
    },
    "input": {
        "type": "http_endpoint"
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
            "match_details": {
                "config_id": 3,
                "config_rev_id": 1,
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
                                                        "pid": 1,
                                                        "start_time": "2023-01-11T08:44:02.000Z",
                                                        "tanium_unique_id": "11529256642826731521",
                                                        "user": {
                                                            "domain": "root",
                                                            "id": "6018826305876723269",
                                                            "name": "root"
                                                        }
                                                    }
                                                },
                                                "pid": 2058,
                                                "start_time": "2023-01-11T08:46:24.000Z",
                                                "tanium_unique_id": "11529864329159510026",
                                                "user": {
                                                    "domain": "root",
                                                    "id": "6018826305876723269",
                                                    "name": "root"
                                                }
                                            }
                                        },
                                        "pid": 43181,
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
                "intel_id": 135,
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
                                "pid": 1,
                                "recorder_unique_id": "11529256642826731521",
                                "start_time": "2023-01-11T08:44:02.000Z",
                                "user": "root\\root"
                            },
                            "pid": 2058,
                            "ppid": 1,
                            "recorder_unique_id": "11529864329159510026",
                            "start_time": "2023-01-11T08:46:24.000Z",
                            "user": "root\\root"
                        },
                        "pid": 43181,
                        "ppid": 2058,
                        "recorder_unique_id": "14156042576993495213",
                        "start_time": "2023-01-18T10:37:18.000Z",
                        "user": "root\\root"
                    },
                    "source": "recorder",
                    "type": "process",
                    "version": 1
                }
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
| tanium.threat_response.alert_id | Alert ID | keyword |
| tanium.threat_response.computer.ip | Computer ip of the threat response. | ip |
| tanium.threat_response.computer.name | Computer name of the threat response. | keyword |
| tanium.threat_response.created_at | Create time for the threat response. | date |
| tanium.threat_response.event.id | Event id of the threat response.. | keyword |
| tanium.threat_response.event.name | Event name of the threat response. | keyword |
| tanium.threat_response.id | Threat response id. | keyword |
| tanium.threat_response.impact_score | Impact score | integer |
| tanium.threat_response.intel_id | Intelligence ID | keyword |
| tanium.threat_response.intel_name | Intelligence name | keyword |
| tanium.threat_response.intel_type | Intelligence type | keyword |
| tanium.threat_response.link | Link | keyword |
| tanium.threat_response.match_details.config_id | Config id. | keyword |
| tanium.threat_response.match_details.config_rev_id | Config rev.iD. | keyword |
| tanium.threat_response.match_details.finding.domain | Finding domain. | keyword |
| tanium.threat_response.match_details.finding.first_seen | First seen. | date |
| tanium.threat_response.match_details.finding.hunt_id | Hunt id. | keyword |
| tanium.threat_response.match_details.finding.id | Finding id. | keyword |
| tanium.threat_response.match_details.finding.intel_id | Finding intel id. | keyword |
| tanium.threat_response.match_details.finding.last_seen | Last seen. | date |
| tanium.threat_response.match_details.finding.reporting_id | Finding reporting id. | keyword |
| tanium.threat_response.match_details.finding.source_name | Source name. | keyword |
| tanium.threat_response.match_details.finding.system_info.bits | Bits. | long |
| tanium.threat_response.match_details.finding.system_info.build_number | Build number. | keyword |
| tanium.threat_response.match_details.finding.system_info.os.platform | OS platform. | keyword |
| tanium.threat_response.match_details.finding.system_info.os.value | OS value. | keyword |
| tanium.threat_response.match_details.finding.system_info.os.version | OS version. | version |
| tanium.threat_response.match_details.finding.system_info.patch_level | Patch level. | keyword |
| tanium.threat_response.match_details.finding.system_info.platform | OS type. | keyword |
| tanium.threat_response.match_details.finding.threat_id | Threat id. | keyword |
| tanium.threat_response.match_details.finding.whats |  | nested |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.artifact_hash | Artifact hash of activity. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.instance_hash | Instance hash of activity. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.is_intel_target | Intel target or not. | boolean |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.arguments | Process arguments. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.file.artifact_hash | Artifact hash of file. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.file.instance_hash | Instance hash of file. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.file.path | Path of file. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.handles | Process handles. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.parent.artifact_hash | Artifact hash. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.parent.instance_hash | Instance hash. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.parent.process.arguments | Process arguments. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.parent.process.file.artifact_hash | Artifact hash of file. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.parent.process.file.instance_hash | Instance hash of file. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.parent.process.file.path | Path of file. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.parent.process.handles | Process handles. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.parent.process.parent.artifact_hash | Artifact hash. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.parent.process.parent.instance_hash | Instance hash. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.parent.process.parent.process.arguments | Process arguments. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.parent.process.parent.process.file.artifact_hash | Artifact hash of file. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.parent.process.parent.process.file.hash.md5 | MD5 hash. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.parent.process.parent.process.file.instance_hash | Instance hash of file. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.parent.process.parent.process.file.path | Path of file. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.parent.process.parent.process.handles | Process handles. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.parent.process.parent.process.md5 | MD5 keyword. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.parent.process.parent.process.pid | Process id. | long |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.parent.process.parent.process.start_time | Start time. | date |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.parent.process.parent.process.tanium_unique_id | Tanium unique id. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.parent.process.parent.process.user.domain | User domain. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.parent.process.parent.process.user.id | User id. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.parent.process.parent.process.user.name | User name. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.parent.process.pid | Process id. | long |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.parent.process.start_time | Start time. | date |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.parent.process.tanium_unique_id | Tanium unique id. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.parent.process.user.domain | User domain. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.parent.process.user.group_id | User group id. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.parent.process.user.id | User id. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.parent.process.user.name | User name. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.pid | Parent id. | long |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.start_time | Start time. | date |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.tanium_unique_id | Tanium unique id. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.user.domain | User domain. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.user.group_id | User group id. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.user.id | User id. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.acting_artifact.process.user.name | User name. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions |  | nested |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.tanium_recorder_context.event.file_create.path | Path of file. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.tanium_recorder_context.event.timestamp_ms | Timestamp in milliseconds. | date |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.tanium_recorder_context.file.unique_event_id | Unique event id. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.tanium_recorder_event_table_id | Tanium recorder event table id. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.artifact_hash | Artifact hash of file. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.file.hash.md5 | MD5 hash. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.file.hash.sha1 | SHA1 hash. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.file.hash.sha256 | SHA256 hash. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.file.instance_hash | Instance hash. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.file.instance_hash_salt | Instance hash salt. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.file.magic_number_hex | Magic number. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.file.modification_time | Modification time of file. | date |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.file.path | Path of file. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.file.size_bytes | File size in bytes. | long |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.instance_hash | Instance hash. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.is_intel_target | Is an intel target. | boolean |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.connection_time | Connection time. | date |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.local_ip | Local IP. | ip |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.local_port | Local port. | long |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.artifact_hash | Artifact hash. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.instance_hash | Instance hash. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.arguments | Process arguments. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.file.artifact_hash | Artifact hash of file. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.file.file.path | Path of file. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.file.file.signature_data.issuer | Signature issuer. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.file.file.signature_data.status | Signature status. | long |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.file.file.signature_data.subject | Signature subject. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.file.instance_hash | Instance hash of file. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.name | Name. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.artifact_hash | Artifact hash. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.instance_hash | Instance hash. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.arguments | Process arguments. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.file.artifact_hash | Artifact hash of file. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.file.file.path | Path of file. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.file.file.signature_data.issuer | Signature issuer. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.file.file.signature_data.status | Signature status. | long |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.file.file.signature_data.subject | Signature subject. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.file.instance_hash | Instance hash of file. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.name | Name. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.parent.artifact_hash | Artifact hash. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.parent.instance_hash | Instance hash. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.parent.process.arguments | Process arguments. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.parent.process.file.artifact_hash | Artifact hash of file. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.parent.process.file.file.path | Path of file. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.parent.process.file.file.signature_data.issuer | Signature issuer. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.parent.process.file.file.signature_data.status | Signature status. | long |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.parent.process.file.file.signature_data.subject | Signature subject. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.parent.process.file.instance_hash | Instance hash of file. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.parent.process.name | Name. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.parent.process.parent.artifact_hash | Artifact hash. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.parent.process.parent.instance_hash | Instance hash. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.parent.process.parent.process.arguments | Process arguments. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.parent.process.parent.process.file.artifact_hash | Artifact hash of file. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.parent.process.parent.process.file.file.path | Path of file. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.parent.process.parent.process.file.instance_hash | Instance hash of file. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.parent.process.parent.process.name | Name. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.parent.process.parent.process.parent.artifact_hash | Artifact hash. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.parent.process.parent.process.parent.instance_hash | Instance hash. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.parent.process.parent.process.parent.process.tanium_recorder_table_id | Tanium recorder table id. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.parent.process.parent.process.pid | Process id. | long |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.parent.process.parent.process.start_time | Start time. | date |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.parent.process.parent.process.tanium_recorder_table_id | Tanium recorder table id. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.parent.process.parent.process.user.user.domain | User domain. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.parent.process.parent.process.user.user.name | User name. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.parent.process.parent.process.user.user.user_id | User id. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.parent.process.pid | Process id. | long |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.parent.process.start_time | Start time. | date |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.parent.process.tanium_recorder_table_id | Tanium recorder table id. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.parent.process.user.user.domain | User domain. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.parent.process.user.user.name | User name. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.parent.process.user.user.user_id | User id. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.pid | Process id. | long |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.start_time | Start time. | date |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.tanium_recorder_table_id | Tanium recorder table id. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.user.user.domain | User domain. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.user.user.name | User name. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.parent.process.user.user.user_id | User id. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.pid | Process id. | long |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.start_time | Start time. | date |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.tanium_recorder_table_id | Tanium recorder table id. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.user.user.domain | User domain. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.user.user.name | User name. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.process.process.user.user.user_id | User id. | keyword |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.remote_ip | Remote IP. | ip |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.target.port.remote_port | Remote port. | long |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.timestamp | Timestamp. | date |
| tanium.threat_response.match_details.finding.whats.artifact_activity.relevant_actions.verb | Verb. | long |
| tanium.threat_response.match_details.finding.whats.intel_intra_ids |  | nested |
| tanium.threat_response.match_details.finding.whats.intel_intra_ids.id | Array of intel intra ids. | keyword |
| tanium.threat_response.match_details.finding.whats.intel_intra_ids.id_v2 | Array of v2 intel intra ids. | keyword |
| tanium.threat_response.match_details.finding.whats.source_name | Source name. | keyword |
| tanium.threat_response.match_details.intel_id | Intel id. | keyword |
| tanium.threat_response.match_details.match.contexts |  | nested |
| tanium.threat_response.match_details.match.contexts.event.file_create.path | Path of file. | keyword |
| tanium.threat_response.match_details.match.contexts.event.timestampMs | Timestamp in milliseconds. | date |
| tanium.threat_response.match_details.match.contexts.file.unique_event_id | Unique event id of file. | keyword |
| tanium.threat_response.match_details.match.hash | Hash value. | keyword |
| tanium.threat_response.match_details.match.properties.args | Property arguments. | keyword |
| tanium.threat_response.match_details.match.properties.file.full_path | Full path of file. | keyword |
| tanium.threat_response.match_details.match.properties.fullpath | Full path. | keyword |
| tanium.threat_response.match_details.match.properties.local_ip | Local IP. | ip |
| tanium.threat_response.match_details.match.properties.local_port | Local port. | long |
| tanium.threat_response.match_details.match.properties.md5 | MD5 hash. | keyword |
| tanium.threat_response.match_details.match.properties.name | Property name. | keyword |
| tanium.threat_response.match_details.match.properties.parent.args | Parent arguments. | keyword |
| tanium.threat_response.match_details.match.properties.parent.file.full_path | Full path of file. | keyword |
| tanium.threat_response.match_details.match.properties.parent.name | Parent name. | keyword |
| tanium.threat_response.match_details.match.properties.parent.parent.args | Parent arguments. | keyword |
| tanium.threat_response.match_details.match.properties.parent.parent.file.full_path | Full path of file. | keyword |
| tanium.threat_response.match_details.match.properties.parent.parent.file.md5 | MD5. | keyword |
| tanium.threat_response.match_details.match.properties.parent.parent.name | Parent name. | keyword |
| tanium.threat_response.match_details.match.properties.parent.parent.pid | Parent id. | long |
| tanium.threat_response.match_details.match.properties.parent.parent.recorder_unique_id | Recorder unique id. | keyword |
| tanium.threat_response.match_details.match.properties.parent.parent.start_time | Start time. | date |
| tanium.threat_response.match_details.match.properties.parent.parent.user | User. | keyword |
| tanium.threat_response.match_details.match.properties.parent.pid | Process id. | long |
| tanium.threat_response.match_details.match.properties.parent.ppid | Parent process id. | long |
| tanium.threat_response.match_details.match.properties.parent.recorder_unique_id | Recorder unique id. | keyword |
| tanium.threat_response.match_details.match.properties.parent.start_time | Start time. | date |
| tanium.threat_response.match_details.match.properties.parent.user | User. | keyword |
| tanium.threat_response.match_details.match.properties.pid | Process id. | long |
| tanium.threat_response.match_details.match.properties.ppid | Parent process id. | long |
| tanium.threat_response.match_details.match.properties.process.args | Process arguments. | keyword |
| tanium.threat_response.match_details.match.properties.process.file.fullpath | Full path. | keyword |
| tanium.threat_response.match_details.match.properties.process.name | Name. | keyword |
| tanium.threat_response.match_details.match.properties.process.pid | Process id. | long |
| tanium.threat_response.match_details.match.properties.process.ppid | Parent process id. | long |
| tanium.threat_response.match_details.match.properties.process.recorder_table_id | Tanium recorder table id. | keyword |
| tanium.threat_response.match_details.match.properties.process.start_time | Start time. | date |
| tanium.threat_response.match_details.match.properties.process.user | User. | keyword |
| tanium.threat_response.match_details.match.properties.recorder_unique_id | Recorder unique id. | keyword |
| tanium.threat_response.match_details.match.properties.remote_ip | Remote IP. | ip |
| tanium.threat_response.match_details.match.properties.remote_port | Remote port. | long |
| tanium.threat_response.match_details.match.properties.sha1 | SHA1 hash. | keyword |
| tanium.threat_response.match_details.match.properties.sha256 | SHA256 hash. | keyword |
| tanium.threat_response.match_details.match.properties.size | Size. | keyword |
| tanium.threat_response.match_details.match.properties.start_time | Start time. | date |
| tanium.threat_response.match_details.match.properties.user | User. | keyword |
| tanium.threat_response.match_details.match.source | Finding source. | keyword |
| tanium.threat_response.match_details.match.type | Finding type. | keyword |
| tanium.threat_response.match_details.match.version | Finding version. | version |
| tanium.threat_response.other_parameters.name | Name of threat. | keyword |
| tanium.threat_response.other_parameters.source | Source of threat. | keyword |
| tanium.threat_response.other_parameters.type | Type of threat. | keyword |
| tanium.threat_response.priority | Priority of the threat response. | keyword |
| tanium.threat_response.revision | Revision of the threat response. | keyword |
| tanium.threat_response.row_id | Row id for the threat response. | keyword |
| tanium.threat_response.severity | Severity of the threat response. | keyword |
| tanium.threat_response.state.action_expiration | Action expiration. | date |
| tanium.threat_response.state.action_id_unix | UNIX action ID. | integer |
| tanium.threat_response.state.action_id_windows | Windows action ID. | integer |
| tanium.threat_response.state.computer_group_id | Computer group ID. | integer |
| tanium.threat_response.state.computer_ip_address | Computer IP address. | integer |
| tanium.threat_response.state.computer_name | Computer name. | keyword |
| tanium.threat_response.state.connection_id | Connection id of the threat response state. | keyword |
| tanium.threat_response.state.created_at | Creation time. | date |
| tanium.threat_response.state.id | ID. | integer |
| tanium.threat_response.state.intel_id | Intel ID. | integer |
| tanium.threat_response.state.legacy_type | Legacy type. | keyword |
| tanium.threat_response.state.service_id | Service ID. | keyword |
| tanium.threat_response.state.session_id | Session id of the threat response state. | keyword |
| tanium.threat_response.state.target.eid | Target eid of the threat response state. | keyword |
| tanium.threat_response.state.target.hostname | Target hostname of the threat response state. | keyword |
| tanium.threat_response.state.updated_at | Update time. | date |
| tanium.threat_response.state.user_id | User ID. | integer |
| tanium.threat_response.table | Table for the threat response. | keyword |
| tanium.threat_response.timestamp | Timestamp of the event. | date |
| tanium.threat_response.updated_at | Threat response update time. | date |
| tanium.threat_response.user.domain | User domain of the threat response. | keyword |
| tanium.threat_response.user.id | User id for the threat response. | keyword |
| tanium.threat_response.user.name | User name for the threat response. | keyword |
| tanium.truncations | JSON paths that were removed to avoid excessive depth. | keyword |

