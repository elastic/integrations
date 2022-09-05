# Microsoft Exchange Online Message Trace

This integration is for Microsoft Exchange Online Message Trace logs. It includes the following
datasets for receiving logs over syslog or read from a file:

- `log` dataset: supports Microsoft Exchange Online Message Trace logs.

## Logs

### Microsoft Exchange Online Message Trace

The `log` dataset collects the Microsoft Exchange Online Message Trace logs.

[Log Documentation](https://medium.com/@nonostar/siem-how-to-push-o365-exchange-online-message-details-into-elk-the-messagetrace-api-34f579abd804)

An example event for `log` looks as following:

```json
{
    "agent": {
        "name": "docker-fleet-agent",
        "id": "ca0beb8d-9522-4450-8af7-3cb7f3d8c478",
        "type": "filebeat",
        "ephemeral_id": "adc79855-a07e-4f88-b14d-79d03400f73d",
        "version": "8.2.0"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/test-dhcpV6.log"
        },
        "offset": 1619
    },
    "elastic_agent": {
        "id": "ca0beb8d-9522-4450-8af7-3cb7f3d8c478",
        "version": "8.2.0",
        "snapshot": false
    },
    "message": "DHCPV6 Request",
    "microsoft": {
        "dhcp": {
            "duid": {
                "length": "18",
                "hex": "0004A34473BFC27FC55B25E86AF0E1761DAA"
            }
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "microsoft_dhcp"
    ],
    "observer": {
        "hostname": "docker-fleet-agent",
        "ip": [
            "172.18.0.7"
        ],
        "mac": [
            "02-42-AC-12-00-07"
        ]
    },
    "input": {
        "type": "log"
    },
    "@timestamp": "2021-12-06T12:43:57.000-05:00",
    "ecs": {
        "version": "8.3.0"
    },
    "data_stream": {
        "namespace": "ep",
        "type": "logs",
        "dataset": "microsoft_dhcp.log"
    },
    "host": {
        "ip": "2a02:cf40:add:4002:91f2:a9b2:e09a:6fc6",
        "domain": "test-host"
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2022-05-09T14:40:22Z",
        "original": "11002,12/06/21,12:43:57,DHCPV6 Request,2a02:cf40:add:4002:91f2:a9b2:e09a:6fc6,test-host,,18,0004A34473BFC27FC55B25E86AF0E1761DAA,,,,,",
        "code": "11002",
        "timezone": "America/New_York",
        "kind": "event",
        "action": "dhcpv6-request",
        "category": [
            "network"
        ],
        "type": [
            "connection",
            "protocol"
        ],
        "dataset": "microsoft_dhcp.log",
        "outcome": "success"
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
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| email.attachments.file.size | Attachment file size in bytes. | long |
| email.delivery_timestamp | The date and time when the email message was received by the service or client. | date |
| email.direction | The direction of the message based on the sending and receiving domains. | keyword |
| email.from.address | The email address of the sender, typically from the RFC 5322 `From:` header field. | keyword |
| email.local_id | Unique identifier given to the email by the source that created the event. Identifier is not persistent across hops. | keyword |
| email.message_id | Identifier from the RFC 5322 `Message-ID:` email header that refers to a particular email message. | wildcard |
| email.subject | A brief summary of the topic of the message. | keyword |
| email.subject.text | Multi-field of `email.subject`. | match_only_text |
| email.to.address | The email address of recipient | keyword |
| input.type |  | keyword |
| log.offset |  | long |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location.lat | Longitude and latitude. | geo_point |
| source.geo.location.lon | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
