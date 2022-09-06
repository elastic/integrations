# Microsoft Exchange Online Message Trace

This integration is for Microsoft Exchange Online Message Trace logs. It includes the following
datasets for receiving logs over syslog or read from a file:

- `log` dataset: supports Microsoft Exchange Online Message Trace logs.

## Logs

### Microsoft Exchange Online Message Trace

The `log` dataset collects the Microsoft Exchange Online Message Trace logs.

[Log Documentation](https://docs.microsoft.com/en-us/previous-versions/office/developer/o365-enterprise-developers/jj984335(v=office.15))

An example event for `log` looks as following:

```json
{
    "_index": ".ds-logs-microsoft_exchange_online_message_trace.log-default-2022.09.06-000001",
    "_id": "XSF2EoMBTgnYwLJGQys0",
    "_version": 1,
    "_score": 0,
    "_source": {
        "agent": {
            "name": "docker-fleet-agent",
            "id": "80b39cad-d415-43ee-8502-e30af004b9cd",
            "type": "filebeat",
            "ephemeral_id": "2ed21e6a-0aed-4fae-a502-140c3144a581",
            "version": "8.3.3"
        },
        "elastic_agent": {
            "id": "80b39cad-d415-43ee-8502-e30af004b9cd",
            "version": "8.3.3",
            "snapshot": false
        },
        "source": {
            "ip": "51.140.75.55"
        },
        "tags": [
            "forwarded"
        ],
        "input": {
            "type": "httpjson"
        },
        "@timestamp": "2022-09-06T11:01:23.939Z",
        "ecs": {
            "version": "8.3.1"
        },
        "data_stream": {
            "namespace": "default",
            "type": "logs",
            "dataset": "microsoft_exchange_online_message_trace.log"
        },
        "event": {
            "agent_id_status": "verified",
            "ingested": "2022-09-06T11:01:23Z",
            "created": "2022-09-06T11:01:22.889Z",
            "dataset": "microsoft_exchange_online_message_trace.log",
            "outcome": "Delivered"
        },
        "email": {
            "attachments": {
                "file": {
                    "size": 87891
                }
            },
            "local_id": "cf7a249a-5edd-4350-130a-08da8f69e0f6",
            "subject": "PIM: A privileged directory role was assigned outside of PIM",
            "delivery_timestamp": "2022-09-05T18:10:13.4907658",
            "from": {
                "address": "azure-noreply@microsoft.com"
            },
            "message_id": "\u003ca210cf91-4f2e-484c-8ada-3b27064ee5e3@az.uksouth.production.microsoft.com\u003e",
            "to": {
                "address": "linus@wildsecurity.onmicrosoft.com"
            }
        }
    },
    "fields": {
        "email.subject": [
            "PIM: A privileged directory role was assigned outside of PIM"
        ],
        "email.attachments.file.size": [
            87891
        ],
        "elastic_agent.version": [
            "8.3.3"
        ],
        "agent.type": [
            "filebeat"
        ],
        "email.subject.text": [
            "PIM: A privileged directory role was assigned outside of PIM"
        ],
        "email.to.address": [
            "linus@wildsecurity.onmicrosoft.com"
        ],
        "source.ip": [
            "51.140.75.55"
        ],
        "agent.name": [
            "docker-fleet-agent"
        ],
        "elastic_agent.snapshot": [
            false
        ],
        "event.agent_id_status": [
            "verified"
        ],
        "event.outcome": [
            "Delivered"
        ],
        "elastic_agent.id": [
            "80b39cad-d415-43ee-8502-e30af004b9cd"
        ],
        "data_stream.namespace": [
            "default"
        ],
        "email.delivery_timestamp": [
            "2022-09-05T18:10:13.490Z"
        ],
        "email.message_id": [
            "\u003ca210cf91-4f2e-484c-8ada-3b27064ee5e3@az.uksouth.production.microsoft.com\u003e"
        ],
        "email.from.address": [
            "azure-noreply@microsoft.com"
        ],
        "input.type": [
            "httpjson"
        ],
        "data_stream.type": [
            "logs"
        ],
        "tags": [
            "forwarded"
        ],
        "event.ingested": [
            "2022-09-06T11:01:23.000Z"
        ],
        "@timestamp": [
            "2022-09-06T11:01:23.939Z"
        ],
        "agent.id": [
            "80b39cad-d415-43ee-8502-e30af004b9cd"
        ],
        "ecs.version": [
            "8.3.1"
        ],
        "data_stream.dataset": [
            "microsoft_exchange_online_message_trace.log"
        ],
        "event.created": [
            "2022-09-06T11:01:22.889Z"
        ],
        "agent.ephemeral_id": [
            "2ed21e6a-0aed-4fae-a502-140c3144a581"
        ],
        "agent.version": [
            "8.3.3"
        ],
        "email.local_id": [
            "cf7a249a-5edd-4350-130a-08da8f69e0f6"
        ],
        "event.dataset": [
            "microsoft_exchange_online_message_trace.log"
        ]
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
