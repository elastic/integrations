# DomainTools Feeds

DomainTools Feeds provide data on the different stages of the domain lifecycle: from first-observed in the wild, to newly re-activated after a period of quiet. Access current feed data in real-time or retrieve historical feed data through separate APIs. Some feeds also offer data for DNS firewalls in Response Policy Zone (RPZ) format.

Summary of Available Feeds:

- `Newly Active Domains (NAD)`: Apex-level domains (e.g. example.com but not <www.example.com>) that we observe based on the latest lifecycle of the domain. A domain may be seen either for the first time ever, or again after at least 10 days of inactivity (no observed resolutions in DNS). Populated with our global passive DNS (pDNS) sensor network.
- `Newly Observed Domains (NOD)`: Apex-level domains (e.g. example.com but not <www.example.com>) that we observe for the first time, and have not observed previously with our global DNS sensor network.
- `Domain Discovery`: New domains as they are either discovered in domain registration information, observed by our global sensor network, or reported by trusted third parties.
- `Domain RDAP`: Changes to global domain registration information, populated by the Registration Data Access Protocol (RDAP). Compliments the 5-Minute WHOIS Feed as registries and registrars switch from Whois to RDAP.

With over 300,000 new domains observed daily, the feed empowers security teams to identify and block potentially malicious domains before they can be weaponized.
Ideal for threat hunting, phishing prevention, and brand protection.

For example, if you wanted to monitor Newly Observed Domains (NOD) feed, you could ingest the DomainTools NOD feed.
Then you can reference ti_domaintools.nod_feed when using visualizations or alerts.

## Data streams

The DomainTools Feeds integration collects one type of data streams: **logs**

Log data streams collected by the DomainTools integration include the following feeds:

- `Newly Observed Domains (NOD)`
- `Newly Active Domains (NAD)`
- `Domain Discovery`
- `Domain RDAP`

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

You will require a license to one or more DomainTools feeds, and API credentials.
Your required API credentials will vary with your authentication method, detailed below.

Obtain your API credentials from your group’s API administrator.
API administrators can manage their API keys at research.domaintools.com, selecting the drop-down account menu and choosing API admin.

## Setup

For step-by-step instructions on how to set up an integration, see the Getting started guide.

### Newly Observed Domains (NOD) Feed

The `nod_feed` data stream provides events from [DomainTools Newly Observed Domains Feed](https://www.domaintools.com/products/threat-intelligence-feeds/).
This data is collected via the [DomainTools Feeds API](https://docs.domaintools.com/feeds/realtime/).

#### Example

An example event for `nod_feed` looks as following:

```json
{
    "@timestamp": "2025-06-17T05:55:49.465Z",
    "agent": {
        "ephemeral_id": "342683ed-b707-4537-bf91-16233fc78a31",
        "id": "df6cda61-c87d-40c3-92d1-6eb4f18f3a79",
        "name": "elastic-agent-42619",
        "type": "filebeat",
        "version": "8.15.3"
    },
    "data_stream": {
        "dataset": "ti_domaintools.nod_feed",
        "namespace": "30698",
        "type": "logs"
    },
    "domaintools": {
        "domain": "test1.com",
        "timestamp": "2025-01-11T08:42:46Z"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "da8d0a37-2d46-4788-96bd-e9ee19e332ec",
        "version": "8.15.3",
        "snapshot": false
    },
    "domaintools": {
        "domain": "tractorpoweredcoreaerator.com",
        "feed": "nod",
        "timestamp": "2025-01-30T20:14:48Z"
    },
    "threat": {
        "indicator": {
            "name": "tractorpoweredcoreaerator.com",
            "type": "domain-name"
        },
        "feed": {
            "reference": "https://docs.techdocs.ci.domaintools.cloud/feeds/realtime/userguide/",
            "name": "DomainTools NOD",
            "description": "Apex-level domains (e.g. example.com but not www.example.com) that we observe for the first time, and have not observed previously with our global DNS sensor network."
        }
    },
    "message": "{\"timestamp\":\"2025-01-30T20:14:48Z\",\"domain\":\"tractorpoweredcoreaerator.com\"}",
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_domaintools.nod_feed",
        "ingested": "2025-06-17T05:55:52Z",
        "kind": "enrichment",
        "type": [
            "indicator"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "elastic-agent-42619",
        "id": "328e5cd3dfd442488a3dd49bf596f391",
        "ip": [
            "192.168.241.2",
            "192.168.254.4"
        ],
        "mac": [
            "02-42-C0-A8-F1-02",
            "02-42-C0-A8-FE-04"
        ],
        "name": "elastic-agent-42619",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.119.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "input": {
        "type": "cel"
    },
    "message": "{\"timestamp\":\"2025-01-11T08:42:46Z\",\"domain\":\"test1.com\"}",
    "threat": {
        "feed": {
            "description": "Apex-level domains (e.g. example.com but not www.example.com) that we observe for the first time, and have not observed previously with our global DNS sensor network.",
            "name": "DomainTools NOD",
            "reference": "https://docs.techdocs.ci.domaintools.cloud/feeds/realtime/userguide/"
        },
        "indicator": {
            "name": "test1.com",
            "type": "domain-name"
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| domaintools.domain | The Domain. Apex-level domains (e.g. example.com but not www.example.com) that we observe for the first time, and have not observed previously with our global DNS sensor network. | keyword |
| domaintools.feed | The feed. | constant_keyword |
| domaintools.timestamp | Timestamp when the domain was added to the DomainTools feed, in ISO 8601 UTC form. | date |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| message | The feed. | match_only_text |
| threat.feed.description | Display the feed description. | constant_keyword |
| threat.feed.name | Display friendly feed name. | constant_keyword |
| threat.feed.reference | Display the feed reference. | constant_keyword |
| threat.indicator.name | The display name indicator in an UI friendly format URL, IP address, email address, registry key, port number, hash value, or other relevant name can serve as the display name. | keyword |
| threat.indicator.type | Type of indicator as represented by Cyber Observable in STIX 2.0. | keyword |


### Newly Active Domains (NAD) Feed

The `nod_feed` data stream provides events from [DomainTools Newly Active Domains Feed](https://www.domaintools.com/products/threat-intelligence-feeds/).
This data is collected via the [DomainTools Feeds API](https://docs.domaintools.com/feeds/realtime/).

#### Example

An example event for `nad_feed` looks as following:

```json
{
    "input": {
        "type": "cel"
    },
    "agent": {
        "name": "docker-fleet-agent",
        "id": "da8d0a37-2d46-4788-96bd-e9ee19e332ec",
        "ephemeral_id": "d1cbe648-0a1d-48e8-a161-cd82403e623e",
        "type": "filebeat",
        "version": "8.15.3"
    },
    "@timestamp": "2025-01-30T20:15:25.396Z",
    "ecs": {
        "version": "8.11.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "logs",
        "dataset": "ti_domaintools.nad_feed"
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "6.10.11-linuxkit",
            "codename": "focal",
            "name": "Ubuntu",
            "type": "linux",
            "family": "debian",
            "version": "20.04.6 LTS (Focal Fossa)",
            "platform": "ubuntu"
        },
        "containerized": false,
        "ip": [
            "172.19.0.10"
        ],
        "name": "docker-fleet-agent",
        "id": "cfae1e7244ae479b9b0968259c91b13a",
        "mac": [
            "02-42-AC-13-00-0A"
        ],
        "architecture": "aarch64"
    },
    "elastic_agent": {
        "id": "da8d0a37-2d46-4788-96bd-e9ee19e332ec",
        "version": "8.15.3",
        "snapshot": false
    },
    "domaintools": {
        "domain": "tractorpoweredcoreaerator.com",
        "feed": "nad",
        "timestamp": "2025-01-30T20:14:48Z"
    },
    "threat": {
        "indicator": {
            "name": "tractorpoweredcoreaerator.com",
            "type": "domain-name"
        },
        "feed": {
            "reference": "https://docs.techdocs.ci.domaintools.cloud/feeds/realtime/userguide/",
            "name": "DomainTools NAD",
            "description": "Apex-level domains (e.g. example.com but not www.example.com) that we observe for the first time, and have not observed previously with our global DNS sensor network."
        }
    },
    "message": "{\"timestamp\":\"2025-01-30T20:14:48Z\",\"domain\":\"tractorpoweredcoreaerator.com\"}",
    "event": {
        "agent_id_status": "verified",
        "ingested": "2025-01-30T20:15:26Z",
        "kind": "enrichment",
        "category": [
            "threat"
        ],
        "type": [
            "indicator"
        ],
        "dataset": "ti_domaintools.nad_feed"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| domaintools.domain | The Domain. Apex-level domains (e.g. example.com but not www.example.com) that we observe for the first time, and have not observed previously with our global DNS sensor network. | keyword |
| domaintools.feed | The feed. | constant_keyword |
| domaintools.timestamp | Timestamp when the domain was added to the DomainTools feed, in ISO 8601 UTC form. | date |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| message | The feed. | match_only_text |
| threat.feed.description | Display the feed description. | constant_keyword |
| threat.feed.name | Display friendly feed name. | constant_keyword |
| threat.feed.reference | Display the feed reference. | constant_keyword |
| threat.indicator.name | The display name indicator in an UI friendly format URL, IP address, email address, registry key, port number, hash value, or other relevant name can serve as the display name. | keyword |
| threat.indicator.type | Type of indicator as represented by Cyber Observable in STIX 2.0. | keyword |


### Domain Discovery Feed

The `domaindiscovery feed` data stream provides events from [DomainTools Domain Discovery Feed](https://www.domaintools.com/products/threat-intelligence-feeds/).
This data is collected via the [DomainTools Feeds API](https://docs.domaintools.com/feeds/realtime/).

#### Example

An example event for `domaindiscovery_feed` looks as following:

```json
{
    "input": {
        "type": "cel"
    },
    "agent": {
        "name": "docker-fleet-agent",
        "id": "da8d0a37-2d46-4788-96bd-e9ee19e332ec",
        "ephemeral_id": "d1cbe648-0a1d-48e8-a161-cd82403e623e",
        "type": "filebeat",
        "version": "8.15.3"
    },
    "@timestamp": "2025-01-30T20:15:25.396Z",
    "ecs": {
        "version": "8.11.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "logs",
        "dataset": "ti_domaintools.domaindiscovery_feed"
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "6.10.11-linuxkit",
            "codename": "focal",
            "name": "Ubuntu",
            "type": "linux",
            "family": "debian",
            "version": "20.04.6 LTS (Focal Fossa)",
            "platform": "ubuntu"
        },
        "containerized": false,
        "ip": [
            "172.19.0.10"
        ],
        "name": "docker-fleet-agent",
        "id": "cfae1e7244ae479b9b0968259c91b13a",
        "mac": [
            "02-42-AC-13-00-0A"
        ],
        "architecture": "aarch64"
    },
    "elastic_agent": {
        "id": "da8d0a37-2d46-4788-96bd-e9ee19e332ec",
        "version": "8.15.3",
        "snapshot": false
    },
    "domaintools": {
        "domain": "tractorpoweredcoreaerator.com",
        "timestamp": "2025-01-30T20:14:48Z",
        "feed": "domaindiscovery"
    },
    "threat": {
        "indicator": {
            "name": "tractorpoweredcoreaerator.com",
            "type": "domain-name"
        },
        "feed": {
            "reference": "https://docs.techdocs.ci.domaintools.cloud/feeds/realtime/userguide/",
            "name": "DomainTools domaindiscovery",
            "description": "New domains as they are either discovered in domain registration information, observed by our global sensor network, or reported by trusted third parties."
        }
    },
    "message": "{\"timestamp\":\"2025-01-30T20:14:48Z\",\"domain\":\"tractorpoweredcoreaerator.com\"}",
    "event": {
        "agent_id_status": "verified",
        "ingested": "2025-01-30T20:15:26Z",
        "kind": "enrichment",
        "category": [
            "threat"
        ],
        "type": [
            "indicator"
        ],
        "dataset": "ti_domaintools.domaindiscovery"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| domaintools.domain | The Domain. | keyword |
| domaintools.feed | The feed type. | constant_keyword |
| domaintools.timestamp | Timestamp when the domain was added to the DomainTools feed, in ISO 8601 UTC form. | date |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| message | The feed from DomainTools Feed API. | match_only_text |
| threat.feed.description | Display the feed description. | constant_keyword |
| threat.feed.name | Display friendly feed name. | constant_keyword |
| threat.feed.reference | Display the feed reference. | constant_keyword |
| threat.indicator.name | The display name indicator in an UI friendly format URL, IP address, email address, registry key, port number, hash value, or other relevant name can serve as the display name. | keyword |
| threat.indicator.type | Type of indicator as represented by Cyber Observable in STIX 2.0. | keyword |


### Domain RDAP Feed

The `domainrdap feed` data stream provides events from [DomainTools Domain RDAP](https://www.domaintools.com/products/threat-intelligence-feeds/).
This data is collected via the [DomainTools Feeds API](https://docs.domaintools.com/feeds/realtime/).

#### Example

An example event for `domainrdap_feed` looks as following:

```json
{
    "input": {
        "type": "cel"
    },
    "agent": {
        "name": "docker-fleet-agent",
        "id": "da8d0a37-2d46-4788-96bd-e9ee19e332ec",
        "ephemeral_id": "d1cbe648-0a1d-48e8-a161-cd82403e623e",
        "type": "filebeat",
        "version": "8.15.3"
    },
    "@timestamp": "2025-01-30T20:15:25.396Z",
    "ecs": {
        "version": "8.11.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "logs",
        "dataset": "ti_domaintools.domainrdap_feed"
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "6.10.11-linuxkit",
            "codename": "focal",
            "name": "Ubuntu",
            "type": "linux",
            "family": "debian",
            "version": "20.04.6 LTS (Focal Fossa)",
            "platform": "ubuntu"
        },
        "containerized": false,
        "ip": [
            "172.19.0.10"
        ],
        "name": "docker-fleet-agent",
        "id": "cfae1e7244ae479b9b0968259c91b13a",
        "mac": [
            "02-42-AC-13-00-0A"
        ],
        "architecture": "aarch64"
    },
    "elastic_agent": {
        "id": "da8d0a37-2d46-4788-96bd-e9ee19e332ec",
        "version": "8.15.3",
        "snapshot": false
    },
    "domaintools": {
        "domain": "unlockyourlifehere.com",
        "timestamp": "2025-06-12T20:34:31Z",
        "feed": "domainrdap",
        "first_request_timestamp": "2025-06-12T20:34:24Z",
        "requests_url": [
            "https://rdap.verisign.com/com/v1/domain/unlockyourlifehere.com"
        ],
        "parsed_record": {
            "parsed_fields": {
                "emails": [
                    "abuse@godaddy.com"
                ],
                "last_changed_date": "2025-05-20T02: 44: 33+00: 00",
                "registrar": {
                    "name": "GoDaddy.com, LLC",
                    "contacts": [
                        {
                            "name": "",
                            "phone": "tel:480-624-2505",
                            "email": "abuse@godaddy.com",
                            "roles": [
                                "abuse"
                            ]
                        }
                    ],
                    "iana_id": "146"
                },
                "handle": "2894681047_DOMAIN_COM-VRSN",
                "creation_date": "2024-06-28T11: 49: 19+00: 00",
                "expiration_date": "2025-06-28T11: 49: 19+00: 00",
                "email_domains": [
                    "godaddy.com"
                ],
                "contacts": []
            }
        }
    },
    "threat": {
        "indicator": {
            "name": "unlockyourlifehere.com",
            "type": "domain-name"
        },
        "feed": {
            "reference": "https://docs.techdocs.ci.domaintools.cloud/feeds/realtime/userguide/",
            "name": "DomainTools domain RDAP",
            "description": "Changes to global domain registration information, populated by the Registration Data Access Protocol (RDAP). Compliments the 5-Minute WHOIS Feed as registries and registrars switch from Whois to RDAP."
        }
    },
    "message": "{\"timestamp\":\"2025-06-12T20:34:31Z\",\"domain\":\"unlockyourlifehere.com\",\"raw_record\":{\"first_request_timestamp\":\"2025-06-12T20:34:24Z\",\"requests\":[{\"data\":\"{\\\"objectClassName\\\":\\\"domain\\\",\\\"handle\\\":\\\"2894681047_DOMAIN_COM-VRSN\\\",\\\"ldhName\\\":\\\"UNLOCKYOURLIFEHERE.COM\\\",\\\"links\\\":[{\\\"value\\\":\\\"https:\\\\/\\\\/rdap.verisign.com\\\\/com\\\\/v1\\\\/domain\\\\/UNLOCKYOURLIFEHERE.COM\\\",\\\"rel\\\":\\\"self\\\",\\\"href\\\":\\\"https:\\\\/\\\\/rdap.verisign.com\\\\/com\\\\/v1\\\\/domain\\\\/UNLOCKYOURLIFEHERE.COM\\\",\\\"type\\\":\\\"application\\\\/rdap+json\\\"},{\\\"value\\\":\\\"https:\\\\/\\\\/rdap.godaddy.com\\\\/v1\\\\/domain\\\\/UNLOCKYOURLIFEHERE.COM\\\",\\\"rel\\\":\\\"related\\\",\\\"href\\\":\\\"https:\\\\/\\\\/rdap.godaddy.com\\\\/v1\\\\/domain\\\\/UNLOCKYOURLIFEHERE.COM\\\",\\\"type\\\":\\\"application\\\\/rdap+json\\\"}],\\\"status\\\":[\\\"redemption period\\\"],\\\"entities\\\":[{\\\"objectClassName\\\":\\\"entity\\\",\\\"handle\\\":\\\"146\\\",\\\"roles\\\":[\\\"registrar\\\"],\\\"publicIds\\\":[{\\\"type\\\":\\\"IANA Registrar ID\\\",\\\"identifier\\\":\\\"146\\\"}],\\\"vcardArray\\\":[\\\"vcard\\\",[[\\\"version\\\",{},\\\"text\\\",\\\"4.0\\\"],[\\\"fn\\\",{},\\\"text\\\",\\\"GoDaddy.com, LLC\\\"]]],\\\"entities\\\":[{\\\"objectClassName\\\":\\\"entity\\\",\\\"roles\\\":[\\\"abuse\\\"],\\\"vcardArray\\\":[\\\"vcard\\\",[[\\\"version\\\",{},\\\"text\\\",\\\"4.0\\\"],[\\\"fn\\\",{},\\\"text\\\",\\\"\\\"],[\\\"tel\\\",{\\\"type\\\":\\\"voice\\\"},\\\"uri\\\",\\\"tel:480-624-2505\\\"],[\\\"email\\\",{},\\\"text\\\",\\\"abuse@godaddy.com\\\"]]]}]}],\\\"events\\\":[{\\\"eventAction\\\":\\\"registration\\\",\\\"eventDate\\\":\\\"2024-06-28T11:49:19Z\\\"},{\\\"eventAction\\\":\\\"expiration\\\",\\\"eventDate\\\":\\\"2025-06-28T11:49:19Z\\\"},{\\\"eventAction\\\":\\\"last changed\\\",\\\"eventDate\\\":\\\"2025-05-20T02:44:33Z\\\"},{\\\"eventAction\\\":\\\"last update of RDAP database\\\",\\\"eventDate\\\":\\\"2025-06-12T20:34:16Z\\\"}],\\\"secureDNS\\\":{\\\"delegationSigned\\\":false},\\\"rdapConformance\\\":[\\\"rdap_level_0\\\",\\\"icann_rdap_technical_implementation_guide_0\\\",\\\"icann_rdap_response_profile_0\\\"],\\\"notices\\\":[{\\\"title\\\":\\\"Terms of Use\\\",\\\"description\\\":[\\\"Service subject to Terms of Use.\\\"],\\\"links\\\":[{\\\"href\\\":\\\"https:\\\\/\\\\/www.verisign.com\\\\/domain-names\\\\/registration-data-access-protocol\\\\/terms-service\\\\/index.xhtml\\\",\\\"type\\\":\\\"text\\\\/html\\\"}]},{\\\"title\\\":\\\"Status Codes\\\",\\\"description\\\":[\\\"For more information on domain status codes, please visit https:\\\\/\\\\/icann.org\\\\/epp\\\"],\\\"links\\\":[{\\\"href\\\":\\\"https:\\\\/\\\\/icann.org\\\\/epp\\\",\\\"type\\\":\\\"text\\\\/html\\\"}]},{\\\"title\\\":\\\"RDDS Inaccuracy Complaint Form\\\",\\\"description\\\":[\\\"URL of the ICANN RDDS Inaccuracy Complaint Form: https:\\\\/\\\\/icann.org\\\\/wicf\\\"],\\\"links\\\":[{\\\"href\\\":\\\"https:\\\\/\\\\/icann.org\\\\/wicf\\\",\\\"type\\\":\\\"text\\\\/html\\\"}]}]}\",\"source_type\":\"registry\",\"timestamp\":\"2025-06-12T20:34:24Z\",\"url\":\"https://rdap.verisign.com/com/v1/domain/unlockyourlifehere.com\"}]},\"parsed_record\":{\"parsed_fields\":{\"conformance\":[\"rdap_level_0\",\"icann_rdap_technical_implementation_guide_0\",\"icann_rdap_response_profile_0\"],\"contacts\":[],\"creation_date\":\"2024-06-28T11: 49: 19+00: 00\",\"dnssec\":{\"signed\":false},\"domain\":\"UNLOCKYOURLIFEHERE.COM\",\"domain_statuses\":[\"redemption period\"],\"email_domains\":[\"godaddy.com\"],\"emails\":[\"abuse@godaddy.com\"],\"expiration_date\":\"2025-06-28T11: 49: 19+00: 00\",\"handle\":\"2894681047_DOMAIN_COM-VRSN\",\"last_changed_date\":\"2025-05-20T02: 44: 33+00: 00\",\"links\":[{\"href\":\"https://rdap.verisign.com/com/v1/domain/UNLOCKYOURLIFEHERE.COM\",\"rel\":\"self\"},{\"href\":\"https://rdap.godaddy.com/v1/domain/UNLOCKYOURLIFEHERE.COM\",\"rel\":\"related\"}],\"registrar\":{\"contacts\":[{\"email\":\"abuse@godaddy.com\",\"name\":\"\",\"phone\":\"tel:480-624-2505\",\"roles\":[\"abuse\"]}],\"iana_id\":\"146\",\"name\":\"GoDaddy.com, LLC\"},\"unclassified_emails\":[]},\"registrar_request_url\":null,\"registry_request_url\":\"https://rdap.verisign.com/com/v1/domain/unlockyourlifehere.com\"}}",
    "event": {
        "agent_id_status": "verified",
        "ingested": "2025-06-12T20:34:31Z",
        "kind": "enrichment",
        "category": [
            "threat"
        ],
        "type": [
            "indicator"
        ],
        "dataset": "ti_domaintools.domainrdap_feed"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| domaintools.domain | The Domain. | keyword |
| domaintools.feed | The feed type. | constant_keyword |
| domaintools.first_request_timestamp | The first request timestamp. | date |
| domaintools.parsed_record.parsed_fields.contacts.country |  | keyword |
| domaintools.parsed_record.parsed_fields.contacts.email |  | keyword |
| domaintools.parsed_record.parsed_fields.contacts.name |  | keyword |
| domaintools.parsed_record.parsed_fields.creation_date | The domain creation date. | keyword |
| domaintools.parsed_record.parsed_fields.email_domains | List of email domains. | keyword |
| domaintools.parsed_record.parsed_fields.emails | List of emails. | keyword |
| domaintools.parsed_record.parsed_fields.expiration_date | The domain expiraton date. | keyword |
| domaintools.parsed_record.parsed_fields.handle | The domain handle. | keyword |
| domaintools.parsed_record.parsed_fields.last_changed_date | The domain last changed date. | keyword |
| domaintools.parsed_record.parsed_fields.nameservers | The domain nameservers. | keyword |
| domaintools.parsed_record.parsed_fields.registrar.contacts.email |  | keyword |
| domaintools.parsed_record.parsed_fields.registrar.contacts.name |  | keyword |
| domaintools.parsed_record.parsed_fields.registrar.contacts.phone |  | keyword |
| domaintools.parsed_record.parsed_fields.registrar.contacts.roles |  | keyword |
| domaintools.parsed_record.parsed_fields.registrar.iana_id |  | keyword |
| domaintools.parsed_record.parsed_fields.registrar.name | The registrar name. | keyword |
| domaintools.requests_url | List of extracted rdap request urls used. | keyword |
| domaintools.timestamp | Timestamp when the domain was added to the DomainTools feed, in ISO 8601 UTC form. | date |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| message | The feed from DomainTools Feed API. | match_only_text |
| threat.feed.description | Display the feed description. | constant_keyword |
| threat.feed.name | Display friendly feed name. | constant_keyword |
| threat.feed.reference | Display the feed reference. | constant_keyword |
| threat.indicator.name | The display name indicator in an UI friendly format URL, IP address, email address, registry key, port number, hash value, or other relevant name can serve as the display name. | keyword |
| threat.indicator.type | Type of indicator as represented by Cyber Observable in STIX 2.0. | keyword |

