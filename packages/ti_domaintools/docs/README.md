# DomainTools Real Time Unified Feeds

The DomainTools Real Time Unified Feeds integration allows you to monitor DomainTools Newly Observed Domains. 
The DomainTools NOD Feed provides real-time access to newly registered and observed domains, enabling proactive threat detection and defense. 

With over 300,000 new domains observed daily, the feed empowers security teams to identify and block potentially malicious domains before they can be weaponized. 
Ideal for threat hunting, phishing prevention, and brand protection, the NOD Feed delivers unparalleled visibility into emerging domain activity to stay ahead of evolving threats.

For example, if you wanted to monitor Newly Observed Domains (NOD) feed, you could ingest the DomainTools NOD feed. 
Then you can reference domaintools.nod_feed when using visualizations or alerts.

## Data streams

The DomainTools Real Time Unified Feeds integration collects one type of data streams: logs

Log data streams collected by the DomainTools integration include the Newly Observed Domains (NOD) feed: Apex-level domains (e.g. Example Domain  but not www.example.com) that we observe for the first time, and have not observed previously. 
Populated with our global DNS sensor network.

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
This data is collected via the [DomainTools Real Time Feeds API](https://docs.domaintools.com/feeds/realtime/).

#### Example

An example event for `nod_feed` looks as following:

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
        "dataset": "ti_domaintools.nod_feed"
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
        "ingested": "2025-01-30T20:15:26Z",
        "kind": "enrichment",
        "category": [
            "threat"
        ],
        "type": [
            "indicator"
        ],
        "dataset": "ti_domaintools.nod_feed"
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
| domaintools.domain | The Domain. Apex-level domains (e.g. example.com but not www.example.com) that we observe for the first time, and have not observed previously with our global DNS sensor network. | keyword |
| domaintools.feed | The feed. | keyword |
| domaintools.timestamp | Timestamp when the domain was added to the DomainTools feed, in ISO 8601 UTC form. | date |
| input.type | Type of filebeat input. | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| message | The feed. | keyword |


