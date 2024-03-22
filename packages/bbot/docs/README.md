# BBOT integration

This integration is for [BBOT](https://www.blacklanternsecurity.com/bbot/) an ASM (Attack Surface Management) OSINT (Open Source Inteligence) Tool. This integration takes the BLS (Black Lantern Security)'s BBOT tool and mapps the finding data to ECS(Elastic Common Schema).

BBOT itself stands for (Bighuge BLS OSINT Tool). This tool is used to enhance your external knowledge of your environment. This is done through the integration of many tools into BBOT providing a overview of your attack surface. Here is [how it works](https://www.blacklanternsecurity.com/bbot/how_it_works/)

**Important Note** - You will have to provide the following paramiter in your BBOT scan for your output.json to be formatted correctly
```
-c output_modules.json.siem_friendly=true
```
**Example BBOT Scan**
```
bbot -t elastic.co --strict-scope -f safe passive -c output_modules.json.siem_friendly=true -om json
```
BBOT Scanning [Documentation](https://www.blacklanternsecurity.com/bbot/scanning/)

- `bbot` dataset: Made up of the findings found in the BBOT Scans.

## Logs

### ASM Findings

This is related BBOT data pertinant for your Attack Surface Management. Specificaly the findings in the output.ndjson file are being pulled!

An example event for `asm_intel` looks as following:

```json
{
    "@timestamp": "2024-02-29T01:41:47.779Z",
    "agent": {
        "ephemeral_id": "9406cda5-43d3-4994-b1cd-4ca6e138cf4e",
        "id": "1d6e3c0c-c4ec-45f9-a9f1-cba233147f9a",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.2"
    },
    "bbot": {
        "data": {},
        "id": "DNS_NAME:f57ba0828becd7bf94faa616db081ed06f31bd3d",
        "module": "TARGET",
        "module_sequence": "TARGET",
        "scan": "SCAN:725368977d3a680e579707504e59428a7e3acc9d",
        "scope_distance": 0,
        "source": "SCAN:725368977d3a680e579707504e59428a7e3acc9d",
        "tags": [
            "resolved",
            "a-record",
            "target",
            "in-scope",
            "subdomain"
        ],
        "type": "DNS_NAME"
    },
    "data_stream": {
        "dataset": "bbot.asm_intel",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.12.0"
    },
    "elastic_agent": {
        "id": "1d6e3c0c-c4ec-45f9-a9f1-cba233147f9a",
        "snapshot": false,
        "version": "8.12.2"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "bbot.asm_intel",
        "ingested": "2024-03-21T18:48:38Z",
        "kind": "asset"
    },
    "host": {
        "name": "example.com"
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/log.log"
        },
        "offset": 398
    },
    "message": "{\"type\": \"DNS_NAME\", \"id\": \"DNS_NAME:f57ba0828becd7bf94faa616db081ed06f31bd3d\", \"data\": {\"DNS_NAME\": \"example.com\"}, \"scope_distance\": 0, \"scan\": \"SCAN:725368977d3a680e579707504e59428a7e3acc9d\", \"timestamp\": 1709170907.779394, \"resolved_hosts\": [\"123.123.123.123\"], \"source\": \"SCAN:725368977d3a680e579707504e59428a7e3acc9d\", \"tags\": [\"resolved\", \"a-record\", \"target\", \"in-scope\", \"subdomain\"], \"module\": \"TARGET\", \"module_sequence\": \"TARGET\"}",
    "related": {
        "hosts": [
            "123.123.123.123"
        ]
    },
    "tags": [
        "forwarded"
    ],
    "url": {
        "domain": [
            "example.com"
        ]
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| bbot.data.ASN.asn |  | keyword |
| bbot.data.ASN.country |  | keyword |
| bbot.data.ASN.description |  | keyword |
| bbot.data.ASN.name |  | keyword |
| bbot.data.ASN.subnet |  | keyword |
| bbot.data.AZURE_TENANT.domains |  | keyword |
| bbot.data.AZURE_TENANT.tenant-id |  | keyword |
| bbot.data.AZURE_TENANT.tenant-names |  | keyword |
| bbot.data.CODE_REPOSITORY.url |  | keyword |
| bbot.data.DNS_NAME |  | keyword |
| bbot.data.EMAIL_ADDRESS |  | keyword |
| bbot.data.FINDING.description |  | keyword |
| bbot.data.FINDING.host |  | keyword |
| bbot.data.FINDING.url |  | keyword |
| bbot.data.OPEN_TCP_PORT |  | keyword |
| bbot.data.ORG_STUB |  | keyword |
| bbot.data.PROTOCOL.banner |  | keyword |
| bbot.data.PROTOCOL.host |  | keyword |
| bbot.data.PROTOCOL.port |  | integer |
| bbot.data.PROTOCOL.protocol |  | keyword |
| bbot.data.SCAN |  | keyword |
| bbot.data.SOCIAL.platform |  | keyword |
| bbot.data.SOCIAL.profile_name |  | keyword |
| bbot.data.SOCIAL.url |  | keyword |
| bbot.data.STORAGE_BUCKET.name |  | keyword |
| bbot.data.STORAGE_BUCKET.url |  | keyword |
| bbot.data.TECHNOLOGY.host |  | keyword |
| bbot.data.TECHNOLOGY.technology |  | keyword |
| bbot.data.TECHNOLOGY.url |  | keyword |
| bbot.data.URL |  | keyword |
| bbot.data.VULNERABILITY.description |  | keyword |
| bbot.data.VULNERABILITY.host |  | keyword |
| bbot.data.VULNERABILITY.url |  | keyword |
| bbot.data.WAF.WAF |  | keyword |
| bbot.data.WAF.host |  | keyword |
| bbot.data.WAF.info |  | keyword |
| bbot.data.WAF.url |  | keyword |
| bbot.data.WEBSCREENSHOT.filename |  | keyword |
| bbot.data.WEBSCREENSHOT.url |  | keyword |
| bbot.id |  | keyword |
| bbot.module |  | keyword |
| bbot.module_sequence |  | keyword |
| bbot.resolved_hosts |  | keyword |
| bbot.scan |  | keyword |
| bbot.scope_distance |  | integer |
| bbot.source |  | keyword |
| bbot.tags |  | keyword |
| bbot.timestamp |  | date |
| bbot.type |  | keyword |
| bbot.web_spider_distance |  | integer |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| host.ip | Host ip addresses. | ip |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| tags | User defined tags. | keyword |
| url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | wildcard |
| url.full.text | Multi-field of `url.full`. | match_only_text |
| url.port | Port of the request, such as 443. | long |
| vulnerability.severity | The severity of the vulnerability can help with metrics and internal prioritization regarding remediation. For example (https://nvd.nist.gov/vuln-metrics/cvss) | keyword |

