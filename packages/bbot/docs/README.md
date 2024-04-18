# BBOT integration

Please read this page in it's entirety as this integration requires some setup.

This integration is for [BBOT](https://www.blacklanternsecurity.com/bbot/), an Attack Surface Management (ASM) Open Source Inteligence (OSINT) Tool. BBOT itself stands for Bighuge BLS OSINT Tool (BBOT).

This integration requires the external use of BBOT! You will have to download and run the tool apart from this integration. Once your scan is complete, this integration will ingest the results into Elastic.

This tool is used to enhance your external knowledge of your environment. This is done through the integration of many tools into BBOT providing a overview of your attack surface. Here is [how it works](https://www.blacklanternsecurity.com/bbot/how_it_works/).

**Important Note** - You will have to provide the following parameter in your BBOT scan for your output.ndjson to be formatted correctly.
```
-c output_modules.json.siem_friendly=true
```
**Example BBOT Scan**
```
bbot -t elastic.co --strict-scope -f safe passive -c output_modules.json.siem_friendly=true -om json
```

You will have to configure the path for the output file within the integration settings. A common and popular path that could work here is:

**Example BBOT Path**
```
/home/*/.bbot/scans/*/output.ndjson
```

BBOT Scanning [Documentation](https://www.blacklanternsecurity.com/bbot/scanning/).

- `bbot` dataset: Made up of the findings found in the BBOT Scans.

## Logs

### ASM Findings

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
| bbot.data.asn.asn | autonomous system number | keyword |
| bbot.data.asn.country | asn country | keyword |
| bbot.data.asn.description | description of the asn | keyword |
| bbot.data.asn.name | name discovered for the asn | keyword |
| bbot.data.asn.subnet |  | keyword |
| bbot.data.azure_tenant.domains | domain of the azure tenant | keyword |
| bbot.data.azure_tenant.tenant-id | id of the azure tenant | keyword |
| bbot.data.azure_tenant.tenant-names | associated names of the azure tenants discovered | keyword |
| bbot.data.code_repository.url | url of the code repository | keyword |
| bbot.data.dns_name | dns name found | keyword |
| bbot.data.email_address | email address found | keyword |
| bbot.data.finding.description | description of the finding | keyword |
| bbot.data.finding.host | host finding was discovered on | keyword |
| bbot.data.finding.url | url finding was discovered on | keyword |
| bbot.data.open_tcp_port | open tcp port discovered | keyword |
| bbot.data.org_stub | the org stub | keyword |
| bbot.data.protocol.banner |  | keyword |
| bbot.data.protocol.host | host related to protocol | keyword |
| bbot.data.protocol.port | port of the protocol | integer |
| bbot.data.protocol.protocol | the protocol | keyword |
| bbot.data.scan | name of the scan | keyword |
| bbot.data.social.platform | social platform discovered | keyword |
| bbot.data.social.profile_name | social platform username | keyword |
| bbot.data.social.url | url of the social finding | keyword |
| bbot.data.storage_bucket.name | name of the storage bucket | keyword |
| bbot.data.storage_bucket.url | url of the storage bucket | keyword |
| bbot.data.technology.host | host where technology was discovered | keyword |
| bbot.data.technology.technology | technology that was discovered | keyword |
| bbot.data.technology.url | url of the discovered technology | keyword |
| bbot.data.url | url of the data finding | keyword |
| bbot.data.vulnerability.description | description of the vulnerabiltiy | keyword |
| bbot.data.vulnerability.host | host vulnerability was discovered on | keyword |
| bbot.data.vulnerability.url | url of the vulnerability | keyword |
| bbot.data.waf.host | host of the waf | keyword |
| bbot.data.waf.info | waf information | keyword |
| bbot.data.waf.url | url of the waf | keyword |
| bbot.data.waf.waf | waf data | keyword |
| bbot.data.webscreenshot.filename | name of the webscreenshot file | keyword |
| bbot.data.webscreenshot.url | url of the webscreenshot | keyword |
| bbot.id | unique id for each finding | keyword |
| bbot.module | module that discovered the finding | keyword |
| bbot.module_sequence | module sequence that discovered the finding | keyword |
| bbot.resolved_hosts | large list of hosts discovered per finding, this field can hold numerous values | keyword |
| bbot.scan | scan document, this finding is it's own document and contains data about the scan | keyword |
| bbot.scope_distance | scope distance of the scan. this is set at runtime of bbot | integer |
| bbot.source |  | keyword |
| bbot.tags |  | keyword |
| bbot.timestamp |  | date |
| bbot.type |  | keyword |
| bbot.web_spider_distance | how far the web spider crawled to discover the finding | integer |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
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

