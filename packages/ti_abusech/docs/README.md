# abuse.ch Integration for Elastic

## Overview

The abuse.ch integration for Elastic enables collection of logs from [abuse.ch](https://abuse.ch/). This integration facilitates the ingestion of threat intelligence indicators to be used for threat detection and event enrichment.

### Compatibility
This integration is compatible with `v1` version of URLhaus, MalwareBazaar, and ThreatFox APIs.

### How it works

This integration periodically queries the abuse.ch APIs to retrieve threat intelligence indicators.

## What data does this integration collect?

This integration collects threat intelligence indicators into the following datasets:

- `ja3_fingerprints`: Collects JA3 fingerprint based threat indicators identified by SSLBL via [SSLBL API endpoint](https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv).
- `malware`: Collects malware payloads from URLs tracked by URLhaus via [URLhaus Bulk API](https://urlhaus-api.abuse.ch/#payloads-recent).
- `malwarebazaar`: Collects malware payloads from MalwareBazaar via [MalwareBazaar API](https://bazaar.abuse.ch/api/#latest_additions).
- `sslblacklist`: Collects SSL certificate based threat indicators blacklisted on SSLBL via [SSLBL API endpoint](https://sslbl.abuse.ch/blacklist/sslblacklist.csv).
- `threatfox`: Collects threat indicators from ThreatFox via [ThreatFox API](https://threatfox.abuse.ch/api/#recent-iocs).
- `url`: Collects malware URL based threat indicators from URLhaus via [URLhaus API](https://urlhaus.abuse.ch/api/#csv).

### Supported use cases

The abuse.ch integration brings threat intel into Elastic Security, enabling detection alerts when indicators of compromise (IoCs) like malicious [IPs](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/threat_intel/threat_intel_indicator_match_address), [domains](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/threat_intel/threat_intel_indicator_match_url), or [hashes](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/threat_intel/threat_intel_indicator_match_hash) match your event or alert data. This data can also support threat hunting, enrich alerts with threat context, and power dashboards to track known threats in your environment.

## What do I need to use this integration?

### From Elastic

#### Transform

As this integration installs [Elastic latest transforms](https://www.elastic.co/docs/explore-analyze/transforms/transform-overview#latest-transform-overview), the requirements of transform must be met. For more details, check the [Transform Setup](https://www.elastic.co/docs/explore-analyze/transforms/transform-setup)

### From abuse.ch

abuse.ch requires using an `Auth Key` (API Key) in the requests for authentication. Requests without authentication will be denied by the abuse.ch APIs.

#### Obtain `Auth Key`

1. Sign up for new account or login into [abuse.ch authentication portal](https://auth.abuse.ch).
2. Connect with atleast one authentication provider, namely Google, Github, X, or LinkedIn.
3. Select **Save profile**.
4. In the **Optional** section, click on **Generate Key** button to generate **Auth Key**.
5. Copy the generated **Auth Key**.

For more details, check the abuse.ch [Community First - New Authentication](https://abuse.ch/blog/community-first/) blog.

## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

#### Agentless-based installation

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

#### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

### Onboard / configure

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **abuse.ch**.
3. Select the **abuse.ch** integration from the search results.
4. Select **Add abuse.ch** to add the integration.
5. Enable and configure only the collection methods which you will use.

    * To **Collect abuse.ch logs via API**, you'll need to:

        - Configure **Auth Key**.
        - Enable/Disable the required datasets.
        - For each dataset, adjust the integration configuration parameters if required, including the URL, Interval, etc. to enable data collection.

6. Select **Save and continue** to save the integration.

### Validation

#### Dashboards populated

1. In Kibana, navigate to **Dashboards**.
2. In the search bar, type **abuse.ch**.
3. Select a dashboard for the dataset you are collecting, and verify the dashboard information is populated.

#### Transforms healthy

1. In Kibana, navigate to **Management** > **Stack Management**.
2. Under **Data**, select **Transforms**.
3. In the search bar, type **abuse.ch**.
4. All transforms from the search results should indicate **Healthy** under the **Health** column.

## Troubleshooting

- When creating the **Auth Key** inside [abuse.ch authentication portal](https://auth.abuse.ch/), ensure that you connect at least one additional authentication provider to ensure seemless access to abuse.ch platform.
- Check for captured ingestion errors inside Kibana. Any ingestion errors, including API errors, are captured into `error.message` field.
    1. Navigate to **Analytics** > **Discover**.
    2. In **Search field names**, search and add fields `error.message` and `data_stream.dataset` into the **Discover** view. For more details on adding fields inside **Discover**, check [Discover getting started](https://www.elastic.co/docs/explore-analyze/discover/discover-get-started).
    3. Search for the dataset(s) that are enabled by this integration. For example, in the KQL query bar, use the KQL query `data_stream.dataset: ti_abusech.url` to search on specific dataset or KQL query `data_stream.dataset: ti_abusech.*` to search on all datasets.
    4. Search for presence of any errors that are captured into `error.message` field using KQL query `error.message: *`. You can combine queries using [KQL boolean expressions](https://www.elastic.co/docs/explore-analyze/query-filter/languages/kql#_combining_multiple_queries), such as `AND`. For example, to search for any errors inside `url` dataset, you can use KQL query: `data_stream.dataset: ti_abusech.url AND error.message: *`.
- Since this integration supports Expiration of Indicators of Compromise (IOCs) using Elastic latest transform, the threat indicators are present in both source and destination indices. While this seem like duplicate ingestion, it is an implmentation detail which is required to properly expire threat indicators.
- Because the latest copy of threat indicators is now indexed in two places, that is, in both source and destination indices, users must anticipate storage requirements accordingly. The ILM policies on source indices can be tuned to manage their data retention period. For more details, check the [Reference](#ilm-policy).
- For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### ECS field reference

#### JA3 Fingerprint Blacklist

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| abusech.ja3_fingerprints.deleted_at | The timestamp when the indicator is (will be) deleted. | date |
| abusech.ja3_fingerprints.urlhaus_reference | Link to URLhaus entry. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| labels.interval | User-configured value for `Interval` setting. This is used in calculation of indicator expiration time. | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| threat.feed.dashboard_id | Dashboard ID used for Kibana CTI UI | constant_keyword |
| threat.feed.name | Display friendly feed name | constant_keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |


#### Malware

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| abusech.malware.deleted_at | The indicator expiration timestamp. | date |
| abusech.malware.ioc_expiration_duration | The configured expiration duration. | keyword |
| abusech.malware.signature | Malware family. | keyword |
| abusech.malware.virustotal.link | Link to the Virustotal report. | keyword |
| abusech.malware.virustotal.percent | AV detection in percent. | float |
| abusech.malware.virustotal.result | AV detection ratio. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| threat.feed.dashboard_id | Dashboard ID used for Kibana CTI UI | constant_keyword |
| threat.feed.name | Display friendly feed name | constant_keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |


#### MalwareBazaar

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| abusech.malwarebazaar.anonymous | Identifies if the sample was submitted anonymously. | long |
| abusech.malwarebazaar.code_sign.algorithm | Algorithm used to generate the public key. | keyword |
| abusech.malwarebazaar.code_sign.cscb_listed | Whether the certificate is present on the Code Signing Certificate Blocklist (CSCB). | boolean |
| abusech.malwarebazaar.code_sign.cscb_reason | Why the certificate is present on the Code Signing Certificate Blocklist (CSCB). | keyword |
| abusech.malwarebazaar.code_sign.issuer_cn | Common name (CN) of issuing certificate authority. | keyword |
| abusech.malwarebazaar.code_sign.serial_number | Unique serial number issued by the certificate authority. | keyword |
| abusech.malwarebazaar.code_sign.subject_cn | Common name (CN) of subject. | keyword |
| abusech.malwarebazaar.code_sign.thumbprint | Hash of certificate. | keyword |
| abusech.malwarebazaar.code_sign.thumbprint_algorithm | Algorithm used to create thumbprint. | keyword |
| abusech.malwarebazaar.code_sign.valid_from | Time at which the certificate is first considered valid. | date |
| abusech.malwarebazaar.code_sign.valid_to | Time at which the certificate is no longer considered valid. | keyword |
| abusech.malwarebazaar.deleted_at | The indicator expiration timestamp. | date |
| abusech.malwarebazaar.dhash_icon | In case the file is a PE executable: dhash of the samples icon. | keyword |
| abusech.malwarebazaar.intelligence.downloads | Number of downloads from MalwareBazaar. | long |
| abusech.malwarebazaar.intelligence.mail.Generic | Malware seen in generic spam traffic. | keyword |
| abusech.malwarebazaar.intelligence.mail.IT | Malware seen in IT spam traffic. | keyword |
| abusech.malwarebazaar.intelligence.uploads | Number of uploads from MalwareBazaar. | long |
| abusech.malwarebazaar.ioc_expiration_duration | The configured expiration duration. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| threat.feed.dashboard_id | Dashboard ID used for Kibana CTI UI | constant_keyword |
| threat.feed.name | Display friendly feed name | constant_keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |


#### SSL Certificate Blacklist

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| abusech.sslblacklist.deleted_at | The timestamp when the indicator is (will be) deleted. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| labels.interval | User-configured value for `Interval` setting. This is used in calculation of indicator expiration time. | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| threat.feed.dashboard_id | Dashboard ID used for Kibana CTI UI | constant_keyword |
| threat.feed.name | Display friendly feed name | constant_keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |


#### ThreatFox

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| abusech.threatfox.confidence_level | Confidence level between 0-100. | long |
| abusech.threatfox.deleted_at | The indicator expiration timestamp. | date |
| abusech.threatfox.ioc_expiration_duration | The configured expiration duration. | keyword |
| abusech.threatfox.malware | The malware associated with the IOC. | keyword |
| abusech.threatfox.tags | A list of tags associated with the queried malware sample. | keyword |
| abusech.threatfox.threat_type | The type of threat. | keyword |
| abusech.threatfox.threat_type_desc | The threat descsription. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| threat.feed.dashboard_id | Dashboard ID used for Kibana CTI UI | constant_keyword |
| threat.feed.name | Display friendly feed name | constant_keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |


#### URL

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| abusech.url.blacklists.spamhaus_dbl | If the indicator is listed on the spamhaus blacklist. | keyword |
| abusech.url.blacklists.surbl | If the indicator is listed on the surbl blacklist. | keyword |
| abusech.url.deleted_at | The timestamp when the indicator is (will be) deleted. | date |
| abusech.url.id | The ID of the indicator. | keyword |
| abusech.url.larted | Indicates whether the malware URL has been reported to the hosting provider (true or false). | boolean |
| abusech.url.last_online | Last timestamp when the URL has been serving malware. | date |
| abusech.url.reporter | The Twitter handle of the reporter that has reported this malware URL (or anonymous). | keyword |
| abusech.url.tags | A list of tags associated with the queried malware URL. | keyword |
| abusech.url.threat | The threat corresponding to this malware URL. | keyword |
| abusech.url.url_status | The current status of the URL. Possible values are: online, offline and unknown. | keyword |
| abusech.url.urlhaus_reference | Link to URLhaus entry. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| labels.interval | User-configured value for `Interval` setting. This is used in calculation of indicator expiration time. | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| threat.feed.dashboard_id | Dashboard ID used for Kibana CTI UI | constant_keyword |
| threat.feed.name | Display friendly feed name | constant_keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |


### Example event

#### JA3 Fingerprint Blacklist

An example event for `ja3_fingerprints` looks as following:

```json
{
    "@timestamp": "2025-07-31T05:12:01.523Z",
    "abusech": {
        "ja3_fingerprints": {
            "deleted_at": "2025-07-31T06:10:34.470Z"
        }
    },
    "agent": {
        "ephemeral_id": "9a4132fc-38d5-43ec-a459-0ef108d28187",
        "id": "28fe4213-ba33-434e-8815-6bbc80c646d0",
        "name": "elastic-agent-82406",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "ti_abusech.ja3_fingerprints",
        "namespace": "86925",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "28fe4213-ba33-434e-8815-6bbc80c646d0",
        "snapshot": false,
        "version": "8.19.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_abusech.ja3_fingerprints",
        "ingested": "2025-07-31T05:12:04Z",
        "kind": "enrichment",
        "original": "{\"first_ts\":\"2017-07-14T18:08:15Z\",\"ja3\":\"b386946a5a44d1ddcc843bc75336dfce\",\"last_ts\":\"2019-07-27T20:42:54Z\",\"reason\":\"Dridex\"}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "cel"
    },
    "labels": {
        "interval": "1h"
    },
    "related": {
        "hash": [
            "b386946a5a44d1ddcc843bc75336dfce"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "abusech-ja3_fingerprints"
    ],
    "threat": {
        "indicator": {
            "description": "Dridex",
            "first_seen": "2017-07-14T18:08:15.000Z",
            "last_seen": "2019-07-27T20:42:54.000Z",
            "name": "b386946a5a44d1ddcc843bc75336dfce",
            "type": "software"
        }
    }
}
```

#### Malware

An example event for `malware` looks as following:

```json
{
    "@timestamp": "2025-07-16T06:30:10.517Z",
    "abusech": {
        "malware": {
            "deleted_at": "2021-10-10T04:17:02.000Z",
            "ioc_expiration_duration": "5d"
        }
    },
    "agent": {
        "ephemeral_id": "c478eac0-6769-456a-8a26-d5d6cc86318d",
        "id": "5d0ab6a2-0351-4c94-8bfb-e268dee367e4",
        "name": "elastic-agent-40763",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "ti_abusech.malware",
        "namespace": "70630",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "5d0ab6a2-0351-4c94-8bfb-e268dee367e4",
        "snapshot": true,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_abusech.malware",
        "ingested": "2025-07-16T06:30:13Z",
        "kind": "enrichment",
        "original": "{\"file_size\":\"1563\",\"file_type\":\"unknown\",\"firstseen\":\"2021-10-05 04:17:02\",\"imphash\":null,\"md5_hash\":\"9cd5a4f0231a47823c4adba7c8ef370f\",\"sha256_hash\":\"7c0852d514df7faf8fdbfa4f358cc235dd1b1a2d843cc65495d03b502e4099f2\",\"signature\":null,\"ssdeep\":\"48:yazkS7neW+mfe4CJjNXcq5Co4Fr1PpsHn:yrmGNt5mbP2n\",\"tlsh\":\"T109314C5E7822CA70B91AD69300C22D8C2F53EAF229E6686C3BDD4C86FA1344208CF1\",\"urlhaus_download\":\"https://urlhaus-api.abuse.ch/v1/download/7c0852d514df7faf8fdbfa4f358cc235dd1b1a2d843cc65495d03b502e4099f2/\",\"virustotal\":null}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "hash": [
            "9cd5a4f0231a47823c4adba7c8ef370f",
            "7c0852d514df7faf8fdbfa4f358cc235dd1b1a2d843cc65495d03b502e4099f2",
            "48:yazkS7neW+mfe4CJjNXcq5Co4Fr1PpsHn:yrmGNt5mbP2n",
            "T109314C5E7822CA70B91AD69300C22D8C2F53EAF229E6686C3BDD4C86FA1344208CF1"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "abusech-malware"
    ],
    "threat": {
        "indicator": {
            "confidence": "Not Specified",
            "file": {
                "hash": {
                    "md5": "9cd5a4f0231a47823c4adba7c8ef370f",
                    "sha256": "7c0852d514df7faf8fdbfa4f358cc235dd1b1a2d843cc65495d03b502e4099f2",
                    "ssdeep": "48:yazkS7neW+mfe4CJjNXcq5Co4Fr1PpsHn:yrmGNt5mbP2n",
                    "tlsh": "T109314C5E7822CA70B91AD69300C22D8C2F53EAF229E6686C3BDD4C86FA1344208CF1"
                },
                "size": 1563,
                "type": "unknown"
            },
            "first_seen": "2021-10-05T04:17:02.000Z",
            "name": "7c0852d514df7faf8fdbfa4f358cc235dd1b1a2d843cc65495d03b502e4099f2",
            "type": "file"
        }
    }
}
```

#### MalwareBazaar

An example event for `malwarebazaar` looks as following:

```json
{
    "@timestamp": "2025-07-16T06:30:59.281Z",
    "abusech": {
        "malwarebazaar": {
            "anonymous": 0,
            "deleted_at": "2021-10-10T14:02:45.000Z",
            "intelligence": {
                "downloads": 11,
                "uploads": 1
            },
            "ioc_expiration_duration": "5d"
        }
    },
    "agent": {
        "ephemeral_id": "f5b70b3f-5d2b-4d55-96b0-dc8e46e10b9a",
        "id": "372b884d-d232-4e1e-806c-d08ae525f868",
        "name": "elastic-agent-37187",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "ti_abusech.malwarebazaar",
        "namespace": "64456",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "372b884d-d232-4e1e-806c-d08ae525f868",
        "snapshot": true,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_abusech.malwarebazaar",
        "ingested": "2025-07-16T06:31:02Z",
        "kind": "enrichment",
        "original": "{\"anonymous\":0,\"code_sign\":[],\"dhash_icon\":null,\"file_name\":\"7a6c03013a2f2ab8b9e8e7e5d226ea89e75da72c1519e.exe\",\"file_size\":432640,\"file_type\":\"exe\",\"file_type_mime\":\"application/x-dosexec\",\"first_seen\":\"2021-10-05 14:02:45\",\"imphash\":\"f34d5f2d4577ed6d9ceec516c1f5a744\",\"intelligence\":{\"clamav\":null,\"downloads\":\"11\",\"mail\":null,\"uploads\":\"1\"},\"last_seen\":null,\"md5_hash\":\"1fc1c2997c8f55ac10496b88e23f5320\",\"origin_country\":\"FR\",\"reporter\":\"abuse_ch\",\"sha1_hash\":\"42c7153680d7402e56fe022d1024aab49a9901a0\",\"sha256_hash\":\"7a6c03013a2f2ab8b9e8e7e5d226ea89e75da72c1519e78fd28b2253ea755c28\",\"sha3_384_hash\":\"d63e73b68973bc73ab559549aeee2141a48b8a3724aabc0d81fb14603c163a098a5a10be9f6d33b888602906c0d89955\",\"signature\":\"RedLineStealer\",\"ssdeep\":\"12288:jhhl1Eo+iEXvpb1C7drqAd1uUaJvzXGyO2F5V3bS1jsTacr:7lL\",\"tags\":[\"exe\",\"RedLineStealer\"],\"telfhash\":null,\"tlsh\":\"T13794242864BFC05994E3EEA12DDCA8FBD99A55E3640C743301B4633B8B52B84DE4F479\"}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "hash": [
            "42c7153680d7402e56fe022d1024aab49a9901a0",
            "d63e73b68973bc73ab559549aeee2141a48b8a3724aabc0d81fb14603c163a098a5a10be9f6d33b888602906c0d89955",
            "7a6c03013a2f2ab8b9e8e7e5d226ea89e75da72c1519e78fd28b2253ea755c28",
            "T13794242864BFC05994E3EEA12DDCA8FBD99A55E3640C743301B4633B8B52B84DE4F479",
            "12288:jhhl1Eo+iEXvpb1C7drqAd1uUaJvzXGyO2F5V3bS1jsTacr:7lL",
            "1fc1c2997c8f55ac10496b88e23f5320",
            "f34d5f2d4577ed6d9ceec516c1f5a744"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "abusech-malwarebazaar",
        "exe",
        "RedLineStealer"
    ],
    "threat": {
        "indicator": {
            "file": {
                "extension": "exe",
                "hash": {
                    "md5": "1fc1c2997c8f55ac10496b88e23f5320",
                    "sha1": "42c7153680d7402e56fe022d1024aab49a9901a0",
                    "sha256": "7a6c03013a2f2ab8b9e8e7e5d226ea89e75da72c1519e78fd28b2253ea755c28",
                    "sha384": "d63e73b68973bc73ab559549aeee2141a48b8a3724aabc0d81fb14603c163a098a5a10be9f6d33b888602906c0d89955",
                    "ssdeep": "12288:jhhl1Eo+iEXvpb1C7drqAd1uUaJvzXGyO2F5V3bS1jsTacr:7lL",
                    "tlsh": "T13794242864BFC05994E3EEA12DDCA8FBD99A55E3640C743301B4633B8B52B84DE4F479"
                },
                "mime_type": "application/x-dosexec",
                "name": "7a6c03013a2f2ab8b9e8e7e5d226ea89e75da72c1519e.exe",
                "pe": {
                    "imphash": "f34d5f2d4577ed6d9ceec516c1f5a744"
                },
                "size": 432640
            },
            "first_seen": "2021-10-05T14:02:45.000Z",
            "geo": {
                "country_iso_code": "FR"
            },
            "marking": {
                "tlp": "CLEAR"
            },
            "name": "7a6c03013a2f2ab8b9e8e7e5d226ea89e75da72c1519e78fd28b2253ea755c28",
            "provider": "abuse_ch",
            "type": "file"
        },
        "software": {
            "alias": [
                "RedLineStealer"
            ]
        }
    }
}
```

#### SSL Certificate Blacklist

An example event for `sslblacklist` looks as following:

```json
{
    "@timestamp": "2025-07-31T05:15:00.672Z",
    "abusech": {
        "sslblacklist": {
            "deleted_at": "2025-07-31T06:13:33.669Z"
        }
    },
    "agent": {
        "ephemeral_id": "80e31fdd-70e8-4156-9a0d-ad6d0d853888",
        "id": "01f51d20-e150-4b4e-a036-1746eb0c7285",
        "name": "elastic-agent-47845",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "ti_abusech.sslblacklist",
        "namespace": "19255",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "01f51d20-e150-4b4e-a036-1746eb0c7285",
        "snapshot": false,
        "version": "8.19.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_abusech.sslblacklist",
        "ingested": "2025-07-31T05:15:03Z",
        "kind": "enrichment",
        "original": "{\"reason\":\"HijackLoader C\\u0026C\",\"sha1\":\"029c128ec7f6c5a62ea19f5ad525cd1487971ce4\",\"ts\":\"2025-06-25T06:50:28Z\"}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "cel"
    },
    "labels": {
        "interval": "1h"
    },
    "related": {
        "hash": [
            "029c128ec7f6c5a62ea19f5ad525cd1487971ce4"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "abusech-sslblacklist"
    ],
    "threat": {
        "indicator": {
            "description": "HijackLoader C&C",
            "first_seen": "2025-06-25T06:50:28.000Z",
            "name": "029c128ec7f6c5a62ea19f5ad525cd1487971ce4",
            "type": "x509-certificate"
        }
    }
}
```

#### ThreatFox

An example event for `threatfox` looks as following:

```json
{
    "@timestamp": "2025-07-16T06:31:50.732Z",
    "abusech": {
        "threatfox": {
            "confidence_level": 100,
            "deleted_at": "2022-08-10T19:43:08.000Z",
            "ioc_expiration_duration": "5d",
            "malware": "win.asyncrat",
            "threat_type": "botnet_cc",
            "threat_type_desc": "Indicator that identifies a botnet command&control server (C&C)"
        }
    },
    "agent": {
        "ephemeral_id": "49a54718-d50a-45cf-8da6-597e14572d1b",
        "id": "07477042-3fd0-44e5-83e1-d33c53a1b34d",
        "name": "elastic-agent-57963",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "ti_abusech.threatfox",
        "namespace": "90202",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "07477042-3fd0-44e5-83e1-d33c53a1b34d",
        "snapshot": true,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_abusech.threatfox",
        "id": "841537",
        "ingested": "2025-07-16T06:31:53Z",
        "kind": "enrichment",
        "original": "{\"confidence_level\":100,\"first_seen\":\"2022-08-05 19:43:08 UTC\",\"id\":\"841537\",\"ioc\":\"wizzy.hopto.org\",\"ioc_type\":\"domain\",\"ioc_type_desc\":\"Domain that is used for botnet Command\\u0026control (C\\u0026C)\",\"last_seen\":null,\"malware\":\"win.asyncrat\",\"malware_alias\":null,\"malware_malpedia\":\"https://malpedia.caad.fkie.fraunhofer.de/details/win.asyncrat\",\"malware_printable\":\"AsyncRAT\",\"reference\":\"https://tria.ge/220805-w57pxsgae2\",\"reporter\":\"AndreGironda\",\"tags\":[\"asyncrat\"],\"threat_type\":\"botnet_cc\",\"threat_type_desc\":\"Indicator that identifies a botnet command\\u0026control server (C\\u0026C)\"}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "cel"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "abusech-threatfox",
        "asyncrat"
    ],
    "threat": {
        "indicator": {
            "confidence": "High",
            "description": "Domain that is used for botnet Command&control (C&C)",
            "first_seen": "2022-08-05T19:43:08.000Z",
            "marking": {
                "tlp": "WHITE"
            },
            "name": "wizzy.hopto.org",
            "provider": "AndreGironda",
            "reference": "https://tria.ge/220805-w57pxsgae2",
            "type": "domain-name",
            "url": {
                "domain": "wizzy.hopto.org"
            }
        },
        "software": {
            "name": "AsyncRAT",
            "reference": "https://malpedia.caad.fkie.fraunhofer.de/details/win.asyncrat"
        }
    }
}
```

#### URL

An example event for `url` looks as following:

```json
{
    "@timestamp": "2025-07-16T06:32:41.644Z",
    "abusech": {
        "url": {
            "deleted_at": "2025-07-16T07:31:14.625Z",
            "id": "2786904",
            "threat": "malware_download",
            "url_status": "online"
        }
    },
    "agent": {
        "ephemeral_id": "8039c627-ea96-4027-8751-2ff7db77251b",
        "id": "9106f11b-d54d-46d0-8ace-39e4fff1157b",
        "name": "elastic-agent-41888",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "ti_abusech.url",
        "namespace": "49664",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "9106f11b-d54d-46d0-8ace-39e4fff1157b",
        "snapshot": true,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_abusech.url",
        "ingested": "2025-07-16T06:32:44Z",
        "kind": "enrichment",
        "original": "{\"dateadded\":\"2024-03-19 11:34:09 UTC\",\"id\":\"2786904\",\"last_online\":\"2024-03-19 11:34:09 UTC\",\"reporter\":\"lrz_urlhaus\",\"tags\":[\"elf\",\"Mozi\"],\"threat\":\"malware_download\",\"url\":\"http://115.55.244.160:41619/Mozi.m\",\"url_status\":\"online\",\"urlhaus_link\":\"https://urlhaus.abuse.ch/url/2786904/\"}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "cel"
    },
    "labels": {
        "interval": "1h"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "abusech-url",
        "elf",
        "Mozi"
    ],
    "threat": {
        "indicator": {
            "first_seen": "2024-03-19T11:34:09.000Z",
            "last_seen": "2024-03-19T11:34:09.000Z",
            "name": "http://115.55.244.160:41619/Mozi.m",
            "provider": "lrz_urlhaus",
            "reference": "https://urlhaus.abuse.ch/url/2786904/",
            "type": "url",
            "url": {
                "domain": "115.55.244.160",
                "extension": "m",
                "full": "http://115.55.244.160:41619/Mozi.m",
                "original": "http://115.55.244.160:41619/Mozi.m",
                "path": "/Mozi.m",
                "port": 41619,
                "scheme": "http"
            }
        }
    }
}
```

### Inputs used

These inputs can be used in this integration:

- [cel](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

This integration datasets uses the following APIs:

- `ja3_fingerprints`: [SSLBL API](https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv).
- `malware`: [URLhaus Bulk API](https://urlhaus-api.abuse.ch/#payloads-recent).
- `malwarebazaar`: [MalwareBazaar API](https://bazaar.abuse.ch/api/#latest_additions).
- `sslblacklist`: [SSLBL API](https://sslbl.abuse.ch/blacklist/sslblacklist.csv).
- `threatfox`: [ThreatFox API](https://threatfox.abuse.ch/api/#recent-iocs).
- `url`: [URLhaus API](https://urlhaus.abuse.ch/api/#csv).

### Expiration of Indicators of Compromise (IOCs)

All abuse.ch datasets now support indicator expiration. For the `URL` dataset, a full list of active threat indicators are ingested every interval. For other datasets namely `Malware`, `MalwareBazaar`, and `ThreatFox`, the threat indicators are expired after duration `IOC Expiration Duration` configured in the integration setting. An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created for every source index to facilitate only active threat indicators be available to the end users. Each transform creates a destination index named `logs-ti_abusech_latest.dest_*` which only contains active and unexpired threat indicators. The indicator match rules and dashboards are updated to list only active threat indicators.
Destinations indices are aliased to `logs-ti_abusech_latest.<data_stream_name>`.

| Source Data stream                  | Destination Index Pattern                        | Destination Alias                       |
|:-----------------------------------|:-------------------------------------------------|-----------------------------------------|
| `logs-ti_abusech.url-*`            | `logs-ti_abusech_latest.dest_url-*`              | `logs-ti_abusech_latest.url`            |
| `logs-ti_abusech.malware-*`        | `logs-ti_abusech_latest.dest_malware-*`          | `logs-ti_abusech_latest.malware`        |
| `logs-ti_abusech.malwarebazaar-*`  | `logs-ti_abusech_latest.dest_malwarebazaar-*`    | `logs-ti_abusech_latest.malwarebazaar`  |
| `logs-ti_abusech.threatfox-*`      | `logs-ti_abusech_latest.dest_threatfox-*`        | `logs-ti_abusech_latest.threatfox`      |

#### ILM Policy

To facilitate IOC expiration, source data stream-backed indices `.ds-logs-ti_abusech.<data_stream_name>-*` are allowed to contain duplicates from each polling interval. ILM policy `logs-ti_abusech.<data_stream_name>-default_policy` is added to these source indices so it doesn't lead to unbounded growth. This means data in these source indices will be deleted after `5 days` from ingested date.
