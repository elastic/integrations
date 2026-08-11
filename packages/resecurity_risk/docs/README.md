# Resecurity RISK Integration for Elastic

## Overview

[Resecurity RISK](https://www.resecurity.com/) is a threat intelligence platform that monitors alerts, indicators of compromise, leaked-credential data breaches, and dark web activity relevant to an organization.

The Resecurity RISK integration for Elastic collects that intelligence from the Resecurity RISK REST API and lets you search, correlate, and visualize it in Kibana alongside the rest of your security data.

### Compatibility

This integration is compatible with the Resecurity RISK REST API as exposed by both the RISK (`https://risk.resecurity.com/api`) and the app (`https://app.resecurity.com/api`) products.

### How it works

The integration periodically polls the Resecurity RISK REST API using the Common Expression Language (CEL) input. Each data stream requests one endpoint, walks the paginated result set, and publishes each record as a document. Documents are keyed by the record's own identifier, so re-collecting a record updates the existing document rather than creating a duplicate.

## What data does this integration collect?

The integration collects the following types of records:

- `Alert`: Threat intelligence alerts, including subject, content, category, confidence and risk scores, TLP status, associated threat actors, geography, and any embedded IOC or TTP detail (endpoint: `GET /alert/index`).
- `IOC`: Indicators of compromise, including malware name, file hashes, detection ratio, and analysis dates (endpoint: `GET /ioc/index`).
- `IOC Lookup`: Watchlist enrichment for a configured list of MD5/SHA-256 hashes (endpoint: `GET /ioc/search-by-hash`).
- `Breach`: Individual leaked-credential records and their breach source metadata (endpoint: `GET /breaches/index`).
- `Dark Web`: Dark web and underground forum posts matching a search term (endpoint: `GET /dark-web/index`).

### Supported use cases

Bringing Resecurity RISK intelligence into Elastic lets analysts investigate external threat data in the same place as their internal telemetry.

**Alert** and **Dark Web** data support monitoring and triage of externally observed threats against your brand, domains, and executives. Alerts carry vendor risk and confidence scoring plus threat actor attribution, and dark web posts add the underlying forum, channel, and marketplace context.

**IOC** and **IOC Lookup** data support detection and enrichment workflows. The `ioc` data stream brings the full indicator feed into Elastic for correlation against host and network telemetry, while `ioc_lookup` answers the reverse question for a specific watchlist of hashes, recording both hits and misses so the absence of a match is itself observable.

**Breach** data supports credential exposure monitoring. Records are keyed to a search term such as a company domain, so teams can track which accounts appear in which breach sources, along with the attack vector, compromised data categories, and severity score reported for each source.

## What do I need to use this integration?

### From Elastic

Elastic Agent must be installed on a host that can reach the Resecurity RISK API. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

### From Resecurity

You need a Resecurity RISK API key. The API authenticates with an `Authorization: Basic` header containing only the base64-encoded API key; there is no password component.

1. Log in to your Resecurity portal.
2. Retrieve the API key issued for your account.
3. Confirm which base URL your product uses: `https://risk.resecurity.com/api` or `https://app.resecurity.com/api`.

The Breach and Dark Web endpoints do not support listing all records. Both require a search phrase, for example a company domain, brand name, or email address to monitor. To monitor several terms, add one instance of the data stream per term.

## How do I deploy this integration?

### Onboard and configure

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **Resecurity RISK**.
3. Select the **Resecurity RISK** integration from the search results.
4. Select **Add Resecurity RISK** to add the integration.
5. Configure the **Resecurity API base URL** and the **API key**.
6. Enable only the data streams you intend to collect, and configure each one:
    - **Resecurity Alert**: optionally set a search query to restrict alerts by subject or content.
    - **Resecurity IOC**: no additional configuration is required.
    - **Resecurity IOC Lookup**: disabled by default. Enable it and provide the list of MD5/SHA-256 hashes to monitor.
    - **Resecurity Breach**: set the required search query.
    - **Resecurity Dark Web**: set the required search query.
7. Adjust the **Collection Interval** and **Max Pages per Poll** for each data stream if required.
8. Select **Save and continue** to save the integration.

### Validation

1. In the top search bar in Kibana, search for **Discover**.
2. Select the `logs-*` data view.
3. Filter on `data_stream.dataset` for the data streams you enabled, for example `resecurity_risk.alert`, and verify that documents are arriving.

## Troubleshooting

If a request to the Resecurity RISK API fails, the failure is recorded in `error.message` on a document in the corresponding data stream, and the ingest pipeline stops processing that document. Search for `error.message: *` in the data stream to find collection failures, and check the API key and base URL configured for the integration.

The Breach and Dark Web data streams return nothing without a search query; confirm one is configured for each instance.

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Performance and scaling

None of the Resecurity RISK list endpoints used by this integration expose a "since timestamp" filter, so every poll re-walks pages from the start rather than fetching only new records. To bound the work done per poll, each list data stream has a **Max Pages per Poll** setting, which defaults to 10.

Document IDs are derived from the source record's own identifier, so re-ingesting the same record on a later poll overwrites the existing document rather than creating a duplicate. If your feed produces more genuinely new records per interval than `max_pages_per_poll * 100` (the API's default page size), increase **Max Pages per Poll** or shorten the **Collection Interval** to keep up.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Alert

The `alert` data stream provides threat intelligence alerts from Resecurity RISK.

#### alert fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.code | Error code describing the error. | keyword |
| error.id | Unique identifier for the error. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.risk_score | Risk score or priority of the event (e.g. security solutions). Use your system's original value here. | float |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| resecurity_risk.alert.category.id | Alert category ID. | long |
| resecurity_risk.alert.category.name | Alert category name, e.g. "Threat Actor". | keyword |
| resecurity_risk.alert.confidence_score | Confidence score: 0=Low, 1=Moderate, 2=High. | long |
| resecurity_risk.alert.content | Alert body content (may contain HTML markup). | text |
| resecurity_risk.alert.for_splunk.email | Email addresses associated with the alert (for_splunk field group). | keyword |
| resecurity_risk.alert.for_splunk.ip | IP addresses associated with the alert (for_splunk field group). | ip |
| resecurity_risk.alert.geography | Country codes the alert is related to. | keyword |
| resecurity_risk.alert.id | Resecurity's internal alert ID. | long |
| resecurity_risk.alert.ioc | Embedded indicator of compromise object, if the alert references one. See the IOC data stream for the equivalent standalone schema. | flattened |
| resecurity_risk.alert.risk_score | Risk score assigned to the alert by Resecurity. | long |
| resecurity_risk.alert.subject | Alert subject line. | keyword |
| resecurity_risk.alert.tags | Vendor-supplied tags for the alert. | keyword |
| resecurity_risk.alert.threat_actors | Names of threat actors associated with the alert. | keyword |
| resecurity_risk.alert.tlp_status | Traffic Light Protocol status (Green, Yellow, or Red). | keyword |
| resecurity_risk.alert.ttp | Embedded CAPEC-style tactics/techniques/procedures object(s), if present. Schema is vendor-defined and varies per entry. | flattened |
| resecurity_risk.alert.updated_at | Timestamp the alert was last updated. | date |
| tags | List of keywords used to tag each event. | keyword |


An example event for `alert` looks as following:

```json
{
    "@timestamp": "2017-09-30T16:52:45.000Z",
    "ecs": {
        "version": "9.4.0"
    },
    "event": {
        "category": [
            "threat"
        ],
        "dataset": "resecurity_risk.alert",
        "kind": "enrichment",
        "risk_score": 33,
        "type": [
            "indicator"
        ]
    },
    "related": {
        "hash": [
            "84c82835a5d21bbcf75a61706d8ab549",
            "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
        ],
        "ip": [
            "192.0.2.10"
        ]
    },
    "resecurity_risk": {
        "alert": {
            "category": {
                "id": 15,
                "name": "Threat Actor"
            },
            "confidence_score": 1,
            "content": "<p>There was identified underground shop in TOR network, selling compromised credit cards.</p>",
            "for_splunk": {
                "email": [
                    "user@example.com"
                ],
                "ip": [
                    "192.0.2.10"
                ]
            },
            "geography": [
                "al",
                "dz"
            ],
            "id": 123,
            "ioc": {
                "actor_name": "Actor11",
                "id": 6811735,
                "malware_name": "Trojan-Ransom.Win32.Wanna.b",
                "md5": "84c82835a5d21bbcf75a61706d8ab549",
                "sha256": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
            },
            "risk_score": 33,
            "subject": "Jocker/Stash Underground Shop (~300 CNB Credit Cards)",
            "tags": [
                "tag1",
                "tag2",
                "tag3"
            ],
            "threat_actors": [
                "Actor1",
                "Actor2"
            ],
            "tlp_status": "Red",
            "ttp": [
                {
                    "category": "Exploit",
                    "cve_code": "CVE-2004-0942",
                    "id": 345,
                    "name": "Apache - Arbitrary Long HTTP Headers Denial of Service"
                }
            ],
            "updated_at": "2017-09-30T16:52:45.000Z"
        }
    },
    "tags": [
        "tag1",
        "tag2",
        "tag3"
    ]
}
```

### IOC

The `ioc` data stream provides indicators of compromise from Resecurity RISK.

#### ioc fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.code | Error code describing the error. | keyword |
| error.id | Unique identifier for the error. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.hash.md5 | MD5 hash. | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| resecurity_risk.ioc.actor_name | Threat actor associated with the IOC. | keyword |
| resecurity_risk.ioc.add_date | Timestamp the IOC was added. | date |
| resecurity_risk.ioc.analysis_date | Timestamp the IOC was analyzed. | date |
| resecurity_risk.ioc.detection_ratio | Antivirus detection ratio, e.g. "52 / 58". | keyword |
| resecurity_risk.ioc.file_name | File name observed. | keyword |
| resecurity_risk.ioc.file_type | File type observed, e.g. "Win32 EXE". | keyword |
| resecurity_risk.ioc.id | Resecurity's internal IOC ID. | long |
| resecurity_risk.ioc.item_url | Link to the IOC record on the Resecurity portal. | keyword |
| resecurity_risk.ioc.malware_name | Malware family/name. | keyword |
| resecurity_risk.ioc.md5 | MD5 hash of the observed file. | keyword |
| resecurity_risk.ioc.sha256 | SHA-256 hash of the observed file. | keyword |
| resecurity_risk.ioc.update_date | Timestamp the IOC was last updated. | date |
| tags | List of keywords used to tag each event. | keyword |


An example event for `ioc` looks as following:

```json
{
    "@timestamp": "2017-05-22T09:06:50.000Z",
    "ecs": {
        "version": "9.4.0"
    },
    "event": {
        "category": [
            "threat"
        ],
        "dataset": "resecurity_risk.ioc",
        "kind": "enrichment",
        "type": [
            "indicator"
        ]
    },
    "file": {
        "hash": {
            "md5": "84c82835a5d21bbcf75a61706d8ab549",
            "sha256": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
        },
        "name": "WannaCry.infected"
    },
    "related": {
        "hash": [
            "84c82835a5d21bbcf75a61706d8ab549",
            "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
        ]
    },
    "resecurity_risk": {
        "ioc": {
            "actor_name": "Actor11",
            "add_date": "2017-05-22T08:42:34.000Z",
            "analysis_date": "2017-05-22T08:54:27.000Z",
            "detection_ratio": "52 / 58",
            "file_name": "WannaCry.infected",
            "file_type": "Win32 EXE",
            "id": 6811735,
            "item_url": "https://app.resecurity.com/ioc?IocSearch[id]=6811735",
            "malware_name": "Trojan-Ransom.Win32.Wanna.b",
            "md5": "84c82835a5d21bbcf75a61706d8ab549",
            "sha256": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
            "update_date": "2017-05-22T09:06:50.000Z"
        }
    }
}
```

### IOC Lookup

The `ioc_lookup` data stream provides the result of looking up each configured hash against Resecurity RISK. A match ingests the full IOC record with `resecurity_risk.ioc.found: true`; a miss ingests a compact record with `resecurity_risk.ioc.found: false`.

#### ioc_lookup fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.code | Error code describing the error. | keyword |
| error.id | Unique identifier for the error. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.hash.md5 | MD5 hash. | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| resecurity_risk.ioc.actor_name | Threat actor associated with the IOC. | keyword |
| resecurity_risk.ioc.add_date | Timestamp the IOC was added. | date |
| resecurity_risk.ioc.analysis_date | Timestamp the IOC was analyzed. | date |
| resecurity_risk.ioc.detection_ratio | Antivirus detection ratio, e.g. "52 / 58". | keyword |
| resecurity_risk.ioc.file_name | File name observed. | keyword |
| resecurity_risk.ioc.file_type | File type observed, e.g. "Win32 EXE". | keyword |
| resecurity_risk.ioc.found | Whether the hash was found in the Resecurity IOC database. | boolean |
| resecurity_risk.ioc.hash_query | The MD5/SHA256 hash that was looked up. | keyword |
| resecurity_risk.ioc.id | Resecurity's internal IOC ID. | long |
| resecurity_risk.ioc.item_url | Link to the IOC record on the Resecurity portal. | keyword |
| resecurity_risk.ioc.malware_name | Malware family/name. | keyword |
| resecurity_risk.ioc.md5 | MD5 hash of the observed file. | keyword |
| resecurity_risk.ioc.sha256 | SHA-256 hash of the observed file. | keyword |
| resecurity_risk.ioc.update_date | Timestamp the IOC was last updated. | date |
| tags | List of keywords used to tag each event. | keyword |


An example event for `ioc_lookup` looks as following:

```json
{
    "@timestamp": "2017-05-22T09:06:50.000Z",
    "ecs": {
        "version": "9.4.0"
    },
    "event": {
        "category": [
            "threat"
        ],
        "dataset": "resecurity_risk.ioc_lookup",
        "kind": "enrichment",
        "type": [
            "indicator"
        ]
    },
    "file": {
        "hash": {
            "md5": "84c82835a5d21bbcf75a61706d8ab549",
            "sha256": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
        },
        "name": "WannaCry.infected"
    },
    "related": {
        "hash": [
            "84c82835a5d21bbcf75a61706d8ab549",
            "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
        ]
    },
    "resecurity_risk": {
        "ioc": {
            "actor_name": "Actor11",
            "add_date": "2017-05-22T08:42:34.000Z",
            "analysis_date": "2017-05-22T08:54:27.000Z",
            "detection_ratio": "52 / 58",
            "file_name": "WannaCry.infected",
            "file_type": "Win32 EXE",
            "found": true,
            "hash_query": "84c82835a5d21bbcf75a61706d8ab549",
            "id": 6811735,
            "item_url": "https://app.resecurity.com/ioc?IocSearch[id]=6811735",
            "malware_name": "Trojan-Ransom.Win32.Wanna.b",
            "md5": "84c82835a5d21bbcf75a61706d8ab549",
            "sha256": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
            "update_date": "2017-05-22T09:06:50.000Z"
        }
    }
}
```

### Breach

The `breach` data stream provides leaked-credential records and their breach source metadata from Resecurity RISK.

#### breach fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.code | Error code describing the error. | keyword |
| error.id | Unique identifier for the error. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| resecurity_risk.breach.email | Leaked email address. | keyword |
| resecurity_risk.breach.id | Resecurity's internal breach record ID. | long |
| resecurity_risk.breach.info | Additional source-specific fields. Schema varies per breach source (vendor-defined). | flattened |
| resecurity_risk.breach.ip | IP address associated with the leaked record, if available. | ip |
| resecurity_risk.breach.password | Leaked plaintext password, if available. Sensitive — restrict access to this field's index accordingly. | keyword |
| resecurity_risk.breach.password_hash | Leaked password hash, if available. | keyword |
| resecurity_risk.breach.salt | Password salt, if available. | keyword |
| resecurity_risk.breach.source.accounts | Total number of accounts in the breach source. | long |
| resecurity_risk.breach.source.actor_name | Threat actor associated with the breach source. | keyword |
| resecurity_risk.breach.source.add_date | Timestamp the breach source was added. | date |
| resecurity_risk.breach.source.attack_vector | Attack vector used to obtain the breach, if known. | keyword |
| resecurity_risk.breach.source.category | Breach source category, e.g. "Blog". | keyword |
| resecurity_risk.breach.source.collect_date | Timestamp the breach source was collected. | date |
| resecurity_risk.breach.source.compromised_data | Categories of compromised data, e.g. "Bank account numbers". | keyword |
| resecurity_risk.breach.source.description | Breach source description. | text |
| resecurity_risk.breach.source.geography | Countries associated with the breach source. | keyword |
| resecurity_risk.breach.source.id | Breach source ID (duplicate of source_id, as returned by the API). | long |
| resecurity_risk.breach.source.is_imported | Whether the breach source has been fully imported. | boolean |
| resecurity_risk.breach.source.meta | Additional free-text metadata tags for the breach source. | keyword |
| resecurity_risk.breach.source.name | Breach source name. | keyword |
| resecurity_risk.breach.source.score | Breach source severity score (0-100). | long |
| resecurity_risk.breach.source.ttp | Exploit/technique detail associated with the breach source (author, platform, port, etc). Schema is vendor-defined. | flattened |
| resecurity_risk.breach.source.url | URL where the breach source was found. | keyword |
| resecurity_risk.breach.source_id | ID of the breach source. | long |
| resecurity_risk.breach.username | Leaked username. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.email | User email address. | keyword |


An example event for `breach` looks as following:

```json
{
    "@timestamp": "2016-08-04T06:40:00.000Z",
    "ecs": {
        "version": "9.4.0"
    },
    "event": {
        "category": [
            "threat"
        ],
        "dataset": "resecurity_risk.breach",
        "kind": "enrichment",
        "type": [
            "indicator"
        ]
    },
    "related": {
        "ip": [
            "192.0.2.10"
        ]
    },
    "resecurity_risk": {
        "breach": {
            "email": "jdoe@example.com",
            "id": 7323,
            "info": {
                "extra_field": "extra value"
            },
            "ip": "192.0.2.10",
            "password": "REDACTED-SAMPLE-PASSWORD",
            "password_hash": "00000000000000000000000000000000:AAA",
            "salt": "",
            "source": {
                "accounts": 9499,
                "actor_name": "hello",
                "add_date": "2016-10-31T10:15:10.000Z",
                "attack_vector": "something",
                "category": "Blog",
                "collect_date": "2016-08-04T06:40:00.000Z",
                "compromised_data": [
                    "Bank account numbers",
                    "Banking PINs"
                ],
                "description": "test",
                "geography": [
                    "International",
                    "Afghanistan",
                    "Albania"
                ],
                "id": 7,
                "is_imported": false,
                "meta": [
                    "Contains financial data"
                ],
                "name": "example_breach_source",
                "score": 100,
                "ttp": [
                    {
                        "author": "I)ruid",
                        "date": "1094850000",
                        "description": "CDRecord's ReadCD - '$RSH' exec() SUID Shell Creation",
                        "file": "platforms/linux/local/438.c",
                        "id": 438,
                        "platform": "linux",
                        "port": 0,
                        "type": "local"
                    }
                ],
                "url": "http://example-url.com"
            },
            "source_id": 7,
            "username": "jdoe"
        }
    },
    "user": {
        "email": "jdoe@example.com"
    }
}
```

### Dark Web

The `dark_web` data stream provides dark web and underground forum posts from Resecurity RISK.

#### dark_web fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.code | Error code describing the error. | keyword |
| error.id | Unique identifier for the error. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| resecurity_risk.dark_web.actor | Name of the actor who posted. | keyword |
| resecurity_risk.dark_web.category | Category name for the post. | keyword |
| resecurity_risk.dark_web.country | Two-letter country code (ISO 3166-1) associated with the post. | keyword |
| resecurity_risk.dark_web.id | Resecurity's internal post ID. | long |
| resecurity_risk.dark_web.language | Two-letter language code (ISO 639-1) of the post. | keyword |
| resecurity_risk.dark_web.post | Full post body text. | text |
| resecurity_risk.dark_web.resource_name | Name of the resource (forum/site/channel) the post came from. | keyword |
| resecurity_risk.dark_web.snippet | Short snippet/excerpt of the post. | text |
| resecurity_risk.dark_web.source | Source type, e.g. "Dark Web", "Telegram", "Twitter". | keyword |
| resecurity_risk.dark_web.timestamp | Timestamp the post was made. | date |
| resecurity_risk.dark_web.title | Post title. | keyword |
| resecurity_risk.dark_web.url | URL of the post, if available. | keyword |
| tags | List of keywords used to tag each event. | keyword |


An example event for `dark_web` looks as following:

```json
{
    "@timestamp": "2017-01-25T07:57:02.000Z",
    "ecs": {
        "version": "9.4.0"
    },
    "event": {
        "category": [
            "threat"
        ],
        "dataset": "resecurity_risk.dark_web",
        "kind": "enrichment",
        "type": [
            "indicator"
        ]
    },
    "resecurity_risk": {
        "dark_web": {
            "actor": "Voodo",
            "category": "Malware",
            "country": "us",
            "id": 499907679,
            "language": "us",
            "post": "Some text. We believe above sellers are engaging in fraudulent",
            "resource_name": "example.com",
            "snippet": "sometext, <b>test</b> buy cn zh 2017-10-24",
            "source": "Dark Web",
            "timestamp": "2017-01-25T07:57:02.000Z",
            "title": "Test code",
            "url": "http://example.com/post123"
        }
    }
}
```

### Inputs used

These inputs can be used with this integration:
<details>
<summary>cel</summary>

## Setup

For more details about the CEL input settings, check the [Filebeat documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-cel.html).

Before configuring the CEL input, make sure you have:
- Network connectivity to the target API endpoint
- Valid authentication credentials (API keys, tokens, or certificates as required)
- Appropriate permissions to read from the target data source

### Collecting logs from CEL

To configure the CEL input, you must specify the `request.url` value pointing to the API endpoint. The interval parameter controls how frequently requests are made and is the primary way to balance data freshness with API rate limits and costs. Authentication is often configured through the `request.headers` section using the appropriate method for the service.

NOTE: To access the API service, make sure you have the necessary API credentials and that the Filebeat instance can reach the endpoint URL. Some services may require IP whitelisting or VPN access.

To collect logs via API endpoint, configure the following parameters:

- API Endpoint URL
- API credentials (tokens, keys, or username/password)
- Request interval (how often to fetch data)
</details>


### API usage

These APIs are used with this integration:

* Alert (endpoint: `GET /alert/index`)
* IOC (endpoint: `GET /ioc/index`)
* IOC Lookup (endpoint: `GET /ioc/search-by-hash`)
* Breach (endpoint: `GET /breaches/index`)
* Dark Web (endpoint: `GET /dark-web/index`)
