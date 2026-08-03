# Resecurity RISK

The Resecurity RISK integration collects Threat Intelligence from the
[Resecurity RISK](https://www.resecurity.com/) REST API. It ships 5 Data Streams:

| Data stream | Source Endpoint | Search Term |
|---|---|---|
| Alert | `GET /alert/index` | optional |
| IOC | `GET /ioc/index` | not supported |
| IOC Lookup | `GET /ioc/search-by-hash` | hash list (**required**) |
| Breach | `GET /breaches/index` | **required** |
| Dark Web | `GET /dark-web/index` | **required** |

## Requirements

You need a Resecurity RISK API key. Resecurity's API Authenticates with an `Authorization: Basic`
Header containing only the **base64-encoded API key**.
Enter your key in the "API key" field of the Integration Policy; make sure you have the corrected URL selected based on your purchased product (in can either be "risk" or "app").

## Breach and Dark Web require a Search Term

Unlike Alert and IOC, the Breach and Dark Web Endpoints do NOT support listing all records. The
upstream API requires a search Phrase (for example a Company Domain, Brand Name, or Email
Address to monitor). Configure this in the "Search Query" field when adding the Breach or Dark
Web Data Stream. To monitor multiple terms, add multiple instances of the Data Stream, one per
term.

## Known Limitation: no incremental collection

None of the 4 Resecurity RISK list endpoints used by this integration expose a "since timestamp"
filter. Every poll re-walks pages from the start rather than fetching only New Records. To bound
the work done per poll, each list data stream has a `max_pages_per_poll` setting (default 10). Document
IDs are derived from the source record's own `id` field, so re-ingesting the same record on a
later poll Overwrites the existing document rather than creating a Duplicate — but if your feed
has more genuinely New Records per interval than `max_pages_per_poll * 100` (the API's default
page size), increase `max_pages_per_poll` or shorten `interval` to keep up.

## Data Streams

### Alert

Threat Intelligence Alerts — subject, content, category, confidence/risk scores, TLP status,
associated threat actors, geography, and any embedded IOC or TTP detail.

An example event for `alert` looks as following:

```json
{
    "@timestamp": "2017-09-30T16:52:45.000Z",
    "ecs": {
        "version": "8.11.0"
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
    "resecurity": {
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
            ]
        }
    },
    "tags": [
        "tag1",
        "tag2",
        "tag3"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.code | Error code describing the error. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.risk_score | Risk score or priority of the event (e.g. security solutions). Use your system's original value here. | float |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| resecurity.alert.category.id | Alert category ID. | long |
| resecurity.alert.category.name | Alert category name, e.g. "Threat Actor". | keyword |
| resecurity.alert.confidence_score | Confidence score: 0=Low, 1=Moderate, 2=High. | long |
| resecurity.alert.content | Alert body content (may contain HTML markup). | text |
| resecurity.alert.for_splunk.email | Email addresses associated with the alert (for_splunk field group). | keyword |
| resecurity.alert.geography | Country codes the alert is related to. | keyword |
| resecurity.alert.id | Resecurity's internal alert ID. | long |
| resecurity.alert.ioc | Embedded indicator of compromise object, if the alert references one. See the IOC data stream for the equivalent standalone schema. | flattened |
| resecurity.alert.subject | Alert subject line. | keyword |
| resecurity.alert.tags | Vendor-supplied tags for the alert. | keyword |
| resecurity.alert.threat_actors | Names of threat actors associated with the alert. | keyword |
| resecurity.alert.tlp_status | Traffic Light Protocol status (Green, Yellow, or Red). | keyword |
| resecurity.alert.ttp | Embedded CAPEC-style tactics/techniques/procedures object(s), if present. Schema is vendor-defined and varies per entry. | flattened |
| tags | List of keywords used to tag each event. | keyword |


### IOC

Indicators of Compromise — malware name, file hashes (MD5/SHA-256), detection ratio, and dates.

An example event for `ioc` looks as following:

```json
{
    "@timestamp": "2017-05-22T09:06:50.000Z",
    "ecs": {
        "version": "8.11.0"
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
    "resecurity": {
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
            "update_date": "2017-05-22T09:06:50.000Z"
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.code | Error code describing the error. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.hash.md5 | MD5 hash. | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| resecurity.ioc.actor_name | Threat actor associated with the IOC. | keyword |
| resecurity.ioc.add_date | Timestamp the IOC was added. | date |
| resecurity.ioc.analysis_date | Timestamp the IOC was analyzed. | date |
| resecurity.ioc.detection_ratio | Antivirus detection ratio, e.g. "52 / 58". | keyword |
| resecurity.ioc.file_name | File name observed. | keyword |
| resecurity.ioc.file_type | File type observed, e.g. "Win32 EXE". | keyword |
| resecurity.ioc.id | Resecurity's internal IOC ID. | long |
| resecurity.ioc.item_url | Link to the IOC record on the Resecurity portal. | keyword |
| resecurity.ioc.malware_name | Malware family/name. | keyword |
| resecurity.ioc.update_date | Timestamp the IOC was last updated. | date |


### IOC Lookup

Watchlist Enrichment: give the stream a list of MD5/SHA-256 hashes and each poll looks every hash up via `GET /ioc/search-by-hash`. A match Ingests the full IOC record with `resecurity.ioc.found: true`; a miss Ingests a compact record with `resecurity.ioc.found: false`.
Documents are keyed by the queried hash, so repeated polls update the same document instead of creating duplicates. The stream is disabled by default — enable it and provide hashes when you have a watchlist to monitor.

An example event for `ioc_lookup` looks as following:

```json
{
    "@timestamp": "2017-05-22T09:06:50.000Z",
    "ecs": {
        "version": "8.11.0"
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
    "resecurity": {
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
            "update_date": "2017-05-22T09:06:50.000Z"
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.code | Error code describing the error. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.hash.md5 | MD5 hash. | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| resecurity.ioc.actor_name | Threat actor associated with the IOC. | keyword |
| resecurity.ioc.add_date | Timestamp the IOC was added. | date |
| resecurity.ioc.analysis_date | Timestamp the IOC was analyzed. | date |
| resecurity.ioc.detection_ratio | Antivirus detection ratio, e.g. "52 / 58". | keyword |
| resecurity.ioc.file_name | File name observed. | keyword |
| resecurity.ioc.file_type | File type observed, e.g. "Win32 EXE". | keyword |
| resecurity.ioc.found | Whether the hash was found in the Resecurity IOC database. | boolean |
| resecurity.ioc.hash_query | The MD5/SHA256 hash that was looked up. | keyword |
| resecurity.ioc.id | Resecurity's internal IOC ID. | long |
| resecurity.ioc.item_url | Link to the IOC record on the Resecurity portal. | keyword |
| resecurity.ioc.malware_name | Malware family/name. | keyword |
| resecurity.ioc.update_date | Timestamp the IOC was last updated. | date |


### Breach

Individual Leaked-Credential Records (email, username, password/password hash) plus the breach
source's metadata (name, category, attack vector, compromised data types, geography).

An example event for `breach` looks as following:

```json
{
    "@timestamp": "2016-08-04T06:40:00.000Z",
    "ecs": {
        "version": "8.11.0"
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
    "resecurity": {
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

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.code | Error code describing the error. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| resecurity.breach.email | Leaked email address. | keyword |
| resecurity.breach.id | Resecurity's internal breach record ID. | long |
| resecurity.breach.info | Additional source-specific fields. Schema varies per breach source (vendor-defined). | flattened |
| resecurity.breach.ip | IP address associated with the leaked record, if available. | ip |
| resecurity.breach.password | Leaked plaintext password, if available. Sensitive — restrict access to this field's index accordingly. | keyword |
| resecurity.breach.password_hash | Leaked password hash, if available. | keyword |
| resecurity.breach.salt | Password salt, if available. | keyword |
| resecurity.breach.source.accounts | Total number of accounts in the breach source. | long |
| resecurity.breach.source.actor_name | Threat actor associated with the breach source. | keyword |
| resecurity.breach.source.add_date | Timestamp the breach source was added. | date |
| resecurity.breach.source.attack_vector | Attack vector used to obtain the breach, if known. | keyword |
| resecurity.breach.source.category | Breach source category, e.g. "Blog". | keyword |
| resecurity.breach.source.collect_date | Timestamp the breach source was collected. | date |
| resecurity.breach.source.compromised_data | Categories of compromised data, e.g. "Bank account numbers". | keyword |
| resecurity.breach.source.description | Breach source description. | text |
| resecurity.breach.source.geography | Countries associated with the breach source. | keyword |
| resecurity.breach.source.id | Breach source ID (duplicate of source_id, as returned by the API). | long |
| resecurity.breach.source.is_imported | Whether the breach source has been fully imported. | boolean |
| resecurity.breach.source.meta | Additional free-text metadata tags for the breach source. | keyword |
| resecurity.breach.source.name | Breach source name. | keyword |
| resecurity.breach.source.score | Breach source severity score (0-100). | long |
| resecurity.breach.source.ttp | Exploit/technique detail associated with the breach source (author, platform, port, etc). Schema is vendor-defined. | flattened |
| resecurity.breach.source.url | URL where the breach source was found. | keyword |
| resecurity.breach.source_id | ID of the breach source. | long |
| resecurity.breach.username | Leaked username. | keyword |
| user.email | User email address. | keyword |


### Dark Web

Dark Web / underground-forum Posts matching your search term — actor, category, country,
language, title, snippet, and source URL.

An example event for `dark_web` looks as following:

```json
{
    "@timestamp": "2017-01-25T07:57:02.000Z",
    "ecs": {
        "version": "8.11.0"
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
    "resecurity": {
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
            "title": "Test code",
            "url": "http://example.com/post123"
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.code | Error code describing the error. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| resecurity.dark_web.actor | Name of the actor who posted. | keyword |
| resecurity.dark_web.category | Category name for the post. | keyword |
| resecurity.dark_web.country | Two-letter country code (ISO 3166-1) associated with the post. | keyword |
| resecurity.dark_web.id | Resecurity's internal post ID. | long |
| resecurity.dark_web.language | Two-letter language code (ISO 639-1) of the post. | keyword |
| resecurity.dark_web.post | Full post body text. | text |
| resecurity.dark_web.resource_name | Name of the resource (forum/site/channel) the post came from. | keyword |
| resecurity.dark_web.snippet | Short snippet/excerpt of the post. | text |
| resecurity.dark_web.source | Source type, e.g. "Dark Web", "Telegram", "Twitter". | keyword |
| resecurity.dark_web.title | Post title. | keyword |
| resecurity.dark_web.url | URL of the post, if available. | keyword |

