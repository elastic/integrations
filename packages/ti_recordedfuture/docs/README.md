# Recorded Future Integration

The Recorded Future integration has three data streams:

* `threat`: Threat intelligence from the Recorded Future Connect
  API's [risklist endpoints](https://api.recordedfuture.com/v2/#!/Domain/Domain_Risk_Lists),
  or local CSV files of that data.
* `playbook_alert`: Playbook alerts data from Recorded
  Future's [API for Playbook Alerts](https://api.recordedfuture.com/playbook-alert).
* `triggered_alert`: Triggered alerts data from the Recorded Future Connect
  API's [alerts endpoint](https://api.recordedfuture.com/v2/#!/Alerts/Alert_Notification_Search).

For the `threat` data stream, you need to define the `entity` and `list` to
fetch. The supported entities are `domain`, `hash`, `ip`, and `url`. Check the
Recorded Future documentation for the available lists for each entity or use the
default. To fetch indicators from multiple entities, you need to create a
separate integration policy for each.

Alternatively, the `threat` data stream can fetch custom Fusion files by
supplying the URL to the CSV file as an advanced configuration option.

The `threat` data stream will check whether the available data has changed
before actually downloading it. A short interval setting will mean that it
checks frequently, but each version of the data will only be ingested once.

The alerts data allows for streamlined alert management and improved security
monitoring. By collecting both alert types, it provides deeper insights into
potential threats.

### Expiration of Indicators of Compromise (IOCs)

The ingested IOCs expire after a certain duration. An
[Elastic Transform][elasticsearch_transforms]
is created to facilitate making only active IOCs available to end users. This
transform creates a destination index named
`logs-ti_recordedfuture_latest.threat-3` which only contains active and
unexpired IOCs. The destination index also has an alias
`logs-ti_recordedfuture_latest.threat`. When setting up indicator match rules,
use this latest destination index to avoid false positives from expired IOCs.
Please refer to the [ILM Policy](#ilm-policy) section below for information on
how source indices are managed to prevent unbounded growth.

[elasticsearch_transforms]: https://www.elastic.co/docs/explore-analyze/transforms

### ILM Policy

To facilitate IOC expiration, source datastream-backed indices
`.ds-logs-ti_recordedfuture.threat-*` are allowed to contain duplicates from
each polling interval. An ILM policy is added to these source indices to prevent
unbounded growth. This means data in these source indices will be deleted after
`5 days` from the ingestion date.

**NOTE:** For large risklist downloads, adjust the timeout setting so that the
Agent has enough time to download and process the risklist.

## Agentless Enabled Integration

Agentless integrations allow you to collect data without having to manage
Elastic Agent in your cloud. They make manual agent deployment unnecessary, so
you can focus on your data instead of the agent that collects it. For more
information, refer to [Agentless integrations][agentless_integrations] and the
[Agentless integrations FAQ][agentless_faq].

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud
environments. This functionality is in beta and is subject to change. Beta
features are not subject to the support SLA of official GA features.

[agentless_integrations]: https://www.elastic.co/docs/solutions/security/get-started/agentless-integrations
[agentless_faq]: https://www.elastic.co/docs/troubleshoot/security/agentless-integrations

## Logs reference

### threat

This is the `threat` dataset.

#### Example

An example event for `threat` looks as following:

```json
{
    "@timestamp": "2025-06-11T14:51:44.624Z",
    "agent": {
        "ephemeral_id": "31a55f89-ff5e-4717-8343-51c1d35c3553",
        "id": "617b70a9-4ef5-4f90-aa80-29ffa16320eb",
        "name": "elastic-agent-91236",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "ti_recordedfuture.threat",
        "namespace": "76002",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "617b70a9-4ef5-4f90-aa80-29ffa16320eb",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_recordedfuture.threat",
        "ingested": "2025-06-11T14:51:47Z",
        "kind": "enrichment",
        "original": "{\"EvidenceDetails\":\"{\\\"EvidenceDetails\\\": [{\\\"Name\\\": \\\"suspectedCncDnsName\\\", \\\"EvidenceString\\\": \\\"1 sighting on 1 source: ThreatFox Infrastructure Analysis. ThreatFox identified ubykou33.top as possible TA0011 (Command and Control) for CryptBot on December 26, 2023. Most recent link (Dec 26, 2023): https://threatfox.abuse.ch/ioc/1223634\\\", \\\"CriticalityLabel\\\": \\\"Unusual\\\", \\\"MitigationString\\\": \\\"\\\", \\\"Rule\\\": \\\"Historical Suspected C\\\\u0026C DNS Name\\\", \\\"SourcesCount\\\": 1.0, \\\"Sources\\\": [\\\"source:sIoEOQ\\\"], \\\"Timestamp\\\": \\\"2023-12-26T17:06:29.000Z\\\", \\\"SightingsCount\\\": 1.0, \\\"Criticality\\\": 1.0}, {\\\"Name\\\": \\\"malwareSiteDetected\\\", \\\"EvidenceString\\\": \\\"2 sightings on 2 sources: External Sensor Data Analysis, Bitdefender. ubykou33.top is observed to be a malware site domain that navigates to malicious content including executables, drive-by infection sites, malicious scripts, viruses, trojans, or code.\\\", \\\"CriticalityLabel\\\": \\\"Unusual\\\", \\\"MitigationString\\\": \\\"\\\", \\\"Rule\\\": \\\"Historically Detected Malware Operation\\\", \\\"SourcesCount\\\": 2.0, \\\"Sources\\\": [\\\"source:kBB1fk\\\", \\\"source:d3Awkm\\\"], \\\"Timestamp\\\": \\\"2024-01-26T00:00:00.000Z\\\", \\\"SightingsCount\\\": 2.0, \\\"Criticality\\\": 1.0}, {\\\"Name\\\": \\\"malwareSiteSuspected\\\", \\\"EvidenceString\\\": \\\"1 sighting on 1 source: Bitdefender. Detected malicious behavior from an endpoint agent via global telemetry. Last observed on Jan 26, 2024.\\\", \\\"CriticalityLabel\\\": \\\"Unusual\\\", \\\"MitigationString\\\": \\\"\\\", \\\"Rule\\\": \\\"Historically Suspected Malware Operation\\\", \\\"SourcesCount\\\": 1.0, \\\"Sources\\\": [\\\"source:d3Awkm\\\"], \\\"Timestamp\\\": \\\"2024-01-26T00:00:00.000Z\\\", \\\"SightingsCount\\\": 1.0, \\\"Criticality\\\": 1.0}, {\\\"Name\\\": \\\"recentMalwareSiteDetected\\\", \\\"EvidenceString\\\": \\\"1 sighting on 1 source: External Sensor Data Analysis. ubykou33.top is observed to be a malware site domain that navigates to malicious content including executables, drive-by infection sites, malicious scripts, viruses, trojans, or code.\\\", \\\"CriticalityLabel\\\": \\\"Malicious\\\", \\\"MitigationString\\\": \\\"\\\", \\\"Rule\\\": \\\"Recently Detected Malware Operation\\\", \\\"SourcesCount\\\": 1.0, \\\"Sources\\\": [\\\"source:kBB1fk\\\"], \\\"Timestamp\\\": \\\"2024-05-08T23:11:43.601Z\\\", \\\"SightingsCount\\\": 1.0, \\\"Criticality\\\": 3.0}]}\",\"Name\":\"ubykou33.top\",\"Risk\":\"67\",\"RiskString\":\"4/52\"}",
        "risk_score": 67,
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "cel"
    },
    "recordedfuture": {
        "evidence_details": [
            {
                "criticality": 1,
                "criticality_label": "Unusual",
                "evidence_string": "1 sighting on 1 source: ThreatFox Infrastructure Analysis. ThreatFox identified ubykou33.top as possible TA0011 (Command and Control) for CryptBot on December 26, 2023. Most recent link (Dec 26, 2023): https://threatfox.abuse.ch/ioc/1223634",
                "mitigation_string": "",
                "name": "suspectedCncDnsName",
                "rule": "Historical Suspected C&C DNS Name",
                "sightings_count": 1,
                "sources": [
                    "source:sIoEOQ"
                ],
                "sources_count": 1,
                "timestamp": "2023-12-26T17:06:29.000Z"
            },
            {
                "criticality": 1,
                "criticality_label": "Unusual",
                "evidence_string": "2 sightings on 2 sources: External Sensor Data Analysis, Bitdefender. ubykou33.top is observed to be a malware site domain that navigates to malicious content including executables, drive-by infection sites, malicious scripts, viruses, trojans, or code.",
                "mitigation_string": "",
                "name": "malwareSiteDetected",
                "rule": "Historically Detected Malware Operation",
                "sightings_count": 2,
                "sources": [
                    "source:kBB1fk",
                    "source:d3Awkm"
                ],
                "sources_count": 2,
                "timestamp": "2024-01-26T00:00:00.000Z"
            },
            {
                "criticality": 1,
                "criticality_label": "Unusual",
                "evidence_string": "1 sighting on 1 source: Bitdefender. Detected malicious behavior from an endpoint agent via global telemetry. Last observed on Jan 26, 2024.",
                "mitigation_string": "",
                "name": "malwareSiteSuspected",
                "rule": "Historically Suspected Malware Operation",
                "sightings_count": 1,
                "sources": [
                    "source:d3Awkm"
                ],
                "sources_count": 1,
                "timestamp": "2024-01-26T00:00:00.000Z"
            },
            {
                "criticality": 3,
                "criticality_label": "Malicious",
                "evidence_string": "1 sighting on 1 source: External Sensor Data Analysis. ubykou33.top is observed to be a malware site domain that navigates to malicious content including executables, drive-by infection sites, malicious scripts, viruses, trojans, or code.",
                "mitigation_string": "",
                "name": "recentMalwareSiteDetected",
                "rule": "Recently Detected Malware Operation",
                "sightings_count": 1,
                "sources": [
                    "source:kBB1fk"
                ],
                "sources_count": 1,
                "timestamp": "2024-05-08T23:11:43.601Z"
            }
        ],
        "list": "test",
        "name": "ubykou33.top",
        "risk_string": "4/52"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "recordedfuture"
    ],
    "threat": {
        "feed": {
            "name": "Recorded Future"
        },
        "indicator": {
            "provider": [
                "ThreatFox Infrastructure Analysis",
                "External Sensor Data Analysis",
                "Bitdefender"
            ],
            "scanner_stats": 5,
            "sightings": 5,
            "type": "domain-name",
            "url": {
                "domain": "ubykou33.top"
            }
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
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
| recordedfuture.evidence_details.criticality |  | double |
| recordedfuture.evidence_details.criticality_label |  | keyword |
| recordedfuture.evidence_details.evidence_string |  | keyword |
| recordedfuture.evidence_details.mitigation_string |  | keyword |
| recordedfuture.evidence_details.name |  | keyword |
| recordedfuture.evidence_details.rule |  | keyword |
| recordedfuture.evidence_details.sightings_count |  | integer |
| recordedfuture.evidence_details.sources |  | keyword |
| recordedfuture.evidence_details.sources_count |  | integer |
| recordedfuture.evidence_details.timestamp |  | date |
| recordedfuture.list | User-configured risklist. | keyword |
| recordedfuture.name | Indicator value. | keyword |
| recordedfuture.risk_string | Details of risk rules observed. | keyword |
| threat.feed.name | Display friendly feed name | constant_keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |


### triggered_alert

This is the `triggered_alert` dataset.

#### Example

An example event for `triggered_alert` looks as following:

```json
{
    "@timestamp": "2499-03-31T04:03:56.425Z",
    "agent": {
        "ephemeral_id": "42c0fdbd-ad32-40b0-94e5-254f3d411918",
        "id": "fcd1547f-caa2-4468-a403-7a963922d26c",
        "name": "elastic-agent-28640",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "ti_recordedfuture.triggered_alert",
        "namespace": "32054",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "fcd1547f-caa2-4468-a403-7a963922d26c",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "ti_recordedfuture.triggered_alert",
        "id": "ABCD1234XYZ",
        "ingested": "2025-05-08T07:58:06Z",
        "kind": "alert",
        "original": "{\"ai_insights\":{\"comment\":\"The Recorded Future AI requires more references in order to produce a summary.\",\"text\":\"Text summary\"},\"analyst_note\":{\"id\":\"abcdef\",\"url\":{\"api\":\"https://api.recordedfuture.com/v2/analystnote/abcdef\",\"portal\":\"https://app.recordedfuture.com/portal/analyst-note/shared/true/doc:abcdef\"}},\"document\":{\"authors\":[],\"source\":{\"id\":\"source:VKz42X\",\"name\":\"Insikt Group\",\"type\":\"Source\"},\"title\":\"Morphing Meerkat PhaaS Platform Uses DNS MX Records and DoH Protocol to Deliver Targeted Phishing Campaign\",\"url\":\"https://example.com/abc/def\"},\"enriched_entities\":[],\"entities\":[{\"id\":\"ip:89.160.20.156\",\"name\":\"89.160.20.156\",\"type\":\"IpAddress\"},{\"id\":\"YOvb\",\"name\":\"Webmail\",\"type\":\"Product\"},{\"id\":\"url:https://carriertrucks.com\",\"name\":\"https://carriertrucks.com\",\"type\":\"URL\"}],\"fragment\":\"On March 27, 2025, Infoblox reported that the phishing-as-a-service (PhaaS) platform Morphing Meerkat uses DNS MX records and DNS-over-HTTPS (DoH) queries to deliver phishing pages tailored to victims’ email providers. Threat actors initiate campaigns using spoofed spam emails impersonating over 100 brands—including financial software providers. Embedded malicious links redirect users via compromised WordPress sites, public file-sharing platforms, or open redirect flaws on trusted domains like Google’s DoubleClick. The phishing kits dynamically serve one of over 114 localized HTML templates by mapping MX responses to specific login pages, defaulting to generic Webmail or Roundcube pages when unrecognized. Client -side JavaScript further customizes\",\"id\":\"ABCD1234XYZ\",\"language\":\"eng\",\"log\":{\"note_author\":null,\"note_date\":\"2025-03-31T04:03:56.425Z\",\"status_change_by\":\"admin\",\"status_date\":\"2025-03-31T04:03:56.425Z\",\"triggered\":\"2499-03-31T04:03:56.425Z\"},\"owner_organisation_details\":{\"enterprise_id\":\"uhash:abcd\",\"enterprise_name\":\"Elastic-Example\",\"organisations\":[{\"organisation_id\":\"abcd:abcd\",\"organisation_name\":\"Elastic-Example\"}]},\"primary_entity\":null,\"review\":{\"assignee\":\"John\",\"note\":\"note\",\"status\":\"no-action\",\"status_in_portal\":\"In Progress\"},\"rule\":{\"id\":\"ABC123\",\"name\":\"Analysis from Insikt Group\",\"url\":{\"portal\":\"https://app.recordedfuture.com/live/sc/ViewIdkobra_view_report_item_alert_editor?view_opts=%7B%22reportId%22%3A%abcd%22%2C%22bTitle%22%3Atrue%2C%22title%22%3A%22Analysis+from+Insikt+Group%22%7D\"},\"use_case_deprecation\":{\"description\":null}},\"title\":\"Analysis from Insikt Group - 1 reference\",\"type\":\"REFERENCE\",\"url\":{\"api\":\"https://api.recordedfuture.com/v3/alerts/ppd\",\"portal\":\"https://app.recordedfuture.com/live/sc/notification/?id=ppd\"}}"
    },
    "input": {
        "type": "cel"
    },
    "message": "On March 27, 2025, Infoblox reported that the phishing-as-a-service (PhaaS) platform Morphing Meerkat uses DNS MX records and DNS-over-HTTPS (DoH) queries to deliver phishing pages tailored to victims’ email providers. Threat actors initiate campaigns using spoofed spam emails impersonating over 100 brands—including financial software providers. Embedded malicious links redirect users via compromised WordPress sites, public file-sharing platforms, or open redirect flaws on trusted domains like Google’s DoubleClick. The phishing kits dynamically serve one of over 114 localized HTML templates by mapping MX responses to specific login pages, defaulting to generic Webmail or Roundcube pages when unrecognized. Client -side JavaScript further customizes",
    "recordedfuture": {
        "triggered_alert": {
            "ai_insights": {
                "comment": "The Recorded Future AI requires more references in order to produce a summary.",
                "text": "Text summary"
            },
            "analyst_note": {
                "id": "abcdef",
                "url": {
                    "api": "https://api.recordedfuture.com/v2/analystnote/abcdef",
                    "portal": "https://app.recordedfuture.com/portal/analyst-note/shared/true/doc:abcdef"
                }
            },
            "document": {
                "source": {
                    "id": "source:VKz42X",
                    "name": "Insikt Group",
                    "type": "Source"
                },
                "title": "Morphing Meerkat PhaaS Platform Uses DNS MX Records and DoH Protocol to Deliver Targeted Phishing Campaign",
                "url": "https://example.com/abc/def"
            },
            "entities": [
                {
                    "id": "ip:89.160.20.156",
                    "name": "89.160.20.156",
                    "type": "IpAddress"
                },
                {
                    "id": "YOvb",
                    "name": "Webmail",
                    "type": "Product"
                },
                {
                    "id": "url:https://carriertrucks.com",
                    "name": "https://carriertrucks.com",
                    "type": "URL"
                }
            ],
            "fragment": "On March 27, 2025, Infoblox reported that the phishing-as-a-service (PhaaS) platform Morphing Meerkat uses DNS MX records and DNS-over-HTTPS (DoH) queries to deliver phishing pages tailored to victims’ email providers. Threat actors initiate campaigns using spoofed spam emails impersonating over 100 brands—including financial software providers. Embedded malicious links redirect users via compromised WordPress sites, public file-sharing platforms, or open redirect flaws on trusted domains like Google’s DoubleClick. The phishing kits dynamically serve one of over 114 localized HTML templates by mapping MX responses to specific login pages, defaulting to generic Webmail or Roundcube pages when unrecognized. Client -side JavaScript further customizes",
            "id": "ABCD1234XYZ",
            "language": "eng",
            "log": {
                "note_date": "2025-03-31T04:03:56.425Z",
                "status_change_by": "admin",
                "status_date": "2025-03-31T04:03:56.425Z",
                "triggered": "2499-03-31T04:03:56.425Z"
            },
            "owner_organisation_details": {
                "enterprise_id": "uhash:abcd",
                "enterprise_name": "Elastic-Example",
                "organisations": [
                    {
                        "organisation_id": "abcd:abcd",
                        "organisation_name": "Elastic-Example"
                    }
                ]
            },
            "review": {
                "assignee": "John",
                "note": "note",
                "status": "no-action",
                "status_in_portal": "In Progress"
            },
            "rule": {
                "id": "ABC123",
                "name": "Analysis from Insikt Group",
                "url": {
                    "portal": "https://app.recordedfuture.com/live/sc/ViewIdkobra_view_report_item_alert_editor?view_opts=%7B%22reportId%22%3A%abcd%22%2C%22bTitle%22%3Atrue%2C%22title%22%3A%22Analysis+from+Insikt+Group%22%7D"
                }
            },
            "title": "Analysis from Insikt Group - 1 reference",
            "type": "REFERENCE",
            "url": {
                "api": "https://api.recordedfuture.com/v3/alerts/ppd",
                "portal": "https://app.recordedfuture.com/live/sc/notification/?id=ppd"
            }
        }
    },
    "related": {
        "ip": [
            "89.160.20.156"
        ],
        "user": [
            "admin",
            "John"
        ]
    },
    "rule": {
        "id": "ABC123",
        "name": "Analysis from Insikt Group"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "recordedfuture-triggered_alert"
    ],
    "url": {
        "domain": "example.com",
        "original": "https://example.com/abc/def",
        "path": "/abc/def",
        "scheme": "https"
    },
    "user": {
        "name": "admin"
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
| recordedfuture.triggered_alert.ai_insights.comment |  | keyword |
| recordedfuture.triggered_alert.ai_insights.text |  | keyword |
| recordedfuture.triggered_alert.analyst_note.id |  | keyword |
| recordedfuture.triggered_alert.analyst_note.url.api |  | keyword |
| recordedfuture.triggered_alert.analyst_note.url.portal |  | keyword |
| recordedfuture.triggered_alert.document.source.id |  | keyword |
| recordedfuture.triggered_alert.document.source.name |  | keyword |
| recordedfuture.triggered_alert.document.source.type |  | keyword |
| recordedfuture.triggered_alert.document.title |  | keyword |
| recordedfuture.triggered_alert.document.url |  | keyword |
| recordedfuture.triggered_alert.entities.id |  | keyword |
| recordedfuture.triggered_alert.entities.name |  | keyword |
| recordedfuture.triggered_alert.entities.type |  | keyword |
| recordedfuture.triggered_alert.fragment |  | keyword |
| recordedfuture.triggered_alert.id |  | keyword |
| recordedfuture.triggered_alert.language |  | keyword |
| recordedfuture.triggered_alert.log.note_author |  | keyword |
| recordedfuture.triggered_alert.log.note_date |  | date |
| recordedfuture.triggered_alert.log.status_change_by |  | keyword |
| recordedfuture.triggered_alert.log.status_date |  | date |
| recordedfuture.triggered_alert.log.triggered |  | date |
| recordedfuture.triggered_alert.owner_organisation_details.enterprise_id |  | keyword |
| recordedfuture.triggered_alert.owner_organisation_details.enterprise_name |  | keyword |
| recordedfuture.triggered_alert.owner_organisation_details.organisations.organisation_id |  | keyword |
| recordedfuture.triggered_alert.owner_organisation_details.organisations.organisation_name |  | keyword |
| recordedfuture.triggered_alert.primary_entity |  | keyword |
| recordedfuture.triggered_alert.review.assignee |  | keyword |
| recordedfuture.triggered_alert.review.note |  | keyword |
| recordedfuture.triggered_alert.review.status |  | keyword |
| recordedfuture.triggered_alert.review.status_in_portal |  | keyword |
| recordedfuture.triggered_alert.rule.id |  | keyword |
| recordedfuture.triggered_alert.rule.name |  | keyword |
| recordedfuture.triggered_alert.rule.url.portal |  | keyword |
| recordedfuture.triggered_alert.rule.use_case_deprecation |  | keyword |
| recordedfuture.triggered_alert.title |  | keyword |
| recordedfuture.triggered_alert.type |  | keyword |
| recordedfuture.triggered_alert.url.api |  | keyword |
| recordedfuture.triggered_alert.url.portal |  | keyword |


### playbook_alert

This is the `playbook_alert` dataset.

#### Example

An example event for `playbook_alert` looks as following:

```json
{
    "@timestamp": "2023-07-21T17:32:28.000Z",
    "agent": {
        "ephemeral_id": "9dcfa256-9b0e-4d4a-ae8b-7881f2e176ce",
        "id": "a3ca240b-87d5-45fe-9e28-6b08bdca9695",
        "name": "elastic-agent-22535",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "ti_recordedfuture.playbook_alert",
        "namespace": "39863",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "a3ca240b-87d5-45fe-9e28-6b08bdca9695",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2023-07-21T17:32:28.000Z",
        "dataset": "ti_recordedfuture.playbook_alert",
        "id": "task:abc",
        "ingested": "2025-05-08T07:56:56Z",
        "kind": "alert",
        "original": "{\"panel_action\":[{\"action\":\"Domain takedown request.\",\"assignee_id\":\"uhash:40wXmPVONA\",\"assignee_name\":\"Marty McFly\",\"description\":\"Initiate a takedown request...\",\"link\":\"takedownrequests.com\",\"status\":\"Resolved\",\"updated\":\"2023-07-21T17:32:28Z\"}],\"panel_evidence_dns\":{\"ip_list\":[{\"context_list\":[{\"context\":\"Active Mail Server\"}],\"criticality\":\"Low\",\"entity\":\"string\",\"record_type\":\"string\",\"risk_score\":99}],\"mx_list\":[{\"context_list\":[{\"context\":\"Active Mail Server\"}],\"criticality\":\"Low\",\"entity\":\"string\",\"record_type\":\"string\",\"risk_score\":99}],\"ns_list\":[{\"context_list\":[{\"context\":\"Active Mail Server\"}],\"criticality\":\"Low\",\"entity\":\"string\",\"record_type\":\"string\",\"risk_score\":99}]},\"panel_evidence_summary\":{\"explanation\":\"string\",\"keywords_in_domain_name\":{\"payment_keywords_in_domain_name\":[{\"domain\":\"idn:sso.bank.com\",\"word\":\"sso, bank\"}],\"security_keywords_in_domain_name\":[{\"domain\":\"idn:sso.bank.com\",\"word\":\"sso, bank\"}]},\"phishing_malicious_behavior\":{\"threatTypes\":[\"malware\"]},\"reregistration\":{\"expiration\":\"2023-07-21T17:32:28Z\",\"registrar\":\"string\",\"registrar_name\":\"string\"},\"resolved_record_list\":[{\"context_list\":[{\"context\":\"Active Mail Server\"}],\"criticality\":\"Low\",\"entity\":\"string\",\"record_type\":\"string\",\"risk_score\":99}],\"screenshot_mentions\":[{\"analyzed\":\"2023-07-21T17:32:28Z\",\"document\":\"doc:3tR0p\",\"mentioned_custom_keywords\":[{\"fragment\":\"string\",\"keyword\":\"string\",\"reference\":\"19GLiq\"}],\"mentioned_entities\":[{\"entity\":{\"id\":\"shq4H\",\"name\":\"My Test Product\",\"type\":\"Product\"},\"fragment\":\"string\",\"reference\":\"19GLiq\"}],\"screenshot\":\"img:27368c9c-5bf3-488a-8300-13657f38e37a\",\"url\":\"url:https://www.recordedfuture.com\"}],\"screenshots\":[{\"availability\":\"Available\",\"created\":\"2025-03-21T12:20:45.457Z\",\"description\":\"string\",\"image_id\":\"img:27368c9c-5bf3-488a-8300-13657f38e37a\",\"tag\":\"Parked / Ad hosting website\"}]},\"panel_evidence_whois\":{\"body\":[{\"added\":\"2025-03-21T12:20:45.457Z\",\"attribute\":\"attr:whois\",\"entity\":\"idn:mail.google.mail.pl\",\"provider\":\"whois\",\"removed\":\"2025-03-21T12:20:45.457Z\",\"value\":{\"contactEmail\":\"user@example.com\",\"createdDate\":\"2025-03-21T12:20:45.457Z\",\"expiresDate\":\"2025-03-21T12:20:45.457Z\",\"nameServers\":[\"idn:ns1.example.com\"],\"privateRegistration\":true,\"registrarName\":\"Example Domains, Inc.\",\"status\":\"string\",\"updatedDate\":\"2025-03-21T12:20:45.457Z\"}}]},\"panel_log_v2\":[{\"author_id\":\"uhash:40wXmPVONA\",\"author_name\":\"Marty McFly\",\"changes\":[{\"new\":{\"id\":\"uhash:Ds92mDX\",\"name\":\"Marty\"},\"old\":{\"id\":\"uhash:Ds92mDX\",\"name\":\"Marty\"},\"type\":\"assignee_change\"},{\"actions_taken\":[\"cyber_vulnerability.patched\",\"brand_mentions_on_code_repository.keys_rotated\",\"domain_abuse.takedown\",\"third_party_risk.vendor_mitigated_findings\",\"identity_novel_exposures.enforced_password_reset\"],\"new\":\"InProgress\",\"old\":\"New\",\"type\":\"status_change\"},{\"new\":\"High\",\"old\":\"Moderate\",\"type\":\"priority_change\"},{\"new\":\"Never\",\"old\":\"SignificantUpdates\",\"type\":\"reopen_strategy_change\"},{\"new\":\"string\",\"old\":\"string\",\"type\":\"title_change\"},{\"added\":[{\"id\":\"ip:19.158.255.26\",\"name\":\"19.158.255.26\",\"type\":\"IpAddress\"}],\"removed\":[{\"id\":\"ip:19.158.255.26\",\"name\":\"19.158.255.26\",\"type\":\"IpAddress\"}],\"type\":\"entities_change\"},{\"added\":[{\"id\":\"ip:19.158.255.26\",\"name\":\"19.158.255.26\",\"type\":\"IpAddress\"}],\"removed\":[{\"id\":\"ip:19.158.255.26\",\"name\":\"19.158.255.26\",\"type\":\"IpAddress\"}],\"type\":\"related_entities_change\"},{\"new\":\"string\",\"old\":\"string\",\"type\":\"description_change\"},{\"new\":\"string\",\"old\":\"string\",\"type\":\"external_id_change\"},{\"comment\":\"string\",\"type\":\"comment_change\"},{\"added\":[\"task:4d65b0f8-8254-402c-8178-4a9f97afc9b2\"],\"removed\":[\"task:4d65b0f8-8254-402c-8178-4a9f97afc9b2\"],\"type\":\"action_change\"},{\"added\":[\"C\\u0026C Server\"],\"removed\":[\"Active Mail Server\"],\"type\":\"assessment_ids_change\"},{\"removed_actions_taken\":[\"cyber_vulnerability.patched\",\"brand_mentions_on_code_repository.keys_rotated\",\"domain_abuse.takedown\",\"third_party_risk.vendor_mitigated_findings\",\"identity_novel_exposures.enforced_password_reset\"],\"type\":\"onward_actions_removed_change\"},{\"added_actions_taken\":[\"cyber_vulnerability.patched\",\"brand_mentions_on_code_repository.keys_rotated\",\"domain_abuse.takedown\",\"third_party_risk.vendor_mitigated_findings\",\"identity_novel_exposures.enforced_password_reset\"],\"type\":\"onward_actions_added_change\"},{\"added\":[{\"entity\":{\"id\":\"ip:19.158.255.26\",\"name\":\"19.158.255.26\",\"type\":\"IpAddress\"},\"type\":\"A\"}],\"domain\":\"mail.google.mail.pl\",\"removed\":[{\"entity\":{\"id\":\"ip:19.158.255.26\",\"name\":\"19.158.255.26\",\"type\":\"IpAddress\"},\"type\":\"A\"}],\"type\":\"dns_change\"},{\"added_contacts\":[{\"city\":\"string\",\"country\":\"string\",\"country_code\":\"string\",\"created\":\"2023-07-21T17:32:28Z\",\"email\":\"mail.google.mail.pl\",\"fax\":\"string\",\"name\":\"string\",\"organization\":\"string\",\"postal_code\":\"string\",\"state\":\"string\",\"street1\":\"string\",\"telephone\":\"string\",\"type\":\"string\"}],\"domain\":\"mail.google.mail.pl\",\"new_record\":{\"contact_email\":\"mail.google.mail.pl\",\"created\":\"2023-07-21T17:32:28Z\",\"name_servers\":[\"mail.google.mail.pl\"],\"private_registration\":true,\"registrar_name\":\"string\",\"status\":\"string\"},\"old_record\":{\"contact_email\":\"mail.google.mail.pl\",\"created\":\"2023-07-21T17:32:28Z\",\"name_servers\":[\"mail.google.mail.pl\"],\"private_registration\":true,\"registrar_name\":\"string\",\"status\":\"string\"},\"removed_contacts\":[{\"city\":\"string\",\"country\":\"string\",\"country_code\":\"string\",\"created\":\"2023-07-21T17:32:28Z\",\"email\":\"mail.google.mail.pl\",\"fax\":\"string\",\"name\":\"string\",\"organization\":\"string\",\"postal_code\":\"string\",\"state\":\"string\",\"street1\":\"string\",\"telephone\":\"string\",\"type\":\"string\"}],\"type\":\"whois_change\"},{\"added\":[{\"logotype_id\":\"U3QTi\",\"screenshot_id\":\"img:e8581823-7acd-402e-b863-daabda7db9d0\",\"url\":\"https://www.recordedfuture.com\"}],\"domain\":\"mail.google.mail.pl\",\"removed\":[{\"logotype_id\":\"U3QTi\",\"screenshot_id\":\"img:e8581823-7acd-402e-b863-daabda7db9d0\",\"url\":\"https://www.recordedfuture.com\"}],\"type\":\"logotype_in_screenshot_change\"},{\"added\":[{\"assessments\":[{\"id\":\"C\\u0026C Server\",\"level\":3,\"title\":\"string\"}],\"id\":\"ip:67.43.156.13\"}],\"domain\":\"mail.google.mail.pl\",\"removed\":[{\"assessments\":[{\"id\":\"C\\u0026C Server\",\"level\":3,\"title\":\"string\"}],\"id\":\"ip:67.43.156.13\"}],\"type\":\"malicious_dns_change\"},{\"added\":{\"expiration\":\"2026-07-21T00:00:00Z\",\"iana_id\":\"string\",\"registrar\":\"ip:67.43.156.13\",\"registrar_name\":\"NameCheap, Inc\"},\"domain\":\"mail.google.mail.pl\",\"removed\":{\"expiration\":\"2026-07-21T00:00:00Z\",\"iana_id\":\"string\",\"registrar\":\"ip:67.43.156.13\",\"registrar_name\":\"NameCheap, Inc\"},\"type\":\"reregistration_change\"},{\"added\":[{\"assessments\":[{\"id\":\"string\",\"level\":3,\"source\":{\"id\":\"string\",\"name\":\"string\"},\"title\":\"string\"}],\"url\":\"https://www.somesite.com\"}],\"domain\":\"recordedfuture.com\",\"removed\":[{\"assessments\":[{\"id\":\"string\",\"level\":3,\"source\":{\"id\":\"string\",\"name\":\"string\"},\"title\":\"string\"}],\"url\":\"https://www.somesite.com\"}],\"type\":\"malicious_url_change\"},{\"added\":[{\"analyzed\":\"2023-07-21T00:00:00Z\",\"document\":\"Ft6Qt\",\"mentioned_entities\":[{\"assessments\":[{\"id\":\"string\",\"level\":3,\"source\":{\"id\":\"string\",\"name\":\"string\"},\"title\":\"string\"}],\"entity\":{\"id\":\"ip:19.158.255.26\",\"name\":\"19.158.255.26\",\"type\":\"IpAddress\"},\"fragment\":\"string\",\"reference\":\"oIj2a\"}],\"mentioned_texts\":[{\"assessments\":[{\"id\":\"string\",\"level\":3,\"source\":{\"id\":\"string\",\"name\":\"string\"},\"title\":\"string\"}],\"fragment\":\"string\",\"reference\":\"string\",\"text\":\"string\"}],\"screenshot_id\":\"img:27368c9c-5bf3-488a-8300-13657f38e37a\",\"url\":\"https://www.somesite.com\"}],\"domain\":\"recordedfuture.com\",\"type\":\"screenshot_mentions_change\"},{\"added\":{\"threat_types\":[\"malware\"]},\"domain\":\"idn:mail.google.mail.pl\",\"removed\":{\"threat_types\":[\"malware\"]},\"type\":\"phishing_malicious_behavior_change\"},{\"added\":{\"id\":\"Exploit Likely\",\"level\":3,\"title\":\"string\"},\"removed\":{\"id\":\"Exploit Likely\",\"level\":3,\"title\":\"string\"},\"triggered_by_risk_rule\":{\"description\":\"Web Reporting Prior to NVD Disclosure\",\"evidence_string\":\"string\",\"id\":\"riskrule:dc2929d6-5157-43f5-ad4f-d96b7ecf7da9\",\"machine_name\":\"noCvssScore\",\"name\":\"c2929d6-5157-43f5-ad4f-d96b7ecf7da9\",\"timestamp\":\"2023-07-21T17:32:28Z\"},\"type\":\"lifecycle_in_cve_change\"},{\"added\":[{\"assessments\":[{\"entity\":{\"id\":\"ip:19.158.255.26\",\"name\":\"19.158.255.26\",\"type\":\"IpAddress\"},\"id\":\"attr:possibleKeyLeak\",\"level\":3,\"text_indicator\":\"credential\",\"title\":\"Possible Key Leak\"}],\"document\":{\"content\":\"string\",\"id\":\"doc:rprM_Q\",\"owner_id\":\"uhash:40wXmPVONA\",\"owner_name\":\"Marty\",\"published\":\"2023-07-21T17:32:28Z\"},\"target_entities\":[{\"id\":\"ip:19.158.255.26\",\"name\":\"19.158.255.26\",\"type\":\"IpAddress\"}],\"watch_lists\":[{\"id\":\"string\",\"name\":\"string\"}]}],\"type\":\"evidence_changes\"},{\"added\":{\"evidence_string\":\"string\",\"level\":3,\"timestamp\":\"2023-08-14T17:32:28Z\"},\"removed\":{\"evidence_string\":\"string\",\"level\":3,\"timestamp\":\"2023-08-14T17:32:28Z\"},\"risk_attribute\":\"Recent Attention on Ransomware Extortion Website\",\"type\":\"tpr_assessment_change\"}],\"created\":\"2023-07-21T17:32:28Z\",\"id\":\"uuid:a3c4f8f0-8dd8-4940-8b0a-75a59764d068\"}],\"panel_status\":{\"actions_taken\":[\"cyber_vulnerability.patched\",\"brand_mentions_on_code_repository.keys_rotated\",\"domain_abuse.takedown\",\"third_party_risk.vendor_mitigated_findings\",\"identity_novel_exposures.enforced_password_reset\"],\"assignee_id\":\"uhash:40wXmPVONA\",\"assignee_name\":\"Marty McFly\",\"case_rule_id\":\"string\",\"case_rule_label\":\"Domain Abuse\",\"context_list\":[{\"context\":\"Active Mail Server\"}],\"created\":\"2023-07-21T17:32:28Z\",\"creator_id\":\"uhash:40wXmPVONA\",\"creator_name\":\"Marty McFly\",\"entity_criticality\":\"Low\",\"entity_id\":\"idn:mail.google.mail.pl\",\"entity_name\":\"mail.google.mail.pl\",\"owner_organisation_details\":{\"enterprise_id\":\"uhash:1HX2qIn4Zy\",\"enterprise_name\":\"Recorded Future\",\"organisations\":[{\"organisation_id\":\"uhash:3HX3rIn4Kv\",\"organisation_name\":\"Recorded Future\"}]},\"priority\":\"High\",\"reopen\":\"Never\",\"risk_score\":99,\"status\":\"Resolved\",\"targets\":[\"idn:mail.google.mail.pl\"],\"updated\":\"2023-07-21T17:32:28Z\"},\"playbook_alert_id\":\"task:abc\"}",
        "risk_score": 99,
        "severity": 73
    },
    "input": {
        "type": "cel"
    },
    "recordedfuture": {
        "playbook_alert": {
            "panel_action": [
                {
                    "action": "Domain takedown request.",
                    "assignee_id": "uhash:40wXmPVONA",
                    "assignee_name": "Marty McFly",
                    "description": "Initiate a takedown request...",
                    "link": "takedownrequests.com",
                    "status": "Resolved",
                    "updated": "2023-07-21T17:32:28.000Z"
                }
            ],
            "panel_evidence_dns": {
                "ip_list": [
                    {
                        "context_list": [
                            {
                                "context": "Active Mail Server"
                            }
                        ],
                        "criticality": "Low",
                        "entity": "string",
                        "record_type": "string",
                        "risk_score": 99
                    }
                ],
                "mx_list": [
                    {
                        "context_list": [
                            {
                                "context": "Active Mail Server"
                            }
                        ],
                        "criticality": "Low",
                        "entity": "string",
                        "record_type": "string",
                        "risk_score": 99
                    }
                ],
                "ns_list": [
                    {
                        "context_list": [
                            {
                                "context": "Active Mail Server"
                            }
                        ],
                        "criticality": "Low",
                        "entity": "string",
                        "record_type": "string",
                        "risk_score": 99
                    }
                ]
            },
            "panel_evidence_summary": {
                "explanation": "string",
                "keywords_in_domain_name": {
                    "payment_keywords_in_domain_name": [
                        {
                            "domain": "idn:sso.bank.com",
                            "word": "sso, bank"
                        }
                    ],
                    "security_keywords_in_domain_name": [
                        {
                            "domain": "idn:sso.bank.com",
                            "word": "sso, bank"
                        }
                    ]
                },
                "phishing_malicious_behavior": {
                    "threatTypes": [
                        "malware"
                    ]
                },
                "reregistration": {
                    "expiration": "2023-07-21T17:32:28.000Z",
                    "registrar": "string",
                    "registrar_name": "string"
                },
                "resolved_record_list": [
                    {
                        "context_list": [
                            {
                                "context": "Active Mail Server"
                            }
                        ],
                        "criticality": "Low",
                        "entity": "string",
                        "record_type": "string",
                        "risk_score": 99
                    }
                ],
                "screenshot_mentions": [
                    {
                        "analyzed": "2023-07-21T17:32:28.000Z",
                        "document": "doc:3tR0p",
                        "mentioned_custom_keywords": [
                            {
                                "fragment": "string",
                                "keyword": "string",
                                "reference": "19GLiq"
                            }
                        ],
                        "mentioned_entities": [
                            {
                                "entity": {
                                    "id": "shq4H",
                                    "name": "My Test Product",
                                    "type": "Product"
                                },
                                "fragment": "string",
                                "reference": "19GLiq"
                            }
                        ],
                        "screenshot": "img:27368c9c-5bf3-488a-8300-13657f38e37a",
                        "url": "url:https://www.recordedfuture.com"
                    }
                ],
                "screenshots": [
                    {
                        "availability": "Available",
                        "created": "2025-03-21T12:20:45.457Z",
                        "description": "string",
                        "image_id": "img:27368c9c-5bf3-488a-8300-13657f38e37a",
                        "tag": "Parked / Ad hosting website"
                    }
                ]
            },
            "panel_evidence_whois": {
                "body": [
                    {
                        "added": "2025-03-21T12:20:45.457Z",
                        "attribute": "attr:whois",
                        "entity": "idn:mail.google.mail.pl",
                        "provider": "whois",
                        "removed": "2025-03-21T12:20:45.457Z",
                        "value": {
                            "contactEmail": "user@example.com",
                            "createdDate": "2025-03-21T12:20:45.457Z",
                            "expiresDate": "2025-03-21T12:20:45.457Z",
                            "nameServers": [
                                "idn:ns1.example.com"
                            ],
                            "privateRegistration": true,
                            "registrarName": "Example Domains, Inc.",
                            "status": "string",
                            "updatedDate": "2025-03-21T12:20:45.457Z"
                        }
                    }
                ]
            },
            "panel_log_v2": [
                {
                    "author_id": "uhash:40wXmPVONA",
                    "author_name": "Marty McFly",
                    "changes": [
                        {
                            "new": {
                                "id": "uhash:Ds92mDX",
                                "name": "Marty"
                            },
                            "old": {
                                "id": "uhash:Ds92mDX",
                                "name": "Marty"
                            },
                            "type": "assignee_change"
                        },
                        {
                            "actions_taken": [
                                "cyber_vulnerability.patched",
                                "brand_mentions_on_code_repository.keys_rotated",
                                "domain_abuse.takedown",
                                "third_party_risk.vendor_mitigated_findings",
                                "identity_novel_exposures.enforced_password_reset"
                            ],
                            "new_str": "InProgress",
                            "old_str": "New",
                            "type": "status_change"
                        },
                        {
                            "new_str": "High",
                            "old_str": "Moderate",
                            "type": "priority_change"
                        },
                        {
                            "new_str": "Never",
                            "old_str": "SignificantUpdates",
                            "type": "reopen_strategy_change"
                        },
                        {
                            "new_str": "string",
                            "old_str": "string",
                            "type": "title_change"
                        },
                        {
                            "added": [
                                {
                                    "id": "ip:19.158.255.26",
                                    "name": "19.158.255.26",
                                    "type": "IpAddress"
                                }
                            ],
                            "removed": [
                                {
                                    "id": "ip:19.158.255.26",
                                    "name": "19.158.255.26",
                                    "type": "IpAddress"
                                }
                            ],
                            "type": "entities_change"
                        },
                        {
                            "added": [
                                {
                                    "id": "ip:19.158.255.26",
                                    "name": "19.158.255.26",
                                    "type": "IpAddress"
                                }
                            ],
                            "removed": [
                                {
                                    "id": "ip:19.158.255.26",
                                    "name": "19.158.255.26",
                                    "type": "IpAddress"
                                }
                            ],
                            "type": "related_entities_change"
                        },
                        {
                            "new_str": "string",
                            "old_str": "string",
                            "type": "description_change"
                        },
                        {
                            "new_str": "string",
                            "old_str": "string",
                            "type": "external_id_change"
                        },
                        {
                            "comment": "string",
                            "type": "comment_change"
                        },
                        {
                            "added_str": [
                                "task:4d65b0f8-8254-402c-8178-4a9f97afc9b2"
                            ],
                            "removed_str": [
                                "task:4d65b0f8-8254-402c-8178-4a9f97afc9b2"
                            ],
                            "type": "action_change"
                        },
                        {
                            "added_str": [
                                "C&C Server"
                            ],
                            "removed_str": [
                                "Active Mail Server"
                            ],
                            "type": "assessment_ids_change"
                        },
                        {
                            "removed_actions_taken": [
                                "cyber_vulnerability.patched",
                                "brand_mentions_on_code_repository.keys_rotated",
                                "domain_abuse.takedown",
                                "third_party_risk.vendor_mitigated_findings",
                                "identity_novel_exposures.enforced_password_reset"
                            ],
                            "type": "onward_actions_removed_change"
                        },
                        {
                            "added_actions_taken": [
                                "cyber_vulnerability.patched",
                                "brand_mentions_on_code_repository.keys_rotated",
                                "domain_abuse.takedown",
                                "third_party_risk.vendor_mitigated_findings",
                                "identity_novel_exposures.enforced_password_reset"
                            ],
                            "type": "onward_actions_added_change"
                        },
                        {
                            "added": [
                                {
                                    "entity": {
                                        "id": "ip:19.158.255.26",
                                        "name": "19.158.255.26",
                                        "type": "IpAddress"
                                    },
                                    "type": "A"
                                }
                            ],
                            "domain": "mail.google.mail.pl",
                            "removed": [
                                {
                                    "entity": {
                                        "id": "ip:19.158.255.26",
                                        "name": "19.158.255.26",
                                        "type": "IpAddress"
                                    },
                                    "type": "A"
                                }
                            ],
                            "type": "dns_change"
                        },
                        {
                            "added_contacts": [
                                {
                                    "city": "string",
                                    "country": "string",
                                    "country_code": "string",
                                    "created": "2023-07-21T17:32:28Z",
                                    "email": "mail.google.mail.pl",
                                    "fax": "string",
                                    "name": "string",
                                    "organization": "string",
                                    "postal_code": "string",
                                    "state": "string",
                                    "street1": "string",
                                    "telephone": "string",
                                    "type": "string"
                                }
                            ],
                            "domain": "mail.google.mail.pl",
                            "new_record": {
                                "contact_email": "mail.google.mail.pl",
                                "created": "2023-07-21T17:32:28Z",
                                "name_servers": [
                                    "mail.google.mail.pl"
                                ],
                                "private_registration": true,
                                "registrar_name": "string",
                                "status": "string"
                            },
                            "old_record": {
                                "contact_email": "mail.google.mail.pl",
                                "created": "2023-07-21T17:32:28Z",
                                "name_servers": [
                                    "mail.google.mail.pl"
                                ],
                                "private_registration": true,
                                "registrar_name": "string",
                                "status": "string"
                            },
                            "removed_contacts": [
                                {
                                    "city": "string",
                                    "country": "string",
                                    "country_code": "string",
                                    "created": "2023-07-21T17:32:28Z",
                                    "email": "mail.google.mail.pl",
                                    "fax": "string",
                                    "name": "string",
                                    "organization": "string",
                                    "postal_code": "string",
                                    "state": "string",
                                    "street1": "string",
                                    "telephone": "string",
                                    "type": "string"
                                }
                            ],
                            "type": "whois_change"
                        },
                        {
                            "added": [
                                {
                                    "logotype_id": "U3QTi",
                                    "screenshot_id": "img:e8581823-7acd-402e-b863-daabda7db9d0",
                                    "url": "https://www.recordedfuture.com"
                                }
                            ],
                            "domain": "mail.google.mail.pl",
                            "removed": [
                                {
                                    "logotype_id": "U3QTi",
                                    "screenshot_id": "img:e8581823-7acd-402e-b863-daabda7db9d0",
                                    "url": "https://www.recordedfuture.com"
                                }
                            ],
                            "type": "logotype_in_screenshot_change"
                        },
                        {
                            "added": [
                                {
                                    "assessments": [
                                        {
                                            "id": "C&C Server",
                                            "level": 3,
                                            "title": "string"
                                        }
                                    ],
                                    "id": "ip:67.43.156.13"
                                }
                            ],
                            "domain": "mail.google.mail.pl",
                            "removed": [
                                {
                                    "assessments": [
                                        {
                                            "id": "C&C Server",
                                            "level": 3,
                                            "title": "string"
                                        }
                                    ],
                                    "id": "ip:67.43.156.13"
                                }
                            ],
                            "type": "malicious_dns_change"
                        },
                        {
                            "added": {
                                "expiration": "2026-07-21T00:00:00Z",
                                "iana_id": "string",
                                "registrar": "ip:67.43.156.13",
                                "registrar_name": "NameCheap, Inc"
                            },
                            "domain": "mail.google.mail.pl",
                            "removed": {
                                "expiration": "2026-07-21T00:00:00Z",
                                "iana_id": "string",
                                "registrar": "ip:67.43.156.13",
                                "registrar_name": "NameCheap, Inc"
                            },
                            "type": "reregistration_change"
                        },
                        {
                            "added": [
                                {
                                    "assessments": [
                                        {
                                            "id": "string",
                                            "level": 3,
                                            "source": {
                                                "id": "string",
                                                "name": "string"
                                            },
                                            "title": "string"
                                        }
                                    ],
                                    "url": "https://www.somesite.com"
                                }
                            ],
                            "domain": "recordedfuture.com",
                            "removed": [
                                {
                                    "assessments": [
                                        {
                                            "id": "string",
                                            "level": 3,
                                            "source": {
                                                "id": "string",
                                                "name": "string"
                                            },
                                            "title": "string"
                                        }
                                    ],
                                    "url": "https://www.somesite.com"
                                }
                            ],
                            "type": "malicious_url_change"
                        },
                        {
                            "added": [
                                {
                                    "analyzed": "2023-07-21T00:00:00Z",
                                    "document": "Ft6Qt",
                                    "mentioned_entities": [
                                        {
                                            "assessments": [
                                                {
                                                    "id": "string",
                                                    "level": 3,
                                                    "source": {
                                                        "id": "string",
                                                        "name": "string"
                                                    },
                                                    "title": "string"
                                                }
                                            ],
                                            "entity": {
                                                "id": "ip:19.158.255.26",
                                                "name": "19.158.255.26",
                                                "type": "IpAddress"
                                            },
                                            "fragment": "string",
                                            "reference": "oIj2a"
                                        }
                                    ],
                                    "mentioned_texts": [
                                        {
                                            "assessments": [
                                                {
                                                    "id": "string",
                                                    "level": 3,
                                                    "source": {
                                                        "id": "string",
                                                        "name": "string"
                                                    },
                                                    "title": "string"
                                                }
                                            ],
                                            "fragment": "string",
                                            "reference": "string",
                                            "text": "string"
                                        }
                                    ],
                                    "screenshot_id": "img:27368c9c-5bf3-488a-8300-13657f38e37a",
                                    "url": "https://www.somesite.com"
                                }
                            ],
                            "domain": "recordedfuture.com",
                            "type": "screenshot_mentions_change"
                        },
                        {
                            "added": {
                                "threat_types": [
                                    "malware"
                                ]
                            },
                            "domain": "idn:mail.google.mail.pl",
                            "removed": {
                                "threat_types": [
                                    "malware"
                                ]
                            },
                            "type": "phishing_malicious_behavior_change"
                        },
                        {
                            "added": {
                                "id": "Exploit Likely",
                                "level": 3,
                                "title": "string"
                            },
                            "removed": {
                                "id": "Exploit Likely",
                                "level": 3,
                                "title": "string"
                            },
                            "triggered_by_risk_rule": {
                                "description": "Web Reporting Prior to NVD Disclosure",
                                "evidence_string": "string",
                                "id": "riskrule:dc2929d6-5157-43f5-ad4f-d96b7ecf7da9",
                                "machine_name": "noCvssScore",
                                "name": "c2929d6-5157-43f5-ad4f-d96b7ecf7da9",
                                "timestamp": "2023-07-21T17:32:28Z"
                            },
                            "type": "lifecycle_in_cve_change"
                        },
                        {
                            "added": [
                                {
                                    "assessments": [
                                        {
                                            "entity": {
                                                "id": "ip:19.158.255.26",
                                                "name": "19.158.255.26",
                                                "type": "IpAddress"
                                            },
                                            "id": "attr:possibleKeyLeak",
                                            "level": 3,
                                            "text_indicator": "credential",
                                            "title": "Possible Key Leak"
                                        }
                                    ],
                                    "document": {
                                        "content": "string",
                                        "id": "doc:rprM_Q",
                                        "owner_id": "uhash:40wXmPVONA",
                                        "owner_name": "Marty",
                                        "published": "2023-07-21T17:32:28Z"
                                    },
                                    "target_entities": [
                                        {
                                            "id": "ip:19.158.255.26",
                                            "name": "19.158.255.26",
                                            "type": "IpAddress"
                                        }
                                    ],
                                    "watch_lists": [
                                        {
                                            "id": "string",
                                            "name": "string"
                                        }
                                    ]
                                }
                            ],
                            "type": "evidence_changes"
                        },
                        {
                            "added": {
                                "evidence_string": "string",
                                "level": 3,
                                "timestamp": "2023-08-14T17:32:28Z"
                            },
                            "removed": {
                                "evidence_string": "string",
                                "level": 3,
                                "timestamp": "2023-08-14T17:32:28Z"
                            },
                            "risk_attribute": "Recent Attention on Ransomware Extortion Website",
                            "type": "tpr_assessment_change"
                        }
                    ],
                    "created": "2023-07-21T17:32:28.000Z",
                    "id": "uuid:a3c4f8f0-8dd8-4940-8b0a-75a59764d068"
                }
            ],
            "panel_status": {
                "actions_taken": [
                    "cyber_vulnerability.patched",
                    "brand_mentions_on_code_repository.keys_rotated",
                    "domain_abuse.takedown",
                    "third_party_risk.vendor_mitigated_findings",
                    "identity_novel_exposures.enforced_password_reset"
                ],
                "assignee_id": "uhash:40wXmPVONA",
                "assignee_name": "Marty McFly",
                "case_rule_id": "string",
                "case_rule_label": "Domain Abuse",
                "context_list": [
                    {
                        "context": "Active Mail Server"
                    }
                ],
                "created": "2023-07-21T17:32:28.000Z",
                "creator_id": "uhash:40wXmPVONA",
                "creator_name": "Marty McFly",
                "entity_criticality": "Low",
                "entity_id": "idn:mail.google.mail.pl",
                "entity_name": "mail.google.mail.pl",
                "owner_organisation_details": {
                    "enterprise_id": "uhash:1HX2qIn4Zy",
                    "enterprise_name": "Recorded Future",
                    "organisations": [
                        {
                            "organisation_id": "uhash:3HX3rIn4Kv",
                            "organisation_name": "Recorded Future"
                        }
                    ]
                },
                "priority": "High",
                "reopen": "Never",
                "risk_score": 99,
                "status": "Resolved",
                "targets_str": [
                    "idn:mail.google.mail.pl"
                ],
                "updated": "2023-07-21T17:32:28.000Z"
            },
            "playbook_alert_id": "task:abc"
        }
    },
    "related": {
        "user": [
            "Marty McFly",
            "mail.google.mail.pl",
            "uhash:40wXmPVONA"
        ]
    },
    "rule": {
        "id": "string"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "recordedfuture-playbook_alert"
    ],
    "url": {
        "full": [
            "url:https://www.recordedfuture.com"
        ]
    },
    "user": {
        "id": "uhash:40wXmPVONA",
        "name": "Marty McFly"
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
| recordedfuture.playbook_alert.panel_action.action |  | keyword |
| recordedfuture.playbook_alert.panel_action.assignee_id |  | keyword |
| recordedfuture.playbook_alert.panel_action.assignee_name |  | keyword |
| recordedfuture.playbook_alert.panel_action.description |  | keyword |
| recordedfuture.playbook_alert.panel_action.link |  | keyword |
| recordedfuture.playbook_alert.panel_action.status |  | keyword |
| recordedfuture.playbook_alert.panel_action.updated |  | date |
| recordedfuture.playbook_alert.panel_evidence_dns.ip_list.context_list.context |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_dns.ip_list.criticality |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_dns.ip_list.entity |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_dns.ip_list.record_type |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_dns.ip_list.risk_score |  | long |
| recordedfuture.playbook_alert.panel_evidence_dns.mx_list.context_list.context |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_dns.mx_list.criticality |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_dns.mx_list.entity |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_dns.mx_list.record_type |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_dns.mx_list.risk_score |  | long |
| recordedfuture.playbook_alert.panel_evidence_dns.ns_list.context_list.context |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_dns.ns_list.criticality |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_dns.ns_list.entity |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_dns.ns_list.record_type |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_dns.ns_list.risk_score |  | long |
| recordedfuture.playbook_alert.panel_evidence_summary.affected_products.name |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.assessments.criticality |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.assessments.name |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.authorization_url |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.compromised_host.antivirus |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.compromised_host.computer_name |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.compromised_host.exfiltration_date |  | date |
| recordedfuture.playbook_alert.panel_evidence_summary.compromised_host.malware_file |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.compromised_host.os |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.compromised_host.os_username |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.compromised_host.timezone |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.compromised_host.uac |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.dump.description |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.dump.name |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.explanation |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.exposed_secret.details.clear_text_hint |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.exposed_secret.details.clear_text_value |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.exposed_secret.details.properties |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.exposed_secret.details.rank |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.exposed_secret.effectively_clear |  | boolean |
| recordedfuture.playbook_alert.panel_evidence_summary.exposed_secret.hashes.algorithm |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.exposed_secret.hashes.hash |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.exposed_secret.hashes.hash_prefix |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.exposed_secret.type |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.infrastructure.ip |  | ip |
| recordedfuture.playbook_alert.panel_evidence_summary.insikt_notes.fragment |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.insikt_notes.id |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.insikt_notes.published |  | date |
| recordedfuture.playbook_alert.panel_evidence_summary.insikt_notes.title |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.insikt_notes.topic |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.keywords_in_domain_name.payment_keywords_in_domain_name.domain |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.keywords_in_domain_name.payment_keywords_in_domain_name.word |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.keywords_in_domain_name.security_keywords_in_domain_name |  | flattened |
| recordedfuture.playbook_alert.panel_evidence_summary.malware_family.id |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.malware_family.name |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.phishing_malicious_behavior.threatTypes |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.reregistration.expiration |  | date |
| recordedfuture.playbook_alert.panel_evidence_summary.reregistration.registrar |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.reregistration.registrar_name |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.resolved_record_list.context_list.context |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.resolved_record_list.criticality |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.resolved_record_list.entity |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.resolved_record_list.record_type |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.resolved_record_list.risk_score |  | long |
| recordedfuture.playbook_alert.panel_evidence_summary.screenshot_mentions.analyzed |  | date |
| recordedfuture.playbook_alert.panel_evidence_summary.screenshot_mentions.document |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.screenshot_mentions.mentioned_custom_keywords.fragment |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.screenshot_mentions.mentioned_custom_keywords.keyword |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.screenshot_mentions.mentioned_custom_keywords.reference |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.screenshot_mentions.mentioned_entities.entity.id |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.screenshot_mentions.mentioned_entities.entity.name |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.screenshot_mentions.mentioned_entities.entity.type |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.screenshot_mentions.mentioned_entities.fragment |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.screenshot_mentions.mentioned_entities.reference |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.screenshot_mentions.screenshot |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.screenshot_mentions.url |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.screenshots.availability |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.screenshots.created |  | date |
| recordedfuture.playbook_alert.panel_evidence_summary.screenshots.description |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.screenshots.image_id |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.screenshots.tag |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.subject |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.summary.lifecycle_stage |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.summary.risk_rules.description |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.summary.risk_rules.rule |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.summary.targets.name |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.technologies.category |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.technologies.id |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_summary.technologies.name |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_whois.body.added |  | date |
| recordedfuture.playbook_alert.panel_evidence_whois.body.attribute |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_whois.body.entity |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_whois.body.provider |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_whois.body.removed |  | date |
| recordedfuture.playbook_alert.panel_evidence_whois.body.value.contactEmail |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_whois.body.value.createdDate |  | date |
| recordedfuture.playbook_alert.panel_evidence_whois.body.value.expiresDate |  | date |
| recordedfuture.playbook_alert.panel_evidence_whois.body.value.nameServers |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_whois.body.value.privateRegistration |  | boolean |
| recordedfuture.playbook_alert.panel_evidence_whois.body.value.registrarName |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_whois.body.value.status |  | keyword |
| recordedfuture.playbook_alert.panel_evidence_whois.body.value.updatedDate |  | date |
| recordedfuture.playbook_alert.panel_log_v2.author_id |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.author_name |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.actions_taken |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.added |  | flattened |
| recordedfuture.playbook_alert.panel_log_v2.changes.added_actions_taken |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.added_contacts.city |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.added_contacts.country |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.added_contacts.country_code |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.added_contacts.created |  | date |
| recordedfuture.playbook_alert.panel_log_v2.changes.added_contacts.email |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.added_contacts.fax |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.added_contacts.name |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.added_contacts.organization |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.added_contacts.postal_code |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.added_contacts.state |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.added_contacts.street1 |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.added_contacts.telephone |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.added_contacts.type |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.added_str |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.comment |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.domain |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.new |  | flattened |
| recordedfuture.playbook_alert.panel_log_v2.changes.new_record.contact_email |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.new_record.created |  | date |
| recordedfuture.playbook_alert.panel_log_v2.changes.new_record.name_servers |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.new_record.private_registration |  | boolean |
| recordedfuture.playbook_alert.panel_log_v2.changes.new_record.registrar_name |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.new_record.status |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.new_str |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.old |  | flattened |
| recordedfuture.playbook_alert.panel_log_v2.changes.old_record.contact_email |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.old_record.created |  | date |
| recordedfuture.playbook_alert.panel_log_v2.changes.old_record.name_servers |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.old_record.private_registration |  | boolean |
| recordedfuture.playbook_alert.panel_log_v2.changes.old_record.registrar_name |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.old_record.status |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.old_str |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.removed |  | flattened |
| recordedfuture.playbook_alert.panel_log_v2.changes.removed_actions_taken |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.removed_contacts.city |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.removed_contacts.country |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.removed_contacts.country_code |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.removed_contacts.created |  | date |
| recordedfuture.playbook_alert.panel_log_v2.changes.removed_contacts.email |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.removed_contacts.fax |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.removed_contacts.name |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.removed_contacts.organization |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.removed_contacts.postal_code |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.removed_contacts.state |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.removed_contacts.street1 |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.removed_contacts.telephone |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.removed_contacts.type |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.removed_str |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.risk_attribute |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.triggered_by_risk_rule.description |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.triggered_by_risk_rule.evidence_string |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.triggered_by_risk_rule.id |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.triggered_by_risk_rule.machine_name |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.triggered_by_risk_rule.name |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.changes.triggered_by_risk_rule.timestamp |  | date |
| recordedfuture.playbook_alert.panel_log_v2.changes.type |  | keyword |
| recordedfuture.playbook_alert.panel_log_v2.created |  | date |
| recordedfuture.playbook_alert.panel_log_v2.id |  | keyword |
| recordedfuture.playbook_alert.panel_status.actions_taken |  | keyword |
| recordedfuture.playbook_alert.panel_status.assignee_id |  | keyword |
| recordedfuture.playbook_alert.panel_status.assignee_name |  | keyword |
| recordedfuture.playbook_alert.panel_status.case_rule_id |  | keyword |
| recordedfuture.playbook_alert.panel_status.case_rule_label |  | keyword |
| recordedfuture.playbook_alert.panel_status.context_list.context |  | keyword |
| recordedfuture.playbook_alert.panel_status.created |  | date |
| recordedfuture.playbook_alert.panel_status.creator_id |  | keyword |
| recordedfuture.playbook_alert.panel_status.creator_name |  | keyword |
| recordedfuture.playbook_alert.panel_status.entity_criticality |  | keyword |
| recordedfuture.playbook_alert.panel_status.entity_id |  | keyword |
| recordedfuture.playbook_alert.panel_status.entity_name |  | keyword |
| recordedfuture.playbook_alert.panel_status.lifecycle_stage |  | keyword |
| recordedfuture.playbook_alert.panel_status.owner_organisation_details.enterprise_id |  | keyword |
| recordedfuture.playbook_alert.panel_status.owner_organisation_details.enterprise_name |  | keyword |
| recordedfuture.playbook_alert.panel_status.owner_organisation_details.organisations.organisation_id |  | keyword |
| recordedfuture.playbook_alert.panel_status.owner_organisation_details.organisations.organisation_name |  | keyword |
| recordedfuture.playbook_alert.panel_status.priority |  | keyword |
| recordedfuture.playbook_alert.panel_status.reopen |  | keyword |
| recordedfuture.playbook_alert.panel_status.risk_score |  | double |
| recordedfuture.playbook_alert.panel_status.status |  | keyword |
| recordedfuture.playbook_alert.panel_status.targets |  | flattened |
| recordedfuture.playbook_alert.panel_status.targets_str |  | keyword |
| recordedfuture.playbook_alert.panel_status.updated |  | date |
| recordedfuture.playbook_alert.playbook_alert_id |  | keyword |

