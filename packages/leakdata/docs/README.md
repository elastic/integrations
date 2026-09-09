# LeakData Exposure Monitoring integration

Bring verified breach-exposure alerts into Elastic Security without copying the underlying personal data into your SIEM. Elastic Agent collects alerts from LeakData and maps them to Elastic Common Schema (ECS).

Each alert provides a severity, a finding count, an event ID and timestamps. Use these signals to prioritize an investigation in LeakData alongside your other security telemetry. An exposure alert does not establish that an account has been compromised.

## Requirements

- Elastic Stack 9.3.1 or later within the supported 9.x range, with Fleet and Elastic Agent.
- An active LeakData account with SIEM integration access.
- A personal-email monitor with confirmed ownership and monitoring enabled.

Your LeakData plan and Elastic deployment requirements apply separately. [Explore LeakData](https://leakdata.io/integrations/elastic-security) or [view plans](https://leakdata.io/pricing).

## Data and verification boundary

LeakData releases an alert only when an active personal-email monitor still has exact ownership verification, every represented source remains verified at the configured `high` or `critical` threshold, and the account still has the SIEM integration entitlement.

The feed does not include an email address, monitor identifier, breach/source name, source URL, credential, password, exposed value, raw record, or `event.original`.

## Setup

1. In the LeakData dashboard, create an Elastic Security connector and choose the exposure threshold you want to monitor.
2. Copy the connector token when it is shown. You will use it to connect Elastic Agent.
3. Add this integration to a Fleet agent policy. Keep the default LeakData URL and paste the token into **Connector token**. Fleet stores this setting as a secret.
4. Leave the poll interval at five minutes, or adjust it to suit your workflow. Keep the `forwarded` tag; you can add your own tags.
5. After LeakData detects a new eligible exposure, use Discover to check `logs-leakdata.exposure-*` for the alert.

An empty feed can be expected when there are no new eligible alerts. Check that the monitor is active, its email ownership remains verified and your account still has SIEM integration access before investigating the connection.

## Logs reference

### exposure

An example event for `exposure` looks as following:

```json
{
    "@timestamp": "2026-08-14T10:00:00.000Z",
    "agent": {
        "ephemeral_id": "11111111-1111-4111-8111-111111111111",
        "id": "22222222-2222-4222-8222-222222222222",
        "name": "elastic-agent-example",
        "type": "filebeat",
        "version": "9.3.1"
    },
    "cloud": {
        "account": {
            "id": "33333333-3333-4333-8333-333333333333"
        },
        "availability_zone": "",
        "instance": {
            "id": "44444444-4444-4444-8444-444444444444",
            "name": "example-runner"
        },
        "machine": {
            "type": "Standard_D4ads_v5"
        },
        "provider": "azure",
        "region": "westus",
        "service": {
            "name": "Virtual Machines"
        }
    },
    "data_stream": {
        "dataset": "leakdata.exposure",
        "namespace": "default",
        "type": "logs"
    },
    "ecs": {
        "version": "9.4.0"
    },
    "elastic_agent": {
        "id": "22222222-2222-4222-8222-222222222222",
        "snapshot": false,
        "version": "9.3.1"
    },
    "event": {
        "action": "verified-exposure-detected",
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2026-08-14T10:00:00.000Z",
        "dataset": "leakdata.exposure",
        "id": "leakdata-synthetic-page-1",
        "ingested": "2026-08-14T10:00:01Z",
        "kind": "alert",
        "module": "leakdata",
        "risk_score": 90,
        "risk_score_norm": 90,
        "severity": 90,
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "cel"
    },
    "leakdata": {
        "exposure": {
            "contains_personal_data": false,
            "evidence_scope": "verified_source_and_verified_email_ownership",
            "finding_count": 2,
            "maximum_severity": "critical",
            "minimum_severity": "high"
        }
    },
    "message": "LeakData detected 2 new verified exposure sources at or above the configured threshold. This event contains no monitored identity, source name, credential, exposed value, or raw record.",
    "observer": {
        "product": "Exposure Monitoring",
        "type": "saas",
        "vendor": "LeakData"
    },
    "rule": {
        "category": "Data Exposure",
        "id": "leakdata-verified-exposure-v1",
        "name": "Verified identity exposure",
        "ruleset": "LeakData verified exposure policy",
        "version": "1"
    },
    "tags": [
        "forwarded",
        "leakdata",
        "secops",
        "verified-exposure",
        "privacy-minimized"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of Elastic Agent input that collected the event. | keyword |
| leakdata.exposure.contains_personal_data | Always false for this privacy-minimized feed. | boolean |
| leakdata.exposure.evidence_scope | Verification boundary used before the alert was released. | keyword |
| leakdata.exposure.finding_count | Number of newly verified sources represented by this alert. | long |
| leakdata.exposure.maximum_severity | Highest severity represented by this alert. | keyword |
| leakdata.exposure.minimum_severity | Minimum severity configured for this connector. | keyword |


Version `0.1.0` is a submission candidate and is not represented as Elastic-reviewed or published.

For setup and account questions, contact [support@leakdata.io](mailto:support@leakdata.io). Report security issues privately to [security@leakdata.io](mailto:security@leakdata.io).
