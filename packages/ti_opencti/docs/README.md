# OpenCTI

The OpenCTI integration allows you to ingest data from the [OpenCTI](https://filigran.io/solutions/products/opencti-threat-intelligence/) threat intelligence platform.

Use this integration to get indicator data from OpenCTI. You can monitor and explore the ingested data on the OpenCTI dashboard or in Kibana's Discover tab. Indicator match rules in [Elastic Security](https://www.elastic.co/guide/en/security/current/es-overview.html) can then use the ingested indicator data to generate alerts about detected threats.

## Data streams

The OpenCTI integration collects one type of data stream: logs.

**Logs** are lists of records created over time.
Each event in the log data stream collected by the OpenCTI integration is an indicator that can be used to detect suspicious or malicious cyber activity. The data is fetched from [OpenCTI's GraphQL API](https://docs.opencti.io/latest/deployment/integrations/#graphql-api).

## Requirements

This integration requires Filebeat version 8.9.0, or later.

It has been updated for OpenCTI version 5.12.24 and requires that version or later.

## Setup

For additional information about threat intelligence integrations, including the steps required to add an integration, please refer to the [Enable threat intelligence integrations](https://www.elastic.co/guide/en/security/current/es-threat-intel-integrations.html) page of the Elastic Security documentation.

When adding the OpenCTI integration, you will need to provide a base URL for the target OpenCTI instance. It should be just the base URL (e.g. `https://demo.opencti.io`) and not include an additional path for the API or UI.

The simplest authentication method to use is an API key (bearer token). You can find a value for the API key on your profile page in the OpenCTI user interface. Advanced integration settings can be used to configure various OAuth2-based authentication arrangements, and to enter SSL settings for mTLS authentication and for other purposes. For information on setting up the OpenCTI side of an authentication strategy, please refer to [OpenCTI's authentication documentation](https://docs.opencti.io/latest/deployment/authentication/).

## Logs

### Indicator

The `indicator` data stream includes indicators of the following types (`threat.indicator.type`): `artifact`, `autonomous-system`, `bank-account`, `cryptocurrency-wallet`, `cryptographic-key`, `directory`, `domain-name`, `email-addr`, `email-message`, `email-mime-part-type`, `hostname`, `ipv4-addr`, `ipv6-addr`, `mac-addr`, `media-content`, `mutex`, `network-traffic`, `payment-card`, `phone-number`, `process`, `software`, `file`, `text`, `url`, `user-account`, `user-agent`, `windows-registry-key`, `windows-registry-value-type`, `x509-certificate`, `unknown`.

OpenCTI's data model closely follows the [STIX standard](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html). It supports complex indicators defined using STIX patterns or other languages, and each indicator can be related to one or more observables. In the [ECS threat fields](https://www.elastic.co/guide/en/ecs/current/ecs-threat.html) the focus is on atomic indicators. This integration fetches as much data as possible about indicators and their related observables, and populates relevant ECS fields wherever possible. It uses related observables rather than the indicator pattern as the data source for type-specific indicator fields.

#### Expiration of inactive indicators

The `opencti.indicator.invalid_or_revoked_from` field is set to the earliest time at which an indicator reaches its `valid_until` time or is marked as revoked. From that time the indicator should no longer be considered active.

An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created to provide a view of active indicators for end users. This transform creates destination indices that are accessible via the alias `logs-ti_opencti_latest.indicator`. When querying for active indicators or setting up indicator match rules, use that alias to avoid false positives from expired indicators.

The dashboards show only active indicators, except the Ingestion dashboard, which shows data from both the source data stream and the indices of the latest indicators.

Indicators that are never expired or revoked will not be removed from the indices of the latest indicators. If accumulation of indicators is a problem there, it can be managed upstream in OpenCTI, or by manually deleting indicators from those indices.

To prevent unbounded growth of the source data stream `logs-ti_opencti.indicator-*`, it has an index lifecycle management (ILM) policy that deletes records 5 days after ingestion.

#### Example

Here is an example `indicator` event:

An example event for `indicator` looks as following:

```json
{
    "@timestamp": "2024-06-12T06:54:25.854Z",
    "agent": {
        "ephemeral_id": "de8fc32a-4eaf-4e32-97ae-bcdb93b8d8ee",
        "id": "d2a14a09-96fc-4f81-94ef-b0cd75ad71e7",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "ti_opencti.indicator",
        "namespace": "66338",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "d2a14a09-96fc-4f81-94ef-b0cd75ad71e7",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2018-02-05T08:04:53.000Z",
        "dataset": "ti_opencti.indicator",
        "id": "d019b01c-b637-4eb2-af53-6d527be3193d",
        "ingested": "2024-06-12T06:54:37Z",
        "kind": "enrichment",
        "original": "{\"confidence\":15,\"created\":\"2018-02-05T08:04:53.000Z\",\"createdBy\":{\"identity_class\":\"organization\",\"name\":\"CthulhuSPRL.be\"},\"description\":\"\",\"externalReferences\":{\"edges\":[]},\"id\":\"d019b01c-b637-4eb2-af53-6d527be3193d\",\"is_inferred\":false,\"killChainPhases\":[],\"lang\":\"en\",\"modified\":\"2023-01-17T05:53:42.851Z\",\"name\":\"ec2-23-21-172-164.compute-1.amazonaws.com\",\"objectLabel\":[{\"value\":\"information-credibility-6\"},{\"value\":\"osint\"}],\"objectMarking\":[{\"definition\":\"TLP:GREEN\",\"definition_type\":\"TLP\"}],\"observables\":{\"edges\":[{\"node\":{\"entity_type\":\"Hostname\",\"id\":\"b0a91059-5637-4050-8dce-a976a607f75c\",\"observable_value\":\"ec2-23-21-172-164.compute-1.amazonaws.com\",\"standard_id\":\"hostname--2047cd44-ffae-5b34-b912-5856add59b59\",\"value\":\"ec2-23-21-172-164.compute-1.amazonaws.com\"}}],\"pageInfo\":{\"globalCount\":1}},\"pattern\":\"[hostname:value = 'ec2-23-21-172-164.compute-1.amazonaws.com']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"revoked\":true,\"standard_id\":\"indicator--cde0a6e1-c622-52c4-b857-e9aeac56131b\",\"valid_from\":\"2018-02-05T08:04:53.000Z\",\"valid_until\":\"2019-02-05T08:04:53.000Z\",\"x_opencti_detection\":false,\"x_opencti_main_observable_type\":\"Hostname\",\"x_opencti_score\":40}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "cel"
    },
    "opencti": {
        "indicator": {
            "creator_identity_class": "organization",
            "detection": false,
            "invalid_or_revoked_from": "2019-02-05T08:04:53.000Z",
            "is_inferred": false,
            "lang": "en",
            "observables_count": 1,
            "pattern": "[hostname:value = 'ec2-23-21-172-164.compute-1.amazonaws.com']",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "revoked": true,
            "score": 40,
            "standard_id": "indicator--cde0a6e1-c622-52c4-b857-e9aeac56131b",
            "valid_from": "2018-02-05T08:04:53.000Z",
            "valid_until": "2019-02-05T08:04:53.000Z"
        },
        "observable": {
            "hostname": {
                "entity_type": "Hostname",
                "id": "b0a91059-5637-4050-8dce-a976a607f75c",
                "standard_id": "hostname--2047cd44-ffae-5b34-b912-5856add59b59",
                "value": "ec2-23-21-172-164.compute-1.amazonaws.com"
            }
        }
    },
    "related": {
        "hosts": [
            "ec2-23-21-172-164.compute-1.amazonaws.com"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "opencti-indicator",
        "information-credibility-6",
        "osint",
        "ecs-indicator-detail"
    ],
    "threat": {
        "feed": {
            "dashboard_id": "ti_opencti-83b2bef0-591c-11ee-ba5f-49a63bb985cd",
            "description": "Indicator data from OpenCTI",
            "name": "OpenCTI",
            "reference": "https://docs.opencti.io/latest/usage/overview/"
        },
        "indicator": {
            "confidence": "Low",
            "marking": {
                "tlp": "GREEN"
            },
            "modified_at": "2023-01-17T05:53:42.851Z",
            "name": "ec2-23-21-172-164.compute-1.amazonaws.com",
            "provider": "CthulhuSPRL.be",
            "reference": "http://svc-opencti_stub:8080/dashboard/observations/indicators/d019b01c-b637-4eb2-af53-6d527be3193d",
            "type": "domain-name",
            "url": {
                "domain": "ec2-23-21-172-164.compute-1.amazonaws.com",
                "registered_domain": "ec2-23-21-172-164.compute-1.amazonaws.com",
                "top_level_domain": "compute-1.amazonaws.com"
            }
        }
    }
}
```

#### Exported fields

Fields for indicators of any type are mapped to ECS fields when possible (primarily `threat.indicator.*`) and otherwise stored with a vendor prefix (`opencti.indicator.*`).

Fields for related observables of the various types are always stored under `opencti.observable.<type>.*` and when possible their values will be copied into corresponding ECS fields.

The `related.*` fields will also be populated with any relevant data.

Timestamps are mapped as follows:

| Source      | Destination                   | Description |
|-------------|-------------------------------|-------------|
| -           | @timestamp                    | Time the event was received by the pipeline |
| -           | event.ingested                | Time the event arrived in the central data store |
| created     | event.created                 | Time of the indicator's creation |
| modified    | threat.indicator.modified_at  | Time of the indicator's last modification |
| valid_from  | opencti.indicator.valid_from  | Time from which this indicator is considered a valid indicator of the behaviors it is related to or represents |
| valid_until | opencti.indicator.valid_until | Time at which this indicator should no longer be considered a valid indicator of the behaviors it is related to or represents |
| -           | opencti.indicator.invalid_or_revoked_from | The earliest time at which an indicator reaches its `valid_until` time or is marked as revoked |

The table below lists all `opencti.*` fields.

The documentation for ECS fields can be found at:
- [ECS Event Fields](https://www.elastic.co/guide/en/ecs/current/ecs-event.html)
- [ECS Threat Fields](https://www.elastic.co/guide/en/ecs/current/ecs-threat.html)
- [ECS Related Fields](https://www.elastic.co/guide/en/ecs/current/ecs-related.html)

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Time the event was received by the pipeline. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.agent_id_status | Agents are normally responsible for populating the `agent.id` field value. If the system receiving events is capable of validating the value based on authentication information for the client then this field can be used to reflect the outcome of that validation. For example if the agent's connection is authenticated with mTLS and the client cert contains the ID of the agent to which the cert was issued then the `agent.id` value in events can be checked against the certificate. If the values match then `event.agent_id_status: verified` is added to the event, otherwise one of the other allowed values should be used. If no validation is performed then the field should be omitted. The allowed values are: `verified` - The `agent.id` field value matches expected value obtained from auth metadata. `mismatch` - The `agent.id` field value does not match the expected value obtained from auth metadata. `missing` - There was no `agent.id` field in the event to validate. `auth_metadata_missing` - There was no auth metadata or it was missing information about the agent ID. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| input.type | Input type. | keyword |
| labels.is_ioc_transform_source | Field indicating if the document is a source for the transform. This field is not added to destination indices to facilitate easier filtering of indicators for indicator match rules. | constant_keyword |
| opencti.indicator.creator_identity_class | The type of the creator of this indicator (e.g. "organization"). | keyword |
| opencti.indicator.detection | Whether the indicator has been detected. | boolean |
| opencti.indicator.external_reference.description | A description for a related record in an external system. | keyword |
| opencti.indicator.external_reference.external_id | A non-STIX ID for a related record in an external system. | keyword |
| opencti.indicator.external_reference.source_name | The name of an external source of related records. | keyword |
| opencti.indicator.external_reference.url | A URL for a related record in an external system. | keyword |
| opencti.indicator.invalid_or_revoked_from | A time from which this indicator should be considered invalid or revoked. | date |
| opencti.indicator.is_inferred | Whether the indicator is inferred. | boolean |
| opencti.indicator.kill_chain_phase | The kill chain name and kill change phase name (e.g. "[mitre-attack] exfiltration"). | keyword |
| opencti.indicator.lang | A language associated with the indicator record. | keyword |
| opencti.indicator.observables_count | The number of observables related to this indicator, which may exceed the number fetched. | long |
| opencti.indicator.pattern | The detection pattern for this indicator, expressed as a STIX pattern or using another appropriate language such as SNORT, YARA, etc. | keyword |
| opencti.indicator.pattern_type | The pattern language used in this indicator. | keyword |
| opencti.indicator.pattern_version | The version of the pattern language used in this indicator. | keyword |
| opencti.indicator.revoked | Whether the indicator is revoked. | boolean |
| opencti.indicator.score | An integer score for the indicator. | long |
| opencti.indicator.standard_id | A predictable STIX ID, generated based on one or multiple attributes of the indicator. | keyword |
| opencti.indicator.valid_from | The time from which this indicator is considered a valid indicator of the behaviors it is related to or represents. | date |
| opencti.indicator.valid_until | The time at which this indicator should no longer be considered a valid indicator of the behaviors it is related to or represents. | date |
| opencti.observable.artifact.additional_names | Additional names of the artifact. | keyword |
| opencti.observable.artifact.decryption_key | The decryption key for the encrypted binary data. | keyword |
| opencti.observable.artifact.encryption_algorithm | The type of encryption algorithm the binary data is encoded in, if the artifact is encrypted. | keyword |
| opencti.observable.artifact.entity_type | The observable type. | keyword |
| opencti.observable.artifact.hash.md5 | MD5 hash for the contents of the url or the payload_bin. | keyword |
| opencti.observable.artifact.hash.sha1 | SHA1 hash for the contents of the url or the payload_bin. | keyword |
| opencti.observable.artifact.hash.sha256 | SHA-256 hash for the contents of the url or the payload_bin. | keyword |
| opencti.observable.artifact.hash.sha3_256 | SHA3-256 hash for the contents of the url or the payload_bin. | keyword |
| opencti.observable.artifact.hash.sha3_512 | SHA3-512 hash for the contents of the url or the payload_bin. | keyword |
| opencti.observable.artifact.hash.sha512 | SHA-512 hash for the contents of the url or the payload_bin. | keyword |
| opencti.observable.artifact.hash.ssdeep | SSDEEP hash for the contents of the url or the payload_bin. | keyword |
| opencti.observable.artifact.hash.tlsh | TLSH hash for the contents of the url or the payload_bin. | keyword |
| opencti.observable.artifact.id | The ID of the observable in OpenCTI. | keyword |
| opencti.observable.artifact.mime_type | MIME type of the artifact, given as of the values defined in the Template column in the IANA media type registry, when feasible. | keyword |
| opencti.observable.artifact.payload_bin | The binary data contained in the artifact as a base64-encoded string. | keyword |
| opencti.observable.artifact.standard_id | A predictable STIX ID, generated based on one or multiple attributes of the observable. | keyword |
| opencti.observable.artifact.url | A valid URL that resolves to the unencoded content. | keyword |
| opencti.observable.artifact.value | The main value for the observable. | keyword |
| opencti.observable.autonomous_system.entity_type | The observable type. | keyword |
| opencti.observable.autonomous_system.id | The ID of the observable in OpenCTI. | keyword |
| opencti.observable.autonomous_system.name | The name of the AS. | keyword |
| opencti.observable.autonomous_system.number | The number assigned to the AS, typically by a Regional Internet Registry (RIR). | long |
| opencti.observable.autonomous_system.rir | The name of the Regional Internet Registry (RIR) that assigned the number to the AS. | keyword |
| opencti.observable.autonomous_system.standard_id | A predictable STIX ID, generated based on one or multiple attributes of the observable. | keyword |
| opencti.observable.autonomous_system.value | The main value for the observable. | keyword |
| opencti.observable.bank_account.account_number | A bank account number. | keyword |
| opencti.observable.bank_account.bic | A Bank Identifier Code (BIC). | keyword |
| opencti.observable.bank_account.entity_type | The observable type. | keyword |
| opencti.observable.bank_account.iban | An International Bank Account Number (IBAN). | keyword |
| opencti.observable.bank_account.id | The ID of the observable in OpenCTI. | keyword |
| opencti.observable.bank_account.standard_id | A predictable STIX ID, generated based on one or multiple attributes of the observable. | keyword |
| opencti.observable.bank_account.value | The main value for the observable. | keyword |
| opencti.observable.cryptocurrency_wallet.entity_type | The observable type. | keyword |
| opencti.observable.cryptocurrency_wallet.id | The ID of the observable in OpenCTI. | keyword |
| opencti.observable.cryptocurrency_wallet.standard_id | A predictable STIX ID, generated based on one or multiple attributes of the observable. | keyword |
| opencti.observable.cryptocurrency_wallet.value | A cryptocurrency wallet ID. | keyword |
| opencti.observable.cryptographic_key.entity_type | The observable type. | keyword |
| opencti.observable.cryptographic_key.id | The ID of the observable in OpenCTI. | keyword |
| opencti.observable.cryptographic_key.standard_id | A predictable STIX ID, generated based on one or multiple attributes of the observable. | keyword |
| opencti.observable.cryptographic_key.value | A cryptographic key. | keyword |
| opencti.observable.directory.atime | The date/time the directory was last accessed. | date |
| opencti.observable.directory.ctime | The date/time the directory was created. | date |
| opencti.observable.directory.entity_type | The observable type. | keyword |
| opencti.observable.directory.id | The ID of the observable in OpenCTI. | keyword |
| opencti.observable.directory.mtime | The date/time the directory was last written to/modified. | date |
| opencti.observable.directory.path | The path, as originally observed, to the directory on the file system. | keyword |
| opencti.observable.directory.path_enc | The observed encoding for the path, using the IANA character set registry. | keyword |
| opencti.observable.directory.standard_id | A predictable STIX ID, generated based on one or multiple attributes of the observable. | keyword |
| opencti.observable.directory.value | The main value for the observable. | keyword |
| opencti.observable.domain_name.entity_type | The observable type. | keyword |
| opencti.observable.domain_name.id | The ID of the observable in OpenCTI. | keyword |
| opencti.observable.domain_name.standard_id | A predictable STIX ID, generated based on one or multiple attributes of the observable. | keyword |
| opencti.observable.domain_name.value | The value of the domain name, using RFC1034, RFC5890. | keyword |
| opencti.observable.email_addr.display_name | A single email display name, i.e., the name that is displayed to the human user of a mail application, using RFC5322. | keyword |
| opencti.observable.email_addr.entity_type | The observable type. | keyword |
| opencti.observable.email_addr.id | The ID of the observable in OpenCTI. | keyword |
| opencti.observable.email_addr.standard_id | A predictable STIX ID, generated based on one or multiple attributes of the observable. | keyword |
| opencti.observable.email_addr.value | The value of the email address, using RFC5322. | keyword |
| opencti.observable.email_message.attribute_date | The date/time that the email message was sent. | date |
| opencti.observable.email_message.body | A string containing the email body. | keyword |
| opencti.observable.email_message.content_type | The value of the "Content-Type" header of the email message. | keyword |
| opencti.observable.email_message.entity_type | The observable type. | keyword |
| opencti.observable.email_message.id | The ID of the observable in OpenCTI. | keyword |
| opencti.observable.email_message.is_multipart | Indicates whether the email body contains multiple MIME parts. | boolean |
| opencti.observable.email_message.message_id | The Message-ID field of the email message. | keyword |
| opencti.observable.email_message.received_lines | One or more "Received" header fields that may be included in the email headers. | keyword |
| opencti.observable.email_message.standard_id | A predictable STIX ID, generated based on one or multiple attributes of the observable. | keyword |
| opencti.observable.email_message.subject | The subject of the email message. | keyword |
| opencti.observable.email_message.value | The main value for the observable. | keyword |
| opencti.observable.email_mime_part_type.body | The contents of the MIME part. | keyword |
| opencti.observable.email_mime_part_type.content_disposition | The value of the "Content-Disposition" header field of the MIME part. | keyword |
| opencti.observable.email_mime_part_type.content_type | The value of the "Content-Type" header field of the MIME part. | keyword |
| opencti.observable.email_mime_part_type.entity_type | The observable type. | keyword |
| opencti.observable.email_mime_part_type.id | The ID of the observable in OpenCTI. | keyword |
| opencti.observable.email_mime_part_type.standard_id | A predictable STIX ID, generated based on one or multiple attributes of the observable. | keyword |
| opencti.observable.email_mime_part_type.value | The main value for the observable. | keyword |
| opencti.observable.file.additional_names | Additional names of the file. | keyword |
| opencti.observable.file.atime | The date/time the file was last accessed. | date |
| opencti.observable.file.content.decryption_key | The decryption key for the encrypted binary data. | keyword |
| opencti.observable.file.content.encryption_algorithm | The type of encryption algorithm the binary data is encoded in, if the file is encrypted. | keyword |
| opencti.observable.file.content.payload_bin | The binary data contained in the file as a base64-encoded string. | keyword |
| opencti.observable.file.content.url | A valid URL that resolves to the unencoded content. | keyword |
| opencti.observable.file.ctime | The date/time the file was created. | date |
| opencti.observable.file.entity_type | The observable type. | keyword |
| opencti.observable.file.hash.md5 | MD5 hash for the file. | keyword |
| opencti.observable.file.hash.sha1 | SHA1 hash for the file. | keyword |
| opencti.observable.file.hash.sha256 | SHA-256 hash for the file. | keyword |
| opencti.observable.file.hash.sha3_256 | SHA3-256 hash for the file. | keyword |
| opencti.observable.file.hash.sha3_512 | SHA3-512 hash for the file. | keyword |
| opencti.observable.file.hash.sha512 | SHA-512 hash for the file. | keyword |
| opencti.observable.file.hash.ssdeep | SSDEEP hash for the file. | keyword |
| opencti.observable.file.hash.tlsh | TLSH hash for the file. | keyword |
| opencti.observable.file.id | The ID of the observable in OpenCTI. | keyword |
| opencti.observable.file.magic_number_hex | The hexadecimal constant ("magic number") associated with a specific file format that corresponds to the file, if applicable. | keyword |
| opencti.observable.file.mime_type | MIME type of the file, given as of the values defined in the Template column in the IANA media type registry, when feasible. | keyword |
| opencti.observable.file.mtime | The date/time the file was last written to/modified. | date |
| opencti.observable.file.name | The name of the file. | keyword |
| opencti.observable.file.name_enc | The observed encoding for the name of the file, using the IANA character set registry. | keyword |
| opencti.observable.file.size | The size of the file, in bytes. | long |
| opencti.observable.file.standard_id | A predictable STIX ID, generated based on one or multiple attributes of the observable. | keyword |
| opencti.observable.file.value | The main value for the observable. | keyword |
| opencti.observable.hostname.entity_type | The observable type. | keyword |
| opencti.observable.hostname.id | The ID of the observable in OpenCTI. | keyword |
| opencti.observable.hostname.standard_id | A predictable STIX ID, generated based on one or multiple attributes of the observable. | keyword |
| opencti.observable.hostname.value | A hostname. | keyword |
| opencti.observable.ipv4_addr.entity_type | The observable type. | keyword |
| opencti.observable.ipv4_addr.id | The ID of the observable in OpenCTI. | keyword |
| opencti.observable.ipv4_addr.standard_id | A predictable STIX ID, generated based on one or multiple attributes of the observable. | keyword |
| opencti.observable.ipv4_addr.value | The values of one or more IPv4 addresses expressed using CIDR notation. | keyword |
| opencti.observable.ipv6_addr.entity_type | The observable type. | keyword |
| opencti.observable.ipv6_addr.id | The ID of the observable in OpenCTI. | keyword |
| opencti.observable.ipv6_addr.standard_id | A predictable STIX ID, generated based on one or multiple attributes of the observable. | keyword |
| opencti.observable.ipv6_addr.value | The values of one or more IPv6 addresses expressed using CIDR notation. | keyword |
| opencti.observable.mac_addr.entity_type | The observable type. | keyword |
| opencti.observable.mac_addr.id | The ID of the observable in OpenCTI. | keyword |
| opencti.observable.mac_addr.standard_id | A predictable STIX ID, generated based on one or multiple attributes of the observable. | keyword |
| opencti.observable.mac_addr.value | The value of a single MAC address. | keyword |
| opencti.observable.media_content.content | The content of an item of media content. | keyword |
| opencti.observable.media_content.entity_type | The observable type. | keyword |
| opencti.observable.media_content.id | The ID of the observable in OpenCTI. | keyword |
| opencti.observable.media_content.media_category | The category of an item of media content. | keyword |
| opencti.observable.media_content.publication_date | The publication date of an item of media content. | date |
| opencti.observable.media_content.standard_id | A predictable STIX ID, generated based on one or multiple attributes of the observable. | keyword |
| opencti.observable.media_content.title | The title of an item of media content. | keyword |
| opencti.observable.media_content.url | The URL of an item of media content. | keyword |
| opencti.observable.media_content.value | The main value for the observable. | keyword |
| opencti.observable.mutex.entity_type | The observable type. | keyword |
| opencti.observable.mutex.id | The ID of the observable in OpenCTI. | keyword |
| opencti.observable.mutex.name | The name of the mutex object. | keyword |
| opencti.observable.mutex.standard_id | A predictable STIX ID, generated based on one or multiple attributes of the observable. | keyword |
| opencti.observable.mutex.value | The main value for the observable. | keyword |
| opencti.observable.network_traffic.dst_byte_count | The number of bytes, as a positive integer, sent from the destination to the source. | long |
| opencti.observable.network_traffic.dst_packets | The number of packets, as a positive integer, sent from the destination to the source. | long |
| opencti.observable.network_traffic.dst_port | The destination port used in the network traffic, as an integer. | long |
| opencti.observable.network_traffic.end | The date/time the network traffic ended, if known. | date |
| opencti.observable.network_traffic.entity_type | The observable type. | keyword |
| opencti.observable.network_traffic.id | The ID of the observable in OpenCTI. | keyword |
| opencti.observable.network_traffic.is_active | Indicates whether the network traffic is still ongoing. | boolean |
| opencti.observable.network_traffic.protocols | The protocols observed in the network traffic, along with their corresponding state. | keyword |
| opencti.observable.network_traffic.src_byte_count | The number of bytes, as a positive integer, sent from the source to the destination. | long |
| opencti.observable.network_traffic.src_packets | The number of packets, as a positive integer, sent from the source to the destination. | long |
| opencti.observable.network_traffic.src_port | The source port used in the network traffic, as an integer. | long |
| opencti.observable.network_traffic.standard_id | A predictable STIX ID, generated based on one or multiple attributes of the observable. | keyword |
| opencti.observable.network_traffic.start | The date/time the network traffic was initiated, if known. | date |
| opencti.observable.network_traffic.value | The main value for the observable. | keyword |
| opencti.observable.payment_card.card_number | A payment card number. | keyword |
| opencti.observable.payment_card.cvv | A Card Verification Value (CVV) for a payment card. | keyword |
| opencti.observable.payment_card.entity_type | The observable type. | keyword |
| opencti.observable.payment_card.expiration_date | A payment card expiration date. | date |
| opencti.observable.payment_card.holder_name | The name of a payment card holder. | long |
| opencti.observable.payment_card.id | The ID of the observable in OpenCTI. | keyword |
| opencti.observable.payment_card.standard_id | A predictable STIX ID, generated based on one or multiple attributes of the observable. | keyword |
| opencti.observable.payment_card.value | The main value for the observable. | keyword |
| opencti.observable.phone_number.entity_type | The observable type. | keyword |
| opencti.observable.phone_number.id | The ID of the observable in OpenCTI. | keyword |
| opencti.observable.phone_number.standard_id | A predictable STIX ID, generated based on one or multiple attributes of the observable. | keyword |
| opencti.observable.phone_number.value | A phone number. | keyword |
| opencti.observable.process.aslr_enabled | Whether Address Space Layout Randomization (ASLR) is enabled for the process (on Windows). | boolean |
| opencti.observable.process.command_line | The full command line used in executing the process, including the process name and any arguments. | keyword |
| opencti.observable.process.created_time | The date/time at which the process was created. | date |
| opencti.observable.process.cwd | The current working directory of the process. | keyword |
| opencti.observable.process.dep_enabled | Whether Data Execution Prevention (DEP) is enabled for the process (on Windows). | boolean |
| opencti.observable.process.description | Description of the process. | keyword |
| opencti.observable.process.descriptions | The descriptions defined for the (Windows) service. | keyword |
| opencti.observable.process.display_name | The display name of the service in Windows GUI controls. | keyword |
| opencti.observable.process.entity_type | The observable type. | keyword |
| opencti.observable.process.environment_variables | The list of environment variables associated with the process. | keyword |
| opencti.observable.process.group_name | The name of the load ordering group of which the (Windows) service is a member. | keyword |
| opencti.observable.process.id | The ID of the observable in OpenCTI. | keyword |
| opencti.observable.process.integrity_level | The Windows integrity level, or trustworthiness, of the process. | keyword |
| opencti.observable.process.is_hidden | Whether the process is hidden. | boolean |
| opencti.observable.process.owner_sid | The Security ID (SID) value of the owner of the process (on Windows). | keyword |
| opencti.observable.process.pid | The Process ID, or PID, of the process. | long |
| opencti.observable.process.priority | The current priority class of the process in Windows. | keyword |
| opencti.observable.process.service_dll.additional_names | Additional names of the service DLL file. | keyword |
| opencti.observable.process.service_dll.atime | The date/time the service DLL file was last accessed. | date |
| opencti.observable.process.service_dll.content.decryption_key | The decryption key for the encrypted binary data of the service DLL file. | keyword |
| opencti.observable.process.service_dll.content.encryption_algorithm | The type of encryption algorithm the binary data is encoded in, if the service DLL file is encrypted. | keyword |
| opencti.observable.process.service_dll.content.payload_bin | The binary data contained in the service DLL file as a base64-encoded string. | keyword |
| opencti.observable.process.service_dll.content.url | A valid URL that resolves to the unencoded content of the service DLL file. | keyword |
| opencti.observable.process.service_dll.ctime | The date/time the service DLL file was created. | date |
| opencti.observable.process.service_dll.hash.md5 | MD5 hash for the service DLL file. | keyword |
| opencti.observable.process.service_dll.hash.sha1 | SHA1 hash for the service DLL file. | keyword |
| opencti.observable.process.service_dll.hash.sha256 | SHA-256 hash for the service DLL file. | keyword |
| opencti.observable.process.service_dll.hash.sha3_256 | SHA3-256 hash for the service DLL file. | keyword |
| opencti.observable.process.service_dll.hash.sha3_512 | SHA3-512 hash for the service DLL file. | keyword |
| opencti.observable.process.service_dll.hash.sha512 | SHA-512 hash for the service DLL file. | keyword |
| opencti.observable.process.service_dll.hash.ssdeep | SSDEEP hash for the service DLL file. | keyword |
| opencti.observable.process.service_dll.hash.tlsh | TLSH hash for the service DLL file. | keyword |
| opencti.observable.process.service_dll.magic_number_hex | The hexadecimal constant ("magic number") associated with a specific file format that corresponds to the service DLL file, if applicable. | keyword |
| opencti.observable.process.service_dll.mime_type | MIME type of the service DLL file, given as of the values defined in the Template column in the IANA media type registry, when feasible. | keyword |
| opencti.observable.process.service_dll.mtime | The date/time the service DLL file was last written to/modified. | date |
| opencti.observable.process.service_dll.name | The name of the service DLL file. | keyword |
| opencti.observable.process.service_dll.name_enc | The observed encoding for the name of the service DLL file, using the IANA character set registry. | keyword |
| opencti.observable.process.service_dll.size | The size of the service DLL file, in bytes. | long |
| opencti.observable.process.service_name | The name of the (Windows) service. | keyword |
| opencti.observable.process.service_status | The type of the (Windows) service. | keyword |
| opencti.observable.process.service_type | The DLLs loaded by the (Windows) service, as a reference to one or more File objects. | keyword |
| opencti.observable.process.standard_id | A predictable STIX ID, generated based on one or multiple attributes of the observable. | keyword |
| opencti.observable.process.start_type | The start options defined for the (Windows) service. | keyword |
| opencti.observable.process.startup_info | The STARTUP_INFO struct used by the process (on Windows). | flattened |
| opencti.observable.process.value | The main value for the observable. | keyword |
| opencti.observable.process.window_title | The title of the main window of the process (on Windows). | keyword |
| opencti.observable.software.cpe | The Common Platform Enumeration (CPE) entry for the software, if available. | keyword |
| opencti.observable.software.entity_type | The observable type. | keyword |
| opencti.observable.software.id | The ID of the observable in OpenCTI. | keyword |
| opencti.observable.software.languages | The languages supported by the software, using RFC5646. | keyword |
| opencti.observable.software.name | The name of the software. | keyword |
| opencti.observable.software.standard_id | A predictable STIX ID, generated based on one or multiple attributes of the observable. | keyword |
| opencti.observable.software.swid | The Software Identification (SWID) Tags entry for the software, if available. | keyword |
| opencti.observable.software.value | The main value for the observable. | keyword |
| opencti.observable.software.vendor | The name of the vendor of the software. | keyword |
| opencti.observable.software.version | The version of the software. | keyword |
| opencti.observable.text.entity_type | The observable type. | keyword |
| opencti.observable.text.id | The ID of the observable in OpenCTI. | keyword |
| opencti.observable.text.standard_id | A predictable STIX ID, generated based on one or multiple attributes of the observable. | keyword |
| opencti.observable.text.value | Text. | keyword |
| opencti.observable.url.entity_type | The observable type. | keyword |
| opencti.observable.url.id | The ID of the observable in OpenCTI. | keyword |
| opencti.observable.url.standard_id | A predictable STIX ID, generated based on one or multiple attributes of the observable. | keyword |
| opencti.observable.url.value | The value of the URL, using RFC3986. | keyword |
| opencti.observable.user_account.account_created | When the account was created. | date |
| opencti.observable.user_account.account_expires | The expiration date of the account. | date |
| opencti.observable.user_account.account_first_login | When the account was first accessed. | date |
| opencti.observable.user_account.account_last_login | When the account was last accessed. | date |
| opencti.observable.user_account.account_login | The account login string, where it differs from the user_id. | keyword |
| opencti.observable.user_account.account_type | The type of the account. | keyword |
| opencti.observable.user_account.can_escalate_privs | That the account has the ability to escalate privileges. | boolean |
| opencti.observable.user_account.credential | A cleartext credential, not PII. | keyword |
| opencti.observable.user_account.credential_last_changed | When the account credential was last changed. | date |
| opencti.observable.user_account.display_name | The display name of the account, to be shown in user interfaces, if applicable. | keyword |
| opencti.observable.user_account.entity_type | The observable type. | keyword |
| opencti.observable.user_account.id | The ID of the observable in OpenCTI. | keyword |
| opencti.observable.user_account.is_disabled | If the account is disabled. | boolean |
| opencti.observable.user_account.is_privileged | That the account has elevated privileges. | boolean |
| opencti.observable.user_account.is_service_account | Indicates that the account is associated with a network service or system process (daemon), not a specific individual. | boolean |
| opencti.observable.user_account.standard_id | A predictable STIX ID, generated based on one or multiple attributes of the observable. | keyword |
| opencti.observable.user_account.user_id | The identifier of the account and may be a numeric ID, a GUID, an account name, an email address, etc. | keyword |
| opencti.observable.user_account.value | The main value for the observable. | keyword |
| opencti.observable.user_agent.entity_type | The observable type. | keyword |
| opencti.observable.user_agent.id | The ID of the observable in OpenCTI. | keyword |
| opencti.observable.user_agent.standard_id | A predictable STIX ID, generated based on one or multiple attributes of the observable. | keyword |
| opencti.observable.user_agent.value | An HTTP User-Agent string. | keyword |
| opencti.observable.windows_registry_key.attribute_key | The full registry key including the hive. | keyword |
| opencti.observable.windows_registry_key.entity_type | The observable type. | keyword |
| opencti.observable.windows_registry_key.id | The ID of the observable in OpenCTI. | keyword |
| opencti.observable.windows_registry_key.modified_time | The last date/time that the registry key was modified. | date |
| opencti.observable.windows_registry_key.number_of_subkeys | The number of subkeys contained under the registry key. | long |
| opencti.observable.windows_registry_key.standard_id | A predictable STIX ID, generated based on one or multiple attributes of the observable. | keyword |
| opencti.observable.windows_registry_key.value | The main value for the observable. | keyword |
| opencti.observable.windows_registry_value_type.data | The data contained in the registry value. | keyword |
| opencti.observable.windows_registry_value_type.data_type | The registry (REG_\*) data type used in the registry value. | keyword |
| opencti.observable.windows_registry_value_type.entity_type | The observable type. | keyword |
| opencti.observable.windows_registry_value_type.id | The ID of the observable in OpenCTI. | keyword |
| opencti.observable.windows_registry_value_type.name | The name of the registry value. | keyword |
| opencti.observable.windows_registry_value_type.standard_id | A predictable STIX ID, generated based on one or multiple attributes of the observable. | keyword |
| opencti.observable.windows_registry_value_type.value | The main value for the observable. | keyword |
| opencti.observable.x509_certificate.authority_key_identifier | The identifier that provides a means of identifying the public key corresponding to the private key used to sign a certificate. | keyword |
| opencti.observable.x509_certificate.basic_constraints | A multi-valued extension which indicates whether a certificate is a CA certificate. | keyword |
| opencti.observable.x509_certificate.certificate_policies | A sequence of one or more policy information terms, each of which consists of an object identifier (OID) and optional qualifiers. | keyword |
| opencti.observable.x509_certificate.crl_distribution_points | How CRL information is obtained. | keyword |
| opencti.observable.x509_certificate.entity_type | The observable type. | keyword |
| opencti.observable.x509_certificate.extended_key_usage | A list of usages indicating purposes for which the certificate public key can be used for. | keyword |
| opencti.observable.x509_certificate.hash.md5 | MD5 hash calculated for the entire contents of the certificate. | keyword |
| opencti.observable.x509_certificate.hash.sha1 | SHA1 hash calculated for the entire contents of the certificate. | keyword |
| opencti.observable.x509_certificate.hash.sha256 | SHA-256 hash calculated for the entire contents of the certificate. | keyword |
| opencti.observable.x509_certificate.hash.sha3_256 | SHA3-256 hash calculated for the entire contents of the certificate. | keyword |
| opencti.observable.x509_certificate.hash.sha3_512 | SHA3-512 hash calculated for the entire contents of the certificate. | keyword |
| opencti.observable.x509_certificate.hash.sha512 | SHA-512 hash calculated for the entire contents of the certificate. | keyword |
| opencti.observable.x509_certificate.hash.ssdeep | SSDEEP hash calculated for the entire contents of the certificate. | keyword |
| opencti.observable.x509_certificate.hash.tlsh | TLSH hash calculated for the entire contents of the certificate. | keyword |
| opencti.observable.x509_certificate.id | The ID of the observable in OpenCTI. | keyword |
| opencti.observable.x509_certificate.inhibit_any_policy | The number of additional certificates that may appear in the path before anyPolicy is no longer permitted. | keyword |
| opencti.observable.x509_certificate.is_self_signed | Whether the certificate is self-signed, i.e., whether it is signed by the same entity whose identity it certifies. | boolean |
| opencti.observable.x509_certificate.issuer | The name of the Certificate Authority that issued the certificate. | keyword |
| opencti.observable.x509_certificate.issuer_alternative_name | The additional identities to be bound to the issuer of the certificate. | keyword |
| opencti.observable.x509_certificate.key_usage | A multi-valued extension consisting of a list of names of the permitted key usages. | keyword |
| opencti.observable.x509_certificate.name_constraints | A namespace within which all subject names in subsequent certificates in a certification path are located. | keyword |
| opencti.observable.x509_certificate.policy_constraints | Any constraints on path validation for certificates issued to CAs. | keyword |
| opencti.observable.x509_certificate.policy_mappings | One or more pairs of OIDs; each pair includes an issuerDomainPolicy and a subjectDomainPolicy. | keyword |
| opencti.observable.x509_certificate.private_key_usage_period_not_after | The date on which the validity period ends for the private key, if it is different from the validity period of the certificate. | date |
| opencti.observable.x509_certificate.private_key_usage_period_not_before | The date on which the validity period begins for the private key, if it is different from the validity period of the certificate. | date |
| opencti.observable.x509_certificate.serial_number | The unique identifier for the certificate, as issued by a specific Certificate Authority. | keyword |
| opencti.observable.x509_certificate.signature_algorithm | The name of the algorithm used to sign the certificate. | keyword |
| opencti.observable.x509_certificate.standard_id | A predictable STIX ID, generated based on one or multiple attributes of the observable. | keyword |
| opencti.observable.x509_certificate.subject | The name of the entity associated with the public key stored in the subject public key field of the certificate. | keyword |
| opencti.observable.x509_certificate.subject_alternative_name | The additional identities to be bound to the subject of the certificate. | keyword |
| opencti.observable.x509_certificate.subject_directory_attributes | The identification attributes (e.g., nationality) of the subject. | keyword |
| opencti.observable.x509_certificate.subject_key_identifier | The identifier that provides a means of identifying certificates that contain a particular public key. | keyword |
| opencti.observable.x509_certificate.subject_public_key_algorithm | The name of the algorithm with which to encrypt data being sent to the subject. | keyword |
| opencti.observable.x509_certificate.subject_public_key_exponent | The exponent portion of the subject’s public RSA key, as an integer. | long |
| opencti.observable.x509_certificate.subject_public_key_modulus | The modulus portion of the subject’s public RSA key. | keyword |
| opencti.observable.x509_certificate.validity_not_after | The date on which the certificate validity period ends. | date |
| opencti.observable.x509_certificate.validity_not_before | The date on which the certificate validity period begins. | date |
| opencti.observable.x509_certificate.value | The main value for the observable. | keyword |
| opencti.observable.x509_certificate.version | The version of the encoded certificate. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| threat.feed.dashboard_id | The saved object ID of the dashboard belonging to the threat feed for displaying dashboard links to threat feeds in Kibana. | keyword |
| threat.feed.description | Description of the threat feed in a UI friendly format. | keyword |
| threat.feed.name | The name of the threat feed in UI friendly format. | keyword |
| threat.feed.reference | Reference information for the threat feed in a UI friendly format. | keyword |
| threat.indicator.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| threat.indicator.as.organization.name | Organization name. | keyword |
| threat.indicator.as.organization.name.text | Multi-field of `threat.indicator.as.organization.name`. | match_only_text |
| threat.indicator.confidence | Identifies the vendor-neutral confidence rating using the None/Low/Medium/High scale defined in Appendix A of the STIX 2.1 framework. Vendor-specific confidence scales may be added as custom fields. | keyword |
| threat.indicator.description | Describes the type of action conducted by the threat. | keyword |
| threat.indicator.email.address | Identifies a threat indicator as an email address (irrespective of direction). | keyword |
| threat.indicator.file.accessed | Last time the file was accessed. Note that not all filesystems keep track of access time. | date |
| threat.indicator.file.created | File creation time. Note that not all filesystems store the creation time. | date |
| threat.indicator.file.directory | Directory where the file is located. It should include the drive letter, when appropriate. | keyword |
| threat.indicator.file.drive_letter | Drive letter where the file is located. This field is only relevant on Windows. The value should be uppercase, and not include the colon. | keyword |
| threat.indicator.file.extension | File extension, excluding the leading dot. Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| threat.indicator.file.hash.md5 | MD5 hash. | keyword |
| threat.indicator.file.hash.sha1 | SHA1 hash. | keyword |
| threat.indicator.file.hash.sha256 | SHA256 hash. | keyword |
| threat.indicator.file.hash.sha384 | SHA384 hash. | keyword |
| threat.indicator.file.hash.sha3_256 | SHA3-256 hash. | keyword |
| threat.indicator.file.hash.sha3_512 | SHA3-512 hash. | keyword |
| threat.indicator.file.hash.sha512 | SHA512 hash. | keyword |
| threat.indicator.file.hash.ssdeep | SSDEEP hash. | keyword |
| threat.indicator.file.hash.tlsh | TLSH hash. | keyword |
| threat.indicator.file.mime_type | MIME type should identify the format of the file or stream of bytes using https://www.iana.org/assignments/media-types/media-types.xhtml[IANA official types], where possible. When more than one type is applicable, the most specific type should be used. | keyword |
| threat.indicator.file.mtime | Last time the file content was modified. | date |
| threat.indicator.file.name | Name of the file including the extension, without the directory. | keyword |
| threat.indicator.file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| threat.indicator.file.path.text | Multi-field of `threat.indicator.file.path`. | match_only_text |
| threat.indicator.file.size | File size in bytes. Only relevant when `file.type` is "file". | long |
| threat.indicator.file.type | File type (file, dir, or symlink). | keyword |
| threat.indicator.ip | Identifies a threat indicator as an IP address (irrespective of direction). | ip |
| threat.indicator.marking.tlp | Traffic Light Protocol sharing markings. | keyword |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |
| threat.indicator.name | The display name indicator in an UI friendly format | keyword |
| threat.indicator.port | Identifies a threat indicator as a port number (irrespective of direction). | long |
| threat.indicator.provider | The name of the indicator's provider. | keyword |
| threat.indicator.reference | Reference URL linking to additional information about this indicator. | keyword |
| threat.indicator.registry.data.bytes | Original bytes written with base64 encoding. For Windows registry operations, such as SetValueEx and RegQueryValueEx, this corresponds to the data pointed by `lp_data`. This is optional but provides better recoverability and should be populated for REG_BINARY encoded values. | keyword |
| threat.indicator.registry.data.strings | Content when writing string types. Populated as an array when writing string data to the registry. For single string registry types (REG_SZ, REG_EXPAND_SZ), this should be an array with one string. For sequences of string with REG_MULTI_SZ, this array will be variable length. For numeric data, such as REG_DWORD and REG_QWORD, this should be populated with the decimal representation (e.g `"1"`). | wildcard |
| threat.indicator.registry.data.type | Standard registry type for encoding contents | keyword |
| threat.indicator.registry.hive | Abbreviated name for the hive. | keyword |
| threat.indicator.registry.key | Hive-relative path of keys. | keyword |
| threat.indicator.registry.path | Full path, including hive, key and value | keyword |
| threat.indicator.registry.value | Name of the value written. | keyword |
| threat.indicator.type | Type of indicator as represented by Cyber Observable in STIX 2.1 or OpenCTI | keyword |
| threat.indicator.url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| threat.indicator.url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| threat.indicator.url.fragment | Portion of the url after the `#`, such as "top". The `#` is not part of the fragment. | keyword |
| threat.indicator.url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | wildcard |
| threat.indicator.url.full.text | Multi-field of `threat.indicator.url.full`. | match_only_text |
| threat.indicator.url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| threat.indicator.url.original.text | Multi-field of `threat.indicator.url.original`. | match_only_text |
| threat.indicator.url.password | Password of the request. | keyword |
| threat.indicator.url.path | Path of the request, such as "/search". | wildcard |
| threat.indicator.url.port | Port of the request, such as 443. | long |
| threat.indicator.url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| threat.indicator.url.registered_domain | The highest registered url domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| threat.indicator.url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| threat.indicator.url.subdomain | The subdomain portion of a fully qualified domain name includes all of the names except the host name under the registered_domain.  In a partially qualified domain, or if the the qualification level of the full name cannot be determined, subdomain contains all of the names below the registered domain. For example the subdomain portion of "www.east.mydomain.co.uk" is "east". If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| threat.indicator.url.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| threat.indicator.url.username | Username of the request. | keyword |
| threat.indicator.x509.alternative_names | List of subject alternative names (SAN). Name types vary by certificate authority and certificate type but commonly contain IP addresses, DNS names (and wildcards), and email addresses. | keyword |
| threat.indicator.x509.issuer.common_name | List of common name (CN) of issuing certificate authority. | keyword |
| threat.indicator.x509.not_after | Time at which the certificate is no longer considered valid. | date |
| threat.indicator.x509.not_before | Time at which the certificate is first considered valid. | date |
| threat.indicator.x509.public_key_algorithm | Algorithm used to generate the public key. | keyword |
| threat.indicator.x509.public_key_exponent | Exponent used to derive the public key. This is algorithm specific. | long |
| threat.indicator.x509.serial_number | Unique serial number issued by the certificate authority. For consistency, if this value is alphanumeric, it should be formatted without colons and uppercase characters. | keyword |
| threat.indicator.x509.signature_algorithm | Identifier for certificate signature algorithm. We recommend using names found in Go Lang Crypto library. See https://github.com/golang/go/blob/go1.14/src/crypto/x509/x509.go#L337-L353. | keyword |
| threat.indicator.x509.subject.common_name | List of common names (CN) of subject. | keyword |
| threat.indicator.x509.version_number | Version of x509 format. | keyword |

