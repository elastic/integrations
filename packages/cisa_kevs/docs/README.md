# CISA KEV integration

This integration is for [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) logs. This data can be useful for current awareness of Known Exploited Vulnerabilities according to CISA and also for enriching other vulnerability scan data in the Elastic stack. The integration periodically checks for the latest CISA KEV list. It includes the following datasets for retrieving logs from the CISA KEV website:

- `vulnerability` dataset: Supports vulnerabilities classified as known exploited from CISA.

## Elastic Managed enabled integration

Elastic Managed integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Elastic Managed integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Elastic Managed integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).
Elastic Managed deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Example Enrich Policy and ES|QL Correlation Query

An enrich policy can be created to have other vulnerability information be enriched based on the CVE number.

The following requests can be used to create and execute the enrich policy after the integration has been installed:

```
PUT /_enrich/policy/enrich_cve_with_context_cisa_kev
{
  "match": {
    "indices": ".ds-logs-cisa_kevs.vulnerability-*",
    "match_field": "vulnerability.id",
    "enrich_fields": ["cisa_kev.vulnerability.date_added", "cisa_kev.vulnerability.due_date", "cisa_kev.vulnerability.known_ransomware_campaign_use", "cisa_kev.vulnerability.name", "cisa_kev.vulnerability.notes","cisa_kev.vulnerability.product","cisa_kev.vulnerability.required_action","cisa_kev.vulnerability.vendor_project"]
  }
}

PUT /_enrich/policy/enrich_cve_with_context_cisa_kev/_execute
```

Here is an example ES|QL query that uses the index pattern of logs-nessus.vulnerability* to enrich the data source with CISA KEV information and keeping the top 10 results. Note, the enrich policy (shown above) must be created first:

```
from logs-nessus.vulnerability*
| where vulnerability.id IS NOT NULL
| keep vulnerability.*, nessus.plugin.name, host.name
| enrich enrich_cve_with_context_cisa_kev with cisa_kev.vulnerability.due_date, cisa_kev.vulnerability.known_ransomware_campaign_use, cisa_kev.vulnerability.name, cisa_kev.vulnerability.notes, cisa_kev.vulnerability.product, cisa_kev.vulnerability.required_action, cisa_kev.vulnerability.vendor_project, cisa_kev.vulnerability.date_added
| where cisa_kev.vulnerability.name IS NOT NULL
| stats count = COUNT(host.name) BY nessus.plugin.name, vulnerability.severity, cisa_kev.vulnerability.date_added, cisa_kev.vulnerability.product
| sort count desc
| keep nessus.plugin.name, vulnerability.severity, cisa_kev.vulnerability.product, cisa_kev.vulnerability.date_added, count
| limit 10
```

### Query-time KEV enrichment (LOOKUP JOIN)

The package ships a `latest` transform that maintains the most recent KEV entry per CVE in the lookup index `logs-cisa_kevs_latest.vulnerability`. Unchanged catalog entries are deduplicated at ingest, while updated entries are retained as new source documents, so the raw data stream can hold multiple historical versions of a CVE. The lookup index collapses those versions into the latest row per CVE, making it the preferred enrichment path.

You can enrich vulnerability findings at query time with the ES|QL [`LOOKUP JOIN`](https://www.elastic.co/guide/en/elasticsearch/reference/current/esql-lookup-join.html) command on `vulnerability.id`:

```esql
FROM logs-endpoint.vulnerability-*
| LOOKUP JOIN logs-cisa_kevs_latest.vulnerability ON vulnerability.id
| KEEP vulnerability.id, cisa_kev.vulnerability.date_added, cisa_kev.vulnerability.due_date, cisa_kev.vulnerability.known_ransomware_campaign_use
| WHERE cisa_kev.vulnerability.date_added IS NOT NULL
```

## Upgrading to v1.7.0+

If upgrading from a version of the package before v1.7.0, you will need to re-enter your configuration details and re-enable the package.

## Logs

### Vulnerabilities

The CISA KEV data_stream retrieves vulnerability information from the endpoint `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`.

An example event for `vulnerability` looks as following:

```json
{
    "@timestamp": "2024-02-15T00:00:00.000Z",
    "agent": {
        "ephemeral_id": "a0d090d4-72c3-4da1-9edd-dd1f21f73ea5",
        "id": "56c73d5d-f002-455d-b986-38250ca0f4b5",
        "name": "elastic-agent-16901",
        "type": "filebeat",
        "version": "9.5.4"
    },
    "cisa_kev": {
        "vulnerability": {
            "date_added": "2024-02-15T00:00:00.000Z",
            "due_date": "2024-03-07T00:00:00.000Z",
            "known_ransomware_campaign_use": "Known",
            "name": "Cisco ASA and FTD Information Disclosure Vulnerability",
            "notes": "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-info-disclose-9eJtycMB",
            "product": "Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD)",
            "required_action": "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.",
            "vendor_project": "Cisco"
        }
    },
    "data_stream": {
        "dataset": "cisa_kevs.vulnerability",
        "namespace": "22597",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "56c73d5d-f002-455d-b986-38250ca0f4b5",
        "snapshot": false,
        "version": "9.5.4"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "vulnerability"
        ],
        "dataset": "cisa_kevs.vulnerability",
        "ingested": "2026-10-05T10:41:14Z",
        "kind": "enrichment",
        "module": "cisa_kevs",
        "original": "{\"cveID\":\"CVE-2020-3259\",\"dateAdded\":\"2024-02-15\",\"dueDate\":\"2024-03-07\",\"knownRansomwareCampaignUse\":\"Known\",\"notes\":\"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-info-disclose-9eJtycMB\",\"product\":\"Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD)\",\"requiredAction\":\"Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.\",\"shortDescription\":\"Cisco Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD) contain an information disclosure vulnerability. An attacker could retrieve memory contents on an affected device, which could lead to the disclosure of confidential information due to a buffer tracking issue when the software parses invalid URLs that are requested from the web services interface. This vulnerability affects only specific AnyConnect and WebVPN configurations.\",\"vendorProject\":\"Cisco\",\"vulnerabilityName\":\"Cisco ASA and FTD Information Disclosure Vulnerability\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "labels": {
        "is_transform_source": "true"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "cisa-kev"
    ],
    "vulnerability": {
        "description": "Cisco Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD) contain an information disclosure vulnerability. An attacker could retrieve memory contents on an affected device, which could lead to the disclosure of confidential information due to a buffer tracking issue when the software parses invalid URLs that are requested from the web services interface. This vulnerability affects only specific AnyConnect and WebVPN configurations.",
        "id": "CVE-2020-3259"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| agent.ephemeral_id | Ephemeral identifier of this agent (if one exists). This id normally changes across restarts, but `agent.id` does not. | keyword |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |
| agent.name | Custom name of the agent. This is a name that can be given to an agent. This can be helpful if for example two Filebeat instances are running on the same host but a human readable separation is needed on which Filebeat instance data is coming from. | keyword |
| agent.type | Type of the agent. The agent type always stays the same and should be given by the agent used. In case of Filebeat the agent would always be Filebeat also if two Filebeat instances are run on the same machine. | keyword |
| agent.version | Version of the agent. | keyword |
| cisa_kev.vulnerability.date_added | The date the vulnerability was added to the catalog in the format YYYY-MM-DD | date |
| cisa_kev.vulnerability.due_date | The date the required action is due in the format YYYY-MM-DD | date |
| cisa_kev.vulnerability.known_ransomware_campaign_use | 'Known' if this vulnerability is known to have been leveraged as part of a ransomware campaign; 'Unknown' if CISA lacks confirmation that the vulnerability has been utilized for ransomware | keyword |
| cisa_kev.vulnerability.name | The name of the vulnerability | keyword |
| cisa_kev.vulnerability.notes | Any additional notes about the vulnerability | keyword |
| cisa_kev.vulnerability.product | The vulnerability product | keyword |
| cisa_kev.vulnerability.required_action | The required action to address the vulnerability | keyword |
| cisa_kev.vulnerability.vendor_project | The vendor or project name for the vulnerability | keyword |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.agent_id_status | Agents are normally responsible for populating the `agent.id` field value. If the system receiving events is capable of validating the value based on authentication information for the client then this field can be used to reflect the outcome of that validation. For example if the agent's connection is authenticated with mTLS and the client cert contains the ID of the agent to which the cert was issued then the `agent.id` value in events can be checked against the certificate. If the values match then `event.agent_id_status: verified` is added to the event, otherwise one of the other allowed values should be used. If no validation is performed then the field should be omitted. The allowed values are: `verified` - The `agent.id` field value matches expected value obtained from auth metadata. `mismatch` - The `agent.id` field value does not match the expected value obtained from auth metadata. `missing` - There was no `agent.id` field in the event to validate. `auth_metadata_missing` - There was no auth metadata or it was missing information about the agent ID. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| input.type | Type of Filebeat input. | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| tags | List of keywords used to tag each event. | keyword |
| vulnerability.description | The description of the vulnerability that provides additional context of the vulnerability. For example (https://cve.mitre.org/about/faqs.html#cve_entry_descriptions_created[Common Vulnerabilities and Exposure CVE description]) | keyword |
| vulnerability.description.text | Multi-field of `vulnerability.description`. | match_only_text |
| vulnerability.id | The identification (ID) is the number portion of a vulnerability entry. It includes a unique identification number for the vulnerability. For example (https://cve.mitre.org/about/faqs.html#what_is_cve_id)[Common Vulnerabilities and Exposure CVE ID] | keyword |
