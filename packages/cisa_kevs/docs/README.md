# CISA KEV integration

This integration is for [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) logs. This data can be useful for current awareness of Known Exploited Vulnerabilities according to CISA and also for enriching other vulnerability scan data in the Elastic stack. The integration periodically checks for the latest CISA KEV list. It includes the following datasets for retrieving logs from the CISA KEV website:

- `vulnerability` dataset: Supports vulnerabilities classified as known exploited from CISA.

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

## Logs

### Vulnerabilities

The CISA KEV data_stream retrieves vulnerability information from the endpoint `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`.

An example event for `vulnerability` looks as following:

```json
{
    "@timestamp": "2024-02-15T00:00:00.000Z",
    "agent": {
        "ephemeral_id": "39957f93-aff4-4e3f-84f0-66d18441ccd6",
        "id": "7edf8be5-ad5d-4c57-a6bd-b86bddc66601",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.2"
    },
    "cisa_kev": {
        "vulnerability": {
            "date_added": "2024-02-15",
            "due_date": "2024-03-07",
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
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "7edf8be5-ad5d-4c57-a6bd-b86bddc66601",
        "snapshot": false,
        "version": "8.12.2"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "vulnerability"
        ],
        "created": "2024-03-13T01:01:09.893Z",
        "dataset": "cisa_kevs.vulnerability",
        "ingested": "2024-03-13T01:01:21Z",
        "kind": "enrichment",
        "original": "{\"cveID\":\"CVE-2020-3259\",\"dateAdded\":\"2024-02-15\",\"dueDate\":\"2024-03-07\",\"knownRansomwareCampaignUse\":\"Known\",\"notes\":\"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-info-disclose-9eJtycMB\",\"product\":\"Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD)\",\"requiredAction\":\"Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.\",\"shortDescription\":\"Cisco Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD) contain an information disclosure vulnerability. An attacker could retrieve memory contents on an affected device, which could lead to the disclosure of confidential information due to a buffer tracking issue when the software parses invalid URLs that are requested from the web services interface. This vulnerability affects only specific AnyConnect and WebVPN configurations.\",\"vendorProject\":\"Cisco\",\"vulnerabilityName\":\"Cisco ASA and FTD Information Disclosure Vulnerability\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "httpjson"
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
| @timestamp | Event timestamp. | date |
| cisa_kev.vulnerability.date_added | The date the vulnerability was added to the catalog in the format YYYY-MM-DD | date |
| cisa_kev.vulnerability.due_date | The date the required action is due in the format YYYY-MM-DD | date |
| cisa_kev.vulnerability.known_ransomware_campaign_use | 'Known' if this vulnerability is known to have been leveraged as part of a ransomware campaign; 'Unknown' if CISA lacks confirmation that the vulnerability has been utilized for ransomware | keyword |
| cisa_kev.vulnerability.name | The name of the vulnerability | keyword |
| cisa_kev.vulnerability.notes | Any additional notes about the vulnerability | keyword |
| cisa_kev.vulnerability.product | The vulnerability product | keyword |
| cisa_kev.vulnerability.required_action | The required action to address the vulnerability | keyword |
| cisa_kev.vulnerability.vendor_project | The vendor or project name for the vulnerability | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| input.type | Type of Filebeat input. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| vulnerability.description | The description of the vulnerability that provides additional context of the vulnerability. For example (https://cve.mitre.org/about/faqs.html#cve_entry_descriptions_created[Common Vulnerabilities and Exposure CVE description]) | keyword |
| vulnerability.description.text | Multi-field of `vulnerability.description`. | match_only_text |
| vulnerability.id | The identification (ID) is the number portion of a vulnerability entry. It includes a unique identification number for the vulnerability. For example (https://cve.mitre.org/about/faqs.html#what_is_cve_id)[Common Vulnerabilities and Exposure CVE ID] | keyword |
