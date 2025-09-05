# Bitsight Integration

This integration collects data from the Bitsight API.

## Data Streams

- **bitsight.vulnerability** — Pulls vulnerabilities with the related company exposures, and evidence items.

## Requirements

- Elasticsearch & Kibana ≥ 8.17.3
- Bitsight API Token

## Setup

1. Install the integration in Kibana.
2. Provide the Bitsight API Base URL and API Token.
3. Configure the polling interval, batch size, and lookback interval for initial data collection.

## Logs

### Vulnerability

This is the `vulnerability` dataset.

An example event for `vulnerability` looks as following:

```json
{
    "@timestamp": "2025-03-01T00:00:00.000Z",
    "bitsight": {
        "company": {
            "company_guid": "aaaa0000-bbbb-cccc-dddd-eeeeeeeeeeee",
            "company_name": "ExampleTech AG",
            "detection_types": [
                "standard"
            ],
            "evidence_certainty": "LIKELY",
            "evidence_tags": [
                {
                    "name": "Long time since last detection",
                    "slug": "LONG_TIME_SINCE_LAST_DETECTION"
                }
            ],
            "exposure_detection": "MITIGATED",
            "first_seen_date": "2025-02-03",
            "last_seen_date": "2025-03-01",
            "logo": "https://service.bitsighttech.com/customer-api/ratings/v1/companies/aaaa0000-bbbb-cccc-dddd-eeeeeeeeeeee/logo-image"
        },
        "evidence": {
            "certainty": "LIKELY",
            "detection_type": "standard",
            "evidence_tag": {
                "name": "Long time since last detection",
                "slug": "LONG_TIME_SINCE_LAST_DETECTION"
            },
            "exposure_detection": "MITIGATED",
            "first_seen_date": "2025-02-03",
            "identifier": "203.0.113.42:443",
            "last_seen_date": "2025-03-01"
        },
        "threat": {
            "category": {
                "name": "vulnerability",
                "slug": "vulnerability"
            },
            "dve": {
                "highest_score": 1.5,
                "highest_score_date": "2022-06-12T00:00:00",
                "score": 0.76
            },
            "epss": {
                "percentile": 80.9,
                "score": 1.6
            },
            "evidence_certainty": "LIKELY",
            "exposed_count": 0,
            "exposure_trend": -1,
            "first_seen_date": "2025-02-03",
            "guid": "11111111-aaaa-bbbb-cccc-222222222222",
            "last_seen_date": "2025-03-01",
            "mitigated_count": 1,
            "name": "CVE-2023-12345",
            "severity": {
                "details": "CVSS 6.1",
                "level": "Moderate"
            },
            "support_started_date": "2023-07-28"
        }
    },
    "host": {
        "ip": [
            "203.0.113.42"
        ]
    },
    "vulnerability": {
        "id": "CVE-2023-12345",
        "scanner": {
            "vendor": "Bitsight"
        },
        "score": {
            "base": 6.1
        },
        "severity": "Medium"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| bitsight.company.company_guid | Company GUID | keyword |
| bitsight.company.company_name | Company name | keyword |
| bitsight.company.detection_types | How the data was collected | keyword |
| bitsight.company.evidence_certainty | Certainty level of the company's evidence | keyword |
| bitsight.company.evidence_tags.name | Evidence tag name | keyword |
| bitsight.company.evidence_tags.slug | Evidence tag slug | keyword |
| bitsight.company.exposure_detection | Company's exposure detection status | keyword |
| bitsight.company.first_seen_date | Date when this threat first affected the company | date |
| bitsight.company.last_seen_date | Date when this threat was last seen for the company | date |
| bitsight.company.logo | URL of the company logo | keyword |
| bitsight.company.tier | Tier the company belongs to (Identifier) | keyword |
| bitsight.company.tier_name | Tier name (Human readable) | keyword |
| bitsight.evidence.certainty | Certainty level of this evidence | keyword |
| bitsight.evidence.detection_type | How the evidence was collected | keyword |
| bitsight.evidence.evidence_tag.name | Evidence tag name | keyword |
| bitsight.evidence.evidence_tag.slug | Evidence tag slug | keyword |
| bitsight.evidence.exposure_detection | Exposure detection status for this evidence | keyword |
| bitsight.evidence.first_seen_date | Date when this evidence was first seen | date |
| bitsight.evidence.identifier | Asset identifier (e.g. “IP:port”) | keyword |
| bitsight.evidence.last_seen_date | Date when this evidence was last seen | date |
| bitsight.threat.category.name | Category name | keyword |
| bitsight.threat.category.slug | Category slug | keyword |
| bitsight.threat.dve.cti_attributes.name | CTI attribute name | keyword |
| bitsight.threat.dve.cti_attributes.slug | CTI attribute slug | keyword |
| bitsight.threat.dve.highest_score | Highest recorded DVE score | float |
| bitsight.threat.dve.highest_score_date | Date of highest DVE score | date |
| bitsight.threat.dve.score | DVE score | float |
| bitsight.threat.epss.percentile | EPSS percentile | float |
| bitsight.threat.epss.score | EPSS score | float |
| bitsight.threat.evidence_certainty | Overall certainty for this threat's evidence | keyword |
| bitsight.threat.exposed_count | Number of companies observed to have evidence of exposure | integer |
| bitsight.threat.exposure_trend | Change in exposure count over the last 14 days | integer |
| bitsight.threat.first_seen_date | Date when this threat was first seen | date |
| bitsight.threat.guid | Unique threat GUID | keyword |
| bitsight.threat.last_seen_date | Date when threat data was last available | date |
| bitsight.threat.mitigated_count | Number of companies with evidence of mitigation | integer |
| bitsight.threat.name | Threat name (e.g. CVE-ID) | keyword |
| bitsight.threat.questionnaires_sent | Number of questionnaires sent (when expanded) | integer |
| bitsight.threat.severity.details | CVSS score details like type and base score (e.g. “CVSS 7.1”) | keyword |
| bitsight.threat.severity.level | Bitsight severity level | keyword |
| bitsight.threat.support_started_date | Date when this threat was first supported in Bitsight | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
