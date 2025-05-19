# Google Threat Intelligence

## Overview

[Google Threat Intelligence](https://gtidocs.virustotal.com/) is a security solution that helps organizations detect, analyze, and mitigate threats. It leverages Google's global telemetry, advanced analytics, and vast infrastructure to provide actionable insights. Key features include threat detection, malware and phishing analysis, and real-time threat alerts.

Google Threat Intelligence uses the **[Threat List API](https://gtidocs.virustotal.com/reference/api-overview)** to deliver hourly data chunks. The Threat Lists feature allows customers to consume **Indicators of Compromise (IOCs)** categorized by various threat types.

## Threat List API Feeds

The Threat List API provides the following types of threat feeds:

- **Ransomware**
- **Malicious Network Infrastructure**
- **Malware**
- **Threat Actor**
- **Daily Top Trending**
- **Mobile**
- **OS X**
- **Linux**
- **Internet of Things (IoT)**
- **Cryptominers**
- **Phishing**
- **First Stage Delivery Vectors**
- **Vulnerability Weaponization**
- **Infostealers**

## GTI Subscription Tiers

Customers can access a subset of the available threat lists based on their **Google Threat Intelligence (GTI) tier**:

- **GTI Standard**: Ransomware, Malicious Network Infrastructure
- **GTI Enterprise**: Ransomware, Malicious Network Infrastructure, Malware, Threat Actor, Daily Top Trending
- **GTI Enterprise+**: Access to all available threat lists

## Data Streams

Data collection is available for all four feed types: `Phishing`, `Ransomware`, `Threat Actor`, `Daily Top Trending`, and `Vulnerability Weaponization`, each provided through a separate data stream. By default, **Ransomware** is enabled. Users can enable additional data streams based on their GTI subscription tier. If a user enables data collection for a data stream they do not have access to, it will result in an error log on the **Discover** page.

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

## Setup

### To collect logs through REST API, follow the below steps:

- VirusTotal URL will work as the base URL for this integration: https://www.virustotal.com
- An API key will be used to authenticate your request.
- **Time Selection of Initial Interval and Interval**:
  - Users need to specify the **initial interval** and **interval** in an hourly format, such as **2h, 3h**, etc.
**Note:** Please make sure both initial interval and interval are in hours and greater than 1 hour.

### Enabling the integration in Elastic:

1. In Kibana, go to **Management > Integrations**.
2. In the "Search for integrations" search bar, type **Google Threat Intelligence**.
3. Click on the **Google Threat Intelligence** integration from the search results.
4. Click on the **Add Google Threat Intelligence** button to add the integration.
5. While adding the integration, to collect logs via REST API, provide the following details:
   - Enable the type of data stream you have access to.
   - Access Token
   - Initial Interval
   - Interval
   - (Optional) Query to add custom query filtering on relationship, GTI score, and positives.
6. Click on **Save and Continue** to save the integration.
**Note:** Please make only the threat feed types you have the privilege to access are enabled.

## Logs Reference

### Phishing

This is the `Phishing` dataset.

#### Example

An example event for `phishing` looks as following:

```json
{
    "@timestamp": "2025-01-27T19:51:31.000Z",
    "agent": {
        "ephemeral_id": "7a361b27-e14d-4e78-be2f-8d766f79c9f5",
        "id": "6aada74e-d6a8-4377-b74e-3e00e4f2081d",
        "name": "elastic-agent-66712",
        "type": "filebeat",
        "version": "8.17.3"
    },
    "data_stream": {
        "dataset": "ti_google_threat_intelligence.phishing",
        "namespace": "77020",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "6aada74e-d6a8-4377-b74e-3e00e4f2081d",
        "snapshot": false,
        "version": "8.17.3"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_google_threat_intelligence.phishing",
        "ingested": "2025-05-19T14:30:52Z",
        "kind": "enrichment",
        "original": "{\"data\":{\"attributes\":{\"first_submission_date\":1582817050,\"gti_assessment\":{\"severity\":{\"value\":\"SEVERITY_NONE\"},\"threat_score\":{\"value\":1},\"verdict\":{\"value\":\"VERDICT_UNDETECTED\"}},\"last_analysis_date\":1582817050,\"last_analysis_stats\":{\"harmless\":55,\"malicious\":8,\"undetected\":8},\"last_http_response_code\":200,\"last_modification_date\":1738007491,\"last_submission_date\":1582817050,\"positives\":8,\"times_submitted\":1,\"tld\":\"ru\",\"url\":\"http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin\"},\"id\":\"0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c\",\"relationships\":{},\"type\":\"url\"}}",
        "type": [
            "indicator"
        ]
    },
    "gti": {
        "phishing": {
            "attributes": {
                "first_submission_date": "2020-02-27T15:24:10.000Z",
                "gti_assessment": {
                    "severity": "SEVERITY_NONE",
                    "threat_score": 1,
                    "verdict": "VERDICT_UNDETECTED"
                },
                "last_analysis_date": "2020-02-27T15:24:10.000Z",
                "last_analysis_stats": {
                    "harmless": 55,
                    "malicious": 8,
                    "undetected": 8
                },
                "last_http_response_code": 200,
                "last_modification_date": "2025-01-27T19:51:31.000Z",
                "last_submission_date": "2020-02-27T15:24:10.000Z",
                "positives": 8,
                "times_submitted": 1,
                "top_level_domain": [
                    "ru"
                ],
                "url": "http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin"
            },
            "id": "0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c",
            "type": "url"
        }
    },
    "http": {
        "response": {
            "status_code": 200
        }
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "Threat Intelligence",
        "vendor": "Google"
    },
    "related": {
        "hosts": [
            "securepasswel.ru"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "google_threat_intelligence-phishing"
    ],
    "threat": {
        "feed": {
            "name": "Phishing"
        },
        "indicator": {
            "id": [
                "0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c"
            ],
            "last_seen": "2020-02-27T15:24:10.000Z",
            "modified_at": "2025-01-27T19:51:31.000Z",
            "name": "0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c",
            "type": "url",
            "url": {
                "full": "http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin",
                "original": "http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin"
            }
        }
    },
    "url": {
        "domain": "securepasswel.ru",
        "extension": "bin",
        "original": "http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin",
        "path": "/files/grapes_encrypted_87ed10f.bin",
        "scheme": "http"
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
| gti.phishing.attributes.as_number | The autonomous system number to which the IP belongs. | long |
| gti.phishing.attributes.as_owner | The owner of the autonomous system to which the IP belongs. | keyword |
| gti.phishing.attributes.categories | Categories based on the predefined criteria. | keyword |
| gti.phishing.attributes.continent | The continent where the IP is placed (ISO-3166 continent code). | keyword |
| gti.phishing.attributes.country | The country where the IP is placed (ISO-3166 country code). | keyword |
| gti.phishing.attributes.creation_date | The date when the IOC was created. | date |
| gti.phishing.attributes.first_submission_date | The UTC timestamp of the date when the URL was first submitted to Google Threat Intelligence. | date |
| gti.phishing.attributes.gti_assessment.severity | The threat severity level. | keyword |
| gti.phishing.attributes.gti_assessment.threat_score | The Google Threat Intelligence score is a function of the verdict and severity, and leverages additional internal factors to generate the score. | long |
| gti.phishing.attributes.gti_assessment.verdict | Indicates the assessed threat verdict, which can be benign, undetected, suspicious, malicious, or unknown. | keyword |
| gti.phishing.attributes.jarm | A JARM hash representing the entity's TLS fingerprint, used for identifying and classifying servers. | keyword |
| gti.phishing.attributes.last_analysis_date | The most recent scan date. | date |
| gti.phishing.attributes.last_analysis_results.engine | The name of the security engine that performed the analysis. | keyword |
| gti.phishing.attributes.last_analysis_results.result | The outcome of the analysis performed by the security engine. | keyword |
| gti.phishing.attributes.last_analysis_stats.harmless | Number of reports saying that is harmless. | long |
| gti.phishing.attributes.last_analysis_stats.malicious | Number of reports saying that is malicious. | long |
| gti.phishing.attributes.last_analysis_stats.suspicious | Number of reports saying that is suspicious. | long |
| gti.phishing.attributes.last_analysis_stats.timeout | Number of reports saying that is timeout. | long |
| gti.phishing.attributes.last_analysis_stats.undetected | Number of reports saying that is undetected. | long |
| gti.phishing.attributes.last_final_url | The URL if the original URL redirects, where does it end. | keyword |
| gti.phishing.attributes.last_http_response_code | The HTTP response code of the last response. | long |
| gti.phishing.attributes.last_modification_date | The date when the object itself was last modified. | date |
| gti.phishing.attributes.last_submission_date | The most recent date the entity was submitted for analysis. | date |
| gti.phishing.attributes.md5 | The file's MD5 hash. | keyword |
| gti.phishing.attributes.meaningful_name | The most interesting name out of all file's names. | keyword |
| gti.phishing.attributes.names | All file names associated with the file. | keyword |
| gti.phishing.attributes.network | The IPv4 network range to which the IP belongs. | keyword |
| gti.phishing.attributes.outgoing_links | Containing links to different domains. | keyword |
| gti.phishing.attributes.positives | The number of security engines that flagged the entity as malicious. | long |
| gti.phishing.attributes.regional_internet_registry | One of the current RIRs. | keyword |
| gti.phishing.attributes.tags | A list of representative attributes. | keyword |
| gti.phishing.attributes.times_submitted | The number of times the entity has been submitted for analysis. | long |
| gti.phishing.attributes.title | The webpage title. | keyword |
| gti.phishing.attributes.top_level_domain | The highest level of the domain name (e.g., .com, .org). | keyword |
| gti.phishing.attributes.type_tags | The broader tags related to the specific file type. | keyword |
| gti.phishing.attributes.url | The original URL to be scanned. | keyword |
| gti.phishing.attributes.vhash | An in-house similarity clustering algorithm value, based on a simple structural feature hash allows you to find similar files. | keyword |
| gti.phishing.id | The unique ID associated with the entity. | keyword |
| gti.phishing.relationships.campaigns.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.phishing.relationships.campaigns.attributes.name | Campaign's name. | keyword |
| gti.phishing.relationships.campaigns.id | The unique identifier associated with a specific relationship entry. | keyword |
| gti.phishing.relationships.campaigns.type | The category of relationship. | keyword |
| gti.phishing.relationships.collections.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.phishing.relationships.collections.attributes.name | Collection's name. | keyword |
| gti.phishing.relationships.collections.id | Unique identifier for the collection grouping related entities. | keyword |
| gti.phishing.relationships.collections.type | The category of relationship. | keyword |
| gti.phishing.relationships.malware_families.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.phishing.relationships.malware_families.attributes.name | Malware family's name. | keyword |
| gti.phishing.relationships.malware_families.id | Unique identifier for the malware family associated with the entity. | keyword |
| gti.phishing.relationships.malware_families.type | The category of relationship. | keyword |
| gti.phishing.relationships.reports.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.phishing.relationships.reports.attributes.name | Report's title. | keyword |
| gti.phishing.relationships.reports.id | Unique identifier for the report detailing the entity's analysis. | keyword |
| gti.phishing.relationships.reports.type | The category of relationship. | keyword |
| gti.phishing.relationships.software_toolkits.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.phishing.relationships.software_toolkits.attributes.name | Software or toolkit's name. | keyword |
| gti.phishing.relationships.software_toolkits.id | Unique identifier for the software or toolkit associated with the entity. | keyword |
| gti.phishing.relationships.software_toolkits.type | The category of relationship. | keyword |
| gti.phishing.relationships.threat_actors.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.phishing.relationships.threat_actors.attributes.name | Threat actor's name. | keyword |
| gti.phishing.relationships.threat_actors.id | Unique identifier for the threat actor associated with the entity. | keyword |
| gti.phishing.relationships.threat_actors.type | The category of relationship. | keyword |
| gti.phishing.relationships.vulnerabilities.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.phishing.relationships.vulnerabilities.attributes.name | Vulnerability's name. | keyword |
| gti.phishing.relationships.vulnerabilities.id | Unique identifier for the vulnerability associated with the entity. | keyword |
| gti.phishing.relationships.vulnerabilities.type | The category of relationship. | keyword |
| gti.phishing.type | Specifies the nature of the entity, such as file, domain, IP, or URL. | keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| log.offset | Log offset. | long |


### Ransomware

This is the `Ransomware` dataset.

#### Example

An example event for `ransomware` looks as following:

```json
{
    "@timestamp": "2025-01-27T19:51:31.000Z",
    "agent": {
        "ephemeral_id": "a5966c81-2e7a-43ec-8e30-cdd9f3ba5e20",
        "id": "b0f83a32-58d7-4173-8b38-01456f062608",
        "name": "elastic-agent-24522",
        "type": "filebeat",
        "version": "8.17.3"
    },
    "data_stream": {
        "dataset": "ti_google_threat_intelligence.ransomware",
        "namespace": "68780",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "b0f83a32-58d7-4173-8b38-01456f062608",
        "snapshot": false,
        "version": "8.17.3"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_google_threat_intelligence.ransomware",
        "ingested": "2025-05-19T14:33:22Z",
        "kind": "enrichment",
        "original": "{\"data\":{\"attributes\":{\"first_submission_date\":1582817050,\"gti_assessment\":{\"severity\":{\"value\":\"SEVERITY_NONE\"},\"threat_score\":{\"value\":1},\"verdict\":{\"value\":\"VERDICT_UNDETECTED\"}},\"last_analysis_date\":1582817050,\"last_analysis_stats\":{\"harmless\":55,\"malicious\":8,\"undetected\":8},\"last_http_response_code\":200,\"last_modification_date\":1738007491,\"last_submission_date\":1582817050,\"positives\":8,\"times_submitted\":1,\"tld\":\"ru\",\"url\":\"http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin\"},\"id\":\"0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c\",\"relationships\":{},\"type\":\"url\"}}",
        "type": [
            "indicator"
        ]
    },
    "gti": {
        "ransomware": {
            "attributes": {
                "first_submission_date": "2020-02-27T15:24:10.000Z",
                "gti_assessment": {
                    "severity": "SEVERITY_NONE",
                    "threat_score": 1,
                    "verdict": "VERDICT_UNDETECTED"
                },
                "last_analysis_date": "2020-02-27T15:24:10.000Z",
                "last_analysis_stats": {
                    "harmless": 55,
                    "malicious": 8,
                    "undetected": 8
                },
                "last_http_response_code": 200,
                "last_modification_date": "2025-01-27T19:51:31.000Z",
                "last_submission_date": "2020-02-27T15:24:10.000Z",
                "positives": 8,
                "times_submitted": 1,
                "top_level_domain": [
                    "ru"
                ],
                "url": "http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin"
            },
            "id": "0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c",
            "type": "url"
        }
    },
    "http": {
        "response": {
            "status_code": 200
        }
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "Threat Intelligence",
        "vendor": "Google"
    },
    "related": {
        "hosts": [
            "securepasswel.ru"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "google_threat_intelligence-ransomware"
    ],
    "threat": {
        "feed": {
            "name": "Ransomware"
        },
        "indicator": {
            "id": [
                "0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c"
            ],
            "last_seen": "2020-02-27T15:24:10.000Z",
            "modified_at": "2025-01-27T19:51:31.000Z",
            "name": "0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c",
            "type": "url",
            "url": {
                "full": "http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin",
                "original": "http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin"
            }
        }
    },
    "url": {
        "domain": "securepasswel.ru",
        "extension": "bin",
        "original": "http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin",
        "path": "/files/grapes_encrypted_87ed10f.bin",
        "scheme": "http"
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
| gti.ransomware.attributes.as_number | The autonomous system number to which the IP belongs. | long |
| gti.ransomware.attributes.as_owner | The owner of the autonomous system to which the IP belongs. | keyword |
| gti.ransomware.attributes.categories | Categories based on the predefined criteria. | keyword |
| gti.ransomware.attributes.continent | The continent where the IP is placed (ISO-3166 continent code). | keyword |
| gti.ransomware.attributes.country | The country where the IP is placed (ISO-3166 country code). | keyword |
| gti.ransomware.attributes.creation_date | The date when the IOC was created. | date |
| gti.ransomware.attributes.first_submission_date | The UTC timestamp of the date when the URL was first submitted to Google Threat Intelligence. | date |
| gti.ransomware.attributes.gti_assessment.severity | The threat severity level. | keyword |
| gti.ransomware.attributes.gti_assessment.threat_score | The Google Threat Intelligence score is a function of the verdict and severity, and leverages additional internal factors to generate the score. | long |
| gti.ransomware.attributes.gti_assessment.verdict | Indicates the assessed threat verdict, which can be benign, undetected, suspicious, malicious, or unknown. | keyword |
| gti.ransomware.attributes.jarm | A JARM hash representing the entity's TLS fingerprint, used for identifying and classifying servers. | keyword |
| gti.ransomware.attributes.last_analysis_date | The most recent scan date. | date |
| gti.ransomware.attributes.last_analysis_results.engine | The name of the security engine that performed the analysis. | keyword |
| gti.ransomware.attributes.last_analysis_results.result | The outcome of the analysis performed by the security engine. | keyword |
| gti.ransomware.attributes.last_analysis_stats.harmless | Number of reports saying that is harmless. | long |
| gti.ransomware.attributes.last_analysis_stats.malicious | Number of reports saying that is malicious. | long |
| gti.ransomware.attributes.last_analysis_stats.suspicious | Number of reports saying that is suspicious. | long |
| gti.ransomware.attributes.last_analysis_stats.timeout | Number of reports saying that is timeout. | long |
| gti.ransomware.attributes.last_analysis_stats.undetected | Number of reports saying that is undetected. | long |
| gti.ransomware.attributes.last_final_url | The URL if the original URL redirects, where does it end. | keyword |
| gti.ransomware.attributes.last_http_response_code | The HTTP response code of the last response. | long |
| gti.ransomware.attributes.last_modification_date | The date when the object itself was last modified. | date |
| gti.ransomware.attributes.last_submission_date | The most recent date the entity was submitted for analysis. | date |
| gti.ransomware.attributes.md5 | The file's MD5 hash. | keyword |
| gti.ransomware.attributes.meaningful_name | The most interesting name out of all file's names. | keyword |
| gti.ransomware.attributes.names | All file names associated with the file. | keyword |
| gti.ransomware.attributes.network | The IPv4 network range to which the IP belongs. | keyword |
| gti.ransomware.attributes.outgoing_links | Containing links to different domains. | keyword |
| gti.ransomware.attributes.positives | The number of security engines that flagged the entity as malicious. | long |
| gti.ransomware.attributes.regional_internet_registry | One of the current RIRs. | keyword |
| gti.ransomware.attributes.tags | A list of representative attributes. | keyword |
| gti.ransomware.attributes.times_submitted | The number of times the entity has been submitted for analysis. | long |
| gti.ransomware.attributes.title | The webpage title. | keyword |
| gti.ransomware.attributes.top_level_domain | The highest level of the domain name (e.g., .com, .org). | keyword |
| gti.ransomware.attributes.type_tags | The broader tags related to the specific file type. | keyword |
| gti.ransomware.attributes.url | The original URL to be scanned. | keyword |
| gti.ransomware.attributes.vhash | An in-house similarity clustering algorithm value, based on a simple structural feature hash allows you to find similar files. | keyword |
| gti.ransomware.id | The unique ID associated with the entity. | keyword |
| gti.ransomware.relationships.campaigns.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.ransomware.relationships.campaigns.attributes.name | Campaign's name. | keyword |
| gti.ransomware.relationships.campaigns.id | The unique identifier associated with a specific relationship entry. | keyword |
| gti.ransomware.relationships.campaigns.type | The category of relationship. | keyword |
| gti.ransomware.relationships.collections.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.ransomware.relationships.collections.attributes.name | Collection's name. | keyword |
| gti.ransomware.relationships.collections.id | Unique identifier for the collection grouping related entities. | keyword |
| gti.ransomware.relationships.collections.type | The category of relationship. | keyword |
| gti.ransomware.relationships.malware_families.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.ransomware.relationships.malware_families.attributes.name | Malware family's name. | keyword |
| gti.ransomware.relationships.malware_families.id | Unique identifier for the malware family associated with the entity. | keyword |
| gti.ransomware.relationships.malware_families.type | The category of relationship. | keyword |
| gti.ransomware.relationships.reports.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.ransomware.relationships.reports.attributes.name | Report's title. | keyword |
| gti.ransomware.relationships.reports.id | Unique identifier for the report detailing the entity's analysis. | keyword |
| gti.ransomware.relationships.reports.type | The category of relationship. | keyword |
| gti.ransomware.relationships.software_toolkits.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.ransomware.relationships.software_toolkits.attributes.name | Software or toolkit's name. | keyword |
| gti.ransomware.relationships.software_toolkits.id | Unique identifier for the software or toolkit associated with the entity. | keyword |
| gti.ransomware.relationships.software_toolkits.type | The category of relationship. | keyword |
| gti.ransomware.relationships.threat_actors.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.ransomware.relationships.threat_actors.attributes.name | Threat actor's name. | keyword |
| gti.ransomware.relationships.threat_actors.id | Unique identifier for the threat actor associated with the entity. | keyword |
| gti.ransomware.relationships.threat_actors.type | The category of relationship. | keyword |
| gti.ransomware.relationships.vulnerabilities.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.ransomware.relationships.vulnerabilities.attributes.name | Vulnerability's name. | keyword |
| gti.ransomware.relationships.vulnerabilities.id | Unique identifier for the vulnerability associated with the entity. | keyword |
| gti.ransomware.relationships.vulnerabilities.type | The category of relationship. | keyword |
| gti.ransomware.type | Specifies the nature of the entity, such as file, domain, IP, or URL. | keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| log.offset | Log offset. | long |


### Threat Actor

This is the `Threat Actor` dataset.

#### Example

An example event for `threat_actor` looks as following:

```json
{
    "@timestamp": "2025-01-27T19:51:31.000Z",
    "agent": {
        "ephemeral_id": "dd5bf467-21c0-4eee-8c00-5cf83767894b",
        "id": "1d78232e-76c0-464a-a7a5-ac594a071c88",
        "name": "elastic-agent-49387",
        "type": "filebeat",
        "version": "8.17.3"
    },
    "data_stream": {
        "dataset": "ti_google_threat_intelligence.threat_actor",
        "namespace": "10850",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "1d78232e-76c0-464a-a7a5-ac594a071c88",
        "snapshot": false,
        "version": "8.17.3"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_google_threat_intelligence.threat_actor",
        "ingested": "2025-05-19T14:35:42Z",
        "kind": "enrichment",
        "original": "{\"data\":{\"attributes\":{\"first_submission_date\":1582817050,\"gti_assessment\":{\"severity\":{\"value\":\"SEVERITY_NONE\"},\"threat_score\":{\"value\":1},\"verdict\":{\"value\":\"VERDICT_UNDETECTED\"}},\"last_analysis_date\":1582817050,\"last_analysis_stats\":{\"harmless\":55,\"malicious\":8,\"undetected\":8},\"last_http_response_code\":200,\"last_modification_date\":1738007491,\"last_submission_date\":1582817050,\"positives\":8,\"times_submitted\":1,\"tld\":\"ru\",\"url\":\"http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin\"},\"id\":\"0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c\",\"relationships\":{},\"type\":\"url\"}}",
        "type": [
            "indicator"
        ]
    },
    "gti": {
        "threat_actor": {
            "attributes": {
                "first_submission_date": "2020-02-27T15:24:10.000Z",
                "gti_assessment": {
                    "severity": "SEVERITY_NONE",
                    "threat_score": 1,
                    "verdict": "VERDICT_UNDETECTED"
                },
                "last_analysis_date": "2020-02-27T15:24:10.000Z",
                "last_analysis_stats": {
                    "harmless": 55,
                    "malicious": 8,
                    "undetected": 8
                },
                "last_http_response_code": 200,
                "last_modification_date": "2025-01-27T19:51:31.000Z",
                "last_submission_date": "2020-02-27T15:24:10.000Z",
                "positives": 8,
                "times_submitted": 1,
                "top_level_domain": [
                    "ru"
                ],
                "url": "http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin"
            },
            "id": "0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c",
            "type": "url"
        }
    },
    "http": {
        "response": {
            "status_code": 200
        }
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "Threat Intelligence",
        "vendor": "Google"
    },
    "related": {
        "hosts": [
            "securepasswel.ru"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "google_threat_intelligence-threat_actor"
    ],
    "threat": {
        "feed": {
            "name": "Threat Actor"
        },
        "indicator": {
            "id": [
                "0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c"
            ],
            "last_seen": "2020-02-27T15:24:10.000Z",
            "modified_at": "2025-01-27T19:51:31.000Z",
            "name": "0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c",
            "type": "url",
            "url": {
                "full": "http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin",
                "original": "http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin"
            }
        }
    },
    "url": {
        "domain": "securepasswel.ru",
        "extension": "bin",
        "original": "http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin",
        "path": "/files/grapes_encrypted_87ed10f.bin",
        "scheme": "http"
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
| gti.threat_actor.attributes.as_number | The autonomous system number to which the IP belongs. | long |
| gti.threat_actor.attributes.as_owner | The owner of the autonomous system to which the IP belongs. | keyword |
| gti.threat_actor.attributes.categories | Categories based on the predefined criteria. | keyword |
| gti.threat_actor.attributes.continent | The continent where the IP is placed (ISO-3166 continent code). | keyword |
| gti.threat_actor.attributes.country | The country where the IP is placed (ISO-3166 country code). | keyword |
| gti.threat_actor.attributes.creation_date | The date when the IOC was created. | date |
| gti.threat_actor.attributes.first_submission_date | The UTC timestamp of the date when the URL was first submitted to Google Threat Intelligence. | date |
| gti.threat_actor.attributes.gti_assessment.severity | The threat severity level. | keyword |
| gti.threat_actor.attributes.gti_assessment.threat_score | The Google Threat Intelligence score is a function of the verdict and severity, and leverages additional internal factors to generate the score. | long |
| gti.threat_actor.attributes.gti_assessment.verdict | Indicates the assessed threat verdict, which can be benign, undetected, suspicious, malicious, or unknown. | keyword |
| gti.threat_actor.attributes.jarm | A JARM hash representing the entity's TLS fingerprint, used for identifying and classifying servers. | keyword |
| gti.threat_actor.attributes.last_analysis_date | The most recent scan date. | date |
| gti.threat_actor.attributes.last_analysis_results.engine | The name of the security engine that performed the analysis. | keyword |
| gti.threat_actor.attributes.last_analysis_results.result | The outcome of the analysis performed by the security engine. | keyword |
| gti.threat_actor.attributes.last_analysis_stats.harmless | Number of reports saying that is harmless. | long |
| gti.threat_actor.attributes.last_analysis_stats.malicious | Number of reports saying that is malicious. | long |
| gti.threat_actor.attributes.last_analysis_stats.suspicious | Number of reports saying that is suspicious. | long |
| gti.threat_actor.attributes.last_analysis_stats.timeout | Number of reports saying that is timeout. | long |
| gti.threat_actor.attributes.last_analysis_stats.undetected | Number of reports saying that is undetected. | long |
| gti.threat_actor.attributes.last_final_url | The URL if the original URL redirects, where does it end. | keyword |
| gti.threat_actor.attributes.last_http_response_code | The HTTP response code of the last response. | long |
| gti.threat_actor.attributes.last_modification_date | The date when the object itself was last modified. | date |
| gti.threat_actor.attributes.last_submission_date | The most recent date the entity was submitted for analysis. | date |
| gti.threat_actor.attributes.md5 | The file's MD5 hash. | keyword |
| gti.threat_actor.attributes.meaningful_name | The most interesting name out of all file's names. | keyword |
| gti.threat_actor.attributes.names | All file names associated with the file. | keyword |
| gti.threat_actor.attributes.network | The IPv4 network range to which the IP belongs. | keyword |
| gti.threat_actor.attributes.outgoing_links | Containing links to different domains. | keyword |
| gti.threat_actor.attributes.positives | The number of security engines that flagged the entity as malicious. | long |
| gti.threat_actor.attributes.regional_internet_registry | One of the current RIRs. | keyword |
| gti.threat_actor.attributes.tags | A list of representative attributes. | keyword |
| gti.threat_actor.attributes.times_submitted | The number of times the entity has been submitted for analysis. | long |
| gti.threat_actor.attributes.title | The webpage title. | keyword |
| gti.threat_actor.attributes.top_level_domain | The highest level of the domain name (e.g., .com, .org). | keyword |
| gti.threat_actor.attributes.type_tags | The broader tags related to the specific file type. | keyword |
| gti.threat_actor.attributes.url | The original URL to be scanned. | keyword |
| gti.threat_actor.attributes.vhash | An in-house similarity clustering algorithm value, based on a simple structural feature hash allows you to find similar files. | keyword |
| gti.threat_actor.id | The unique ID associated with the entity. | keyword |
| gti.threat_actor.relationships.campaigns.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.threat_actor.relationships.campaigns.attributes.name | Campaign's name. | keyword |
| gti.threat_actor.relationships.campaigns.id | The unique identifier associated with a specific relationship entry. | keyword |
| gti.threat_actor.relationships.campaigns.type | The category of relationship. | keyword |
| gti.threat_actor.relationships.collections.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.threat_actor.relationships.collections.attributes.name | Collection's name. | keyword |
| gti.threat_actor.relationships.collections.id | Unique identifier for the collection grouping related entities. | keyword |
| gti.threat_actor.relationships.collections.type | The category of relationship. | keyword |
| gti.threat_actor.relationships.malware_families.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.threat_actor.relationships.malware_families.attributes.name | Malware family's name. | keyword |
| gti.threat_actor.relationships.malware_families.id | Unique identifier for the malware family associated with the entity. | keyword |
| gti.threat_actor.relationships.malware_families.type | The category of relationship. | keyword |
| gti.threat_actor.relationships.reports.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.threat_actor.relationships.reports.attributes.name | Report's title. | keyword |
| gti.threat_actor.relationships.reports.id | Unique identifier for the report detailing the entity's analysis. | keyword |
| gti.threat_actor.relationships.reports.type | The category of relationship. | keyword |
| gti.threat_actor.relationships.software_toolkits.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.threat_actor.relationships.software_toolkits.attributes.name | Software or toolkit's name. | keyword |
| gti.threat_actor.relationships.software_toolkits.id | Unique identifier for the software or toolkit associated with the entity. | keyword |
| gti.threat_actor.relationships.software_toolkits.type | The category of relationship. | keyword |
| gti.threat_actor.relationships.threat_actors.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.threat_actor.relationships.threat_actors.attributes.name | Threat actor's name. | keyword |
| gti.threat_actor.relationships.threat_actors.id | Unique identifier for the threat actor associated with the entity. | keyword |
| gti.threat_actor.relationships.threat_actors.type | The category of relationship. | keyword |
| gti.threat_actor.relationships.vulnerabilities.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.threat_actor.relationships.vulnerabilities.attributes.name | Vulnerability's name. | keyword |
| gti.threat_actor.relationships.vulnerabilities.id | Unique identifier for the vulnerability associated with the entity. | keyword |
| gti.threat_actor.relationships.vulnerabilities.type | The category of relationship. | keyword |
| gti.threat_actor.type | Specifies the nature of the entity, such as file, domain, IP, or URL. | keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| log.offset | Log offset. | long |


### Daily Top trending

This is the `Daily Top trending` dataset.

#### Example

An example event for `trending` looks as following:

```json
{
    "@timestamp": "2025-01-27T19:51:31.000Z",
    "agent": {
        "ephemeral_id": "991bf2fc-9bcc-4ffb-bba4-8e47c87378a8",
        "id": "11bad4f5-753b-4a02-8b58-41113ded1a83",
        "name": "elastic-agent-55107",
        "type": "filebeat",
        "version": "8.17.3"
    },
    "data_stream": {
        "dataset": "ti_google_threat_intelligence.trending",
        "namespace": "87318",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "11bad4f5-753b-4a02-8b58-41113ded1a83",
        "snapshot": false,
        "version": "8.17.3"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_google_threat_intelligence.trending",
        "ingested": "2025-05-19T14:38:01Z",
        "kind": "enrichment",
        "original": "{\"data\":{\"attributes\":{\"first_submission_date\":1582817050,\"gti_assessment\":{\"severity\":{\"value\":\"SEVERITY_NONE\"},\"threat_score\":{\"value\":1},\"verdict\":{\"value\":\"VERDICT_UNDETECTED\"}},\"last_analysis_date\":1582817050,\"last_analysis_stats\":{\"harmless\":55,\"malicious\":8,\"undetected\":8},\"last_http_response_code\":200,\"last_modification_date\":1738007491,\"last_submission_date\":1582817050,\"positives\":8,\"times_submitted\":1,\"tld\":\"ru\",\"url\":\"http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin\"},\"id\":\"0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c\",\"relationships\":{},\"type\":\"url\"}}",
        "type": [
            "indicator"
        ]
    },
    "gti": {
        "trending": {
            "attributes": {
                "first_submission_date": "2020-02-27T15:24:10.000Z",
                "gti_assessment": {
                    "severity": "SEVERITY_NONE",
                    "threat_score": 1,
                    "verdict": "VERDICT_UNDETECTED"
                },
                "last_analysis_date": "2020-02-27T15:24:10.000Z",
                "last_analysis_stats": {
                    "harmless": 55,
                    "malicious": 8,
                    "undetected": 8
                },
                "last_http_response_code": 200,
                "last_modification_date": "2025-01-27T19:51:31.000Z",
                "last_submission_date": "2020-02-27T15:24:10.000Z",
                "positives": 8,
                "times_submitted": 1,
                "top_level_domain": [
                    "ru"
                ],
                "url": "http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin"
            },
            "id": "0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c",
            "type": "url"
        }
    },
    "http": {
        "response": {
            "status_code": 200
        }
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "Threat Intelligence",
        "vendor": "Google"
    },
    "related": {
        "hosts": [
            "securepasswel.ru"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "google_threat_intelligence-trending"
    ],
    "threat": {
        "feed": {
            "name": "Daily Top trending"
        },
        "indicator": {
            "id": [
                "0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c"
            ],
            "last_seen": "2020-02-27T15:24:10.000Z",
            "modified_at": "2025-01-27T19:51:31.000Z",
            "name": "0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c",
            "type": "url",
            "url": {
                "full": "http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin",
                "original": "http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin"
            }
        }
    },
    "url": {
        "domain": "securepasswel.ru",
        "extension": "bin",
        "original": "http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin",
        "path": "/files/grapes_encrypted_87ed10f.bin",
        "scheme": "http"
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
| gti.trending.attributes.as_number | The autonomous system number to which the IP belongs. | long |
| gti.trending.attributes.as_owner | The owner of the autonomous system to which the IP belongs. | keyword |
| gti.trending.attributes.categories | Categories based on the predefined criteria. | keyword |
| gti.trending.attributes.continent | The continent where the IP is placed (ISO-3166 continent code). | keyword |
| gti.trending.attributes.country | The country where the IP is placed (ISO-3166 country code). | keyword |
| gti.trending.attributes.creation_date | The date when the IOC was created. | date |
| gti.trending.attributes.first_submission_date | The UTC timestamp of the date when the URL was first submitted to Google Threat Intelligence. | date |
| gti.trending.attributes.gti_assessment.severity | The threat severity level. | keyword |
| gti.trending.attributes.gti_assessment.threat_score | The Google Threat Intelligence score is a function of the verdict and severity, and leverages additional internal factors to generate the score. | long |
| gti.trending.attributes.gti_assessment.verdict | Indicates the assessed threat verdict, which can be benign, undetected, suspicious, malicious, or unknown. | keyword |
| gti.trending.attributes.jarm | A JARM hash representing the entity's TLS fingerprint, used for identifying and classifying servers. | keyword |
| gti.trending.attributes.last_analysis_date | The most recent scan date. | date |
| gti.trending.attributes.last_analysis_results.engine | The name of the security engine that performed the analysis. | keyword |
| gti.trending.attributes.last_analysis_results.result | The outcome of the analysis performed by the security engine. | keyword |
| gti.trending.attributes.last_analysis_stats.harmless | Number of reports saying that is harmless. | long |
| gti.trending.attributes.last_analysis_stats.malicious | Number of reports saying that is malicious. | long |
| gti.trending.attributes.last_analysis_stats.suspicious | Number of reports saying that is suspicious. | long |
| gti.trending.attributes.last_analysis_stats.timeout | Number of reports saying that is timeout. | long |
| gti.trending.attributes.last_analysis_stats.undetected | Number of reports saying that is undetected. | long |
| gti.trending.attributes.last_final_url | The URL if the original URL redirects, where does it end. | keyword |
| gti.trending.attributes.last_http_response_code | The HTTP response code of the last response. | long |
| gti.trending.attributes.last_modification_date | The date when the object itself was last modified. | date |
| gti.trending.attributes.last_submission_date | The most recent date the entity was submitted for analysis. | date |
| gti.trending.attributes.md5 | The file's MD5 hash. | keyword |
| gti.trending.attributes.meaningful_name | The most interesting name out of all file's names. | keyword |
| gti.trending.attributes.names | All file names associated with the file. | keyword |
| gti.trending.attributes.network | The IPv4 network range to which the IP belongs. | keyword |
| gti.trending.attributes.outgoing_links | Containing links to different domains. | keyword |
| gti.trending.attributes.positives | The number of security engines that flagged the entity as malicious. | long |
| gti.trending.attributes.regional_internet_registry | One of the current RIRs. | keyword |
| gti.trending.attributes.tags | A list of representative attributes. | keyword |
| gti.trending.attributes.times_submitted | The number of times the entity has been submitted for analysis. | long |
| gti.trending.attributes.title | The webpage title. | keyword |
| gti.trending.attributes.top_level_domain | The highest level of the domain name (e.g., .com, .org). | keyword |
| gti.trending.attributes.type_tags | The broader tags related to the specific file type. | keyword |
| gti.trending.attributes.url | The original URL to be scanned. | keyword |
| gti.trending.attributes.vhash | An in-house similarity clustering algorithm value, based on a simple structural feature hash allows you to find similar files. | keyword |
| gti.trending.id | The unique ID associated with the entity. | keyword |
| gti.trending.relationships.campaigns.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.trending.relationships.campaigns.attributes.name | Campaign's name. | keyword |
| gti.trending.relationships.campaigns.id | The unique identifier associated with a specific relationship entry. | keyword |
| gti.trending.relationships.campaigns.type | The category of relationship. | keyword |
| gti.trending.relationships.collections.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.trending.relationships.collections.attributes.name | Collection's name. | keyword |
| gti.trending.relationships.collections.id | Unique identifier for the collection grouping related entities. | keyword |
| gti.trending.relationships.collections.type | The category of relationship. | keyword |
| gti.trending.relationships.malware_families.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.trending.relationships.malware_families.attributes.name | Malware family's name. | keyword |
| gti.trending.relationships.malware_families.id | Unique identifier for the malware family associated with the entity. | keyword |
| gti.trending.relationships.malware_families.type | The category of relationship. | keyword |
| gti.trending.relationships.reports.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.trending.relationships.reports.attributes.name | Report's title. | keyword |
| gti.trending.relationships.reports.id | Unique identifier for the report detailing the entity's analysis. | keyword |
| gti.trending.relationships.reports.type | The category of relationship. | keyword |
| gti.trending.relationships.software_toolkits.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.trending.relationships.software_toolkits.attributes.name | Software or toolkit's name. | keyword |
| gti.trending.relationships.software_toolkits.id | Unique identifier for the software or toolkit associated with the entity. | keyword |
| gti.trending.relationships.software_toolkits.type | The category of relationship. | keyword |
| gti.trending.relationships.threat_actors.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.trending.relationships.threat_actors.attributes.name | Threat actor's name. | keyword |
| gti.trending.relationships.threat_actors.id | Unique identifier for the threat actor associated with the entity. | keyword |
| gti.trending.relationships.threat_actors.type | The category of relationship. | keyword |
| gti.trending.relationships.vulnerabilities.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.trending.relationships.vulnerabilities.attributes.name | Vulnerability's name. | keyword |
| gti.trending.relationships.vulnerabilities.id | Unique identifier for the vulnerability associated with the entity. | keyword |
| gti.trending.relationships.vulnerabilities.type | The category of relationship. | keyword |
| gti.trending.type | Specifies the nature of the entity, such as file, domain, IP, or URL. | keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| log.offset | Log offset. | long |


### Vulnerability Weaponization

This is the `Vulnerability Weaponization` dataset.

#### Example

An example event for `vulnerability_weaponization` looks as following:

```json
{
    "@timestamp": "2025-01-27T19:51:31.000Z",
    "agent": {
        "ephemeral_id": "62da52d4-35a7-4dd2-8500-056a0de0eb5b",
        "id": "190436b7-5610-4d30-a111-8e82611201c6",
        "name": "elastic-agent-43273",
        "type": "filebeat",
        "version": "8.17.3"
    },
    "data_stream": {
        "dataset": "ti_google_threat_intelligence.vulnerability_weaponization",
        "namespace": "77860",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "190436b7-5610-4d30-a111-8e82611201c6",
        "snapshot": false,
        "version": "8.17.3"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat",
            "vulnerability"
        ],
        "dataset": "ti_google_threat_intelligence.vulnerability_weaponization",
        "ingested": "2025-05-19T14:40:21Z",
        "kind": "enrichment",
        "original": "{\"data\":{\"attributes\":{\"first_submission_date\":1582817050,\"gti_assessment\":{\"severity\":{\"value\":\"SEVERITY_NONE\"},\"threat_score\":{\"value\":1},\"verdict\":{\"value\":\"VERDICT_UNDETECTED\"}},\"last_analysis_date\":1582817050,\"last_analysis_stats\":{\"harmless\":55,\"malicious\":8,\"undetected\":8},\"last_http_response_code\":200,\"last_modification_date\":1738007491,\"last_submission_date\":1582817050,\"positives\":8,\"times_submitted\":1,\"tld\":\"ru\",\"url\":\"http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin\"},\"id\":\"0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c\",\"relationships\":{},\"type\":\"url\"}}",
        "type": [
            "indicator",
            "info"
        ]
    },
    "gti": {
        "vulnerability_weaponization": {
            "attributes": {
                "first_submission_date": "2020-02-27T15:24:10.000Z",
                "gti_assessment": {
                    "severity": "SEVERITY_NONE",
                    "threat_score": 1,
                    "verdict": "VERDICT_UNDETECTED"
                },
                "last_analysis_date": "2020-02-27T15:24:10.000Z",
                "last_analysis_stats": {
                    "harmless": 55,
                    "malicious": 8,
                    "undetected": 8
                },
                "last_http_response_code": 200,
                "last_modification_date": "2025-01-27T19:51:31.000Z",
                "last_submission_date": "2020-02-27T15:24:10.000Z",
                "positives": 8,
                "times_submitted": 1,
                "top_level_domain": [
                    "ru"
                ],
                "url": "http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin"
            },
            "id": "0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c",
            "type": "url"
        }
    },
    "http": {
        "response": {
            "status_code": 200
        }
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "Threat Intelligence",
        "vendor": "Google"
    },
    "related": {
        "hosts": [
            "securepasswel.ru"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "google_threat_intelligence-vulnerability_weaponization"
    ],
    "threat": {
        "feed": {
            "name": "Vulnerability Weaponization"
        },
        "indicator": {
            "id": [
                "0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c"
            ],
            "last_seen": "2020-02-27T15:24:10.000Z",
            "modified_at": "2025-01-27T19:51:31.000Z",
            "name": "0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c",
            "type": "url",
            "url": {
                "full": "http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin",
                "original": "http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin"
            }
        }
    },
    "url": {
        "domain": "securepasswel.ru",
        "extension": "bin",
        "original": "http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin",
        "path": "/files/grapes_encrypted_87ed10f.bin",
        "scheme": "http"
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
| gti.vulnerability_weaponization.attributes.as_number | The autonomous system number to which the IP belongs. | long |
| gti.vulnerability_weaponization.attributes.as_owner | The owner of the autonomous system to which the IP belongs. | keyword |
| gti.vulnerability_weaponization.attributes.categories | Categories based on the predefined criteria. | keyword |
| gti.vulnerability_weaponization.attributes.continent | The continent where the IP is placed (ISO-3166 continent code). | keyword |
| gti.vulnerability_weaponization.attributes.country | The country where the IP is placed (ISO-3166 country code). | keyword |
| gti.vulnerability_weaponization.attributes.creation_date | The date when the IOC was created. | date |
| gti.vulnerability_weaponization.attributes.first_submission_date | The UTC timestamp of the date when the URL was first submitted to Google Threat Intelligence. | date |
| gti.vulnerability_weaponization.attributes.gti_assessment.severity | The threat severity level. | keyword |
| gti.vulnerability_weaponization.attributes.gti_assessment.threat_score | The Google Threat Intelligence score is a function of the verdict and severity, and leverages additional internal factors to generate the score. | long |
| gti.vulnerability_weaponization.attributes.gti_assessment.verdict | Indicates the assessed threat verdict, which can be benign, undetected, suspicious, malicious, or unknown. | keyword |
| gti.vulnerability_weaponization.attributes.jarm | A JARM hash representing the entity's TLS fingerprint, used for identifying and classifying servers. | keyword |
| gti.vulnerability_weaponization.attributes.last_analysis_date | The most recent scan date. | date |
| gti.vulnerability_weaponization.attributes.last_analysis_results.engine | The name of the security engine that performed the analysis. | keyword |
| gti.vulnerability_weaponization.attributes.last_analysis_results.result | The outcome of the analysis performed by the security engine. | keyword |
| gti.vulnerability_weaponization.attributes.last_analysis_stats.harmless | Number of reports saying that is harmless. | long |
| gti.vulnerability_weaponization.attributes.last_analysis_stats.malicious | Number of reports saying that is malicious. | long |
| gti.vulnerability_weaponization.attributes.last_analysis_stats.suspicious | Number of reports saying that is suspicious. | long |
| gti.vulnerability_weaponization.attributes.last_analysis_stats.timeout | Number of reports saying that is timeout. | long |
| gti.vulnerability_weaponization.attributes.last_analysis_stats.undetected | Number of reports saying that is undetected. | long |
| gti.vulnerability_weaponization.attributes.last_final_url | The URL if the original URL redirects, where does it end. | keyword |
| gti.vulnerability_weaponization.attributes.last_http_response_code | The HTTP response code of the last response. | long |
| gti.vulnerability_weaponization.attributes.last_modification_date | The date when the object itself was last modified. | date |
| gti.vulnerability_weaponization.attributes.last_submission_date | The most recent date the entity was submitted for analysis. | date |
| gti.vulnerability_weaponization.attributes.md5 | The file's MD5 hash. | keyword |
| gti.vulnerability_weaponization.attributes.meaningful_name | The most interesting name out of all file's names. | keyword |
| gti.vulnerability_weaponization.attributes.names | All file names associated with the file. | keyword |
| gti.vulnerability_weaponization.attributes.network | The IPv4 network range to which the IP belongs. | keyword |
| gti.vulnerability_weaponization.attributes.outgoing_links | Containing links to different domains. | keyword |
| gti.vulnerability_weaponization.attributes.positives | The number of security engines that flagged the entity as malicious. | long |
| gti.vulnerability_weaponization.attributes.regional_internet_registry | One of the current RIRs. | keyword |
| gti.vulnerability_weaponization.attributes.tags | A list of representative attributes. | keyword |
| gti.vulnerability_weaponization.attributes.times_submitted | The number of times the entity has been submitted for analysis. | long |
| gti.vulnerability_weaponization.attributes.title | The webpage title. | keyword |
| gti.vulnerability_weaponization.attributes.top_level_domain | The highest level of the domain name (e.g., .com, .org). | keyword |
| gti.vulnerability_weaponization.attributes.type_tags | The broader tags related to the specific file type. | keyword |
| gti.vulnerability_weaponization.attributes.url | The original URL to be scanned. | keyword |
| gti.vulnerability_weaponization.attributes.vhash | An in-house similarity clustering algorithm value, based on a simple structural feature hash allows you to find similar files. | keyword |
| gti.vulnerability_weaponization.id | The unique ID associated with the entity. | keyword |
| gti.vulnerability_weaponization.relationships.campaigns.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.vulnerability_weaponization.relationships.campaigns.attributes.name | Campaign's name. | keyword |
| gti.vulnerability_weaponization.relationships.campaigns.id | The unique identifier associated with a specific relationship entry. | keyword |
| gti.vulnerability_weaponization.relationships.campaigns.type | The category of relationship. | keyword |
| gti.vulnerability_weaponization.relationships.collections.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.vulnerability_weaponization.relationships.collections.attributes.name | Collection's name. | keyword |
| gti.vulnerability_weaponization.relationships.collections.id | Unique identifier for the collection grouping related entities. | keyword |
| gti.vulnerability_weaponization.relationships.collections.type | The category of relationship. | keyword |
| gti.vulnerability_weaponization.relationships.malware_families.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.vulnerability_weaponization.relationships.malware_families.attributes.name | Malware family's name. | keyword |
| gti.vulnerability_weaponization.relationships.malware_families.id | Unique identifier for the malware family associated with the entity. | keyword |
| gti.vulnerability_weaponization.relationships.malware_families.type | The category of relationship. | keyword |
| gti.vulnerability_weaponization.relationships.reports.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.vulnerability_weaponization.relationships.reports.attributes.name | Report's title. | keyword |
| gti.vulnerability_weaponization.relationships.reports.id | Unique identifier for the report detailing the entity's analysis. | keyword |
| gti.vulnerability_weaponization.relationships.reports.type | The category of relationship. | keyword |
| gti.vulnerability_weaponization.relationships.software_toolkits.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.vulnerability_weaponization.relationships.software_toolkits.attributes.name | Software or toolkit's name. | keyword |
| gti.vulnerability_weaponization.relationships.software_toolkits.id | Unique identifier for the software or toolkit associated with the entity. | keyword |
| gti.vulnerability_weaponization.relationships.software_toolkits.type | The category of relationship. | keyword |
| gti.vulnerability_weaponization.relationships.threat_actors.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.vulnerability_weaponization.relationships.threat_actors.attributes.name | Threat actor's name. | keyword |
| gti.vulnerability_weaponization.relationships.threat_actors.id | Unique identifier for the threat actor associated with the entity. | keyword |
| gti.vulnerability_weaponization.relationships.threat_actors.type | The category of relationship. | keyword |
| gti.vulnerability_weaponization.relationships.vulnerabilities.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.vulnerability_weaponization.relationships.vulnerabilities.attributes.name | Vulnerability's name. | keyword |
| gti.vulnerability_weaponization.relationships.vulnerabilities.id | Unique identifier for the vulnerability associated with the entity. | keyword |
| gti.vulnerability_weaponization.relationships.vulnerabilities.type | The category of relationship. | keyword |
| gti.vulnerability_weaponization.type | Specifies the nature of the entity, such as file, domain, IP, or URL. | keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| log.offset | Log offset. | long |

