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

Data collection is available for all four feed types: `Linux`, `Malicious Network Infrastructure`, `Malware`, `Mobile` and `OS X`, each with a separate data stream. By default, **Malicious Network Infrastructure** is enabled. Users can enable additional data streams based on their GTI subscription tier. If a user enables data collection for a data stream they do not have access to, it will result in an error log on the **Discover** page.

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

### Linux

This is the `Linux` dataset.

#### Example

An example event for `linux` looks as following:

```json
{
    "@timestamp": "2025-01-27T19:51:31.000Z",
    "agent": {
        "ephemeral_id": "e75ac915-fb7f-493d-abbc-8f53c7dd5e01",
        "id": "9fb4d3c7-be37-48bf-b12e-5cf66fefcf98",
        "name": "elastic-agent-74350",
        "type": "filebeat",
        "version": "8.17.3"
    },
    "data_stream": {
        "dataset": "ti_google_threat_intelligence.linux",
        "namespace": "69256",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "9fb4d3c7-be37-48bf-b12e-5cf66fefcf98",
        "snapshot": false,
        "version": "8.17.3"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_google_threat_intelligence.linux",
        "ingested": "2025-05-25T14:53:39Z",
        "kind": "enrichment",
        "original": "{\"data\":{\"attributes\":{\"first_submission_date\":1582817050,\"gti_assessment\":{\"severity\":{\"value\":\"SEVERITY_NONE\"},\"threat_score\":{\"value\":1},\"verdict\":{\"value\":\"VERDICT_UNDETECTED\"}},\"last_analysis_date\":1582817050,\"last_analysis_stats\":{\"harmless\":55,\"malicious\":8,\"undetected\":8},\"last_http_response_code\":200,\"last_modification_date\":1738007491,\"last_submission_date\":1582817050,\"positives\":8,\"times_submitted\":1,\"tld\":\"ru\",\"url\":\"http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin\"},\"id\":\"0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c\",\"relationships\":{},\"type\":\"url\"}}",
        "type": [
            "indicator"
        ]
    },
    "gti": {
        "linux": {
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
        "hash": [
            "0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c"
        ],
        "hosts": [
            "securepasswel.ru"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "google_threat_intelligence-linux"
    ],
    "threat": {
        "feed": {
            "name": "Linux"
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
| gti.linux.attributes.as_number | The autonomous system number to which the IP belongs. | long |
| gti.linux.attributes.as_owner | The owner of the autonomous system to which the IP belongs. | keyword |
| gti.linux.attributes.categories | Categories based on the predefined criteria. | keyword |
| gti.linux.attributes.continent | The continent where the IP is placed (ISO-3166 continent code). | keyword |
| gti.linux.attributes.country | The country where the IP is placed (ISO-3166 country code). | keyword |
| gti.linux.attributes.creation_date | The date when the IOC was created. | date |
| gti.linux.attributes.first_submission_date | The UTC timestamp of the date when the URL was first submitted to Google Threat Intelligence. | date |
| gti.linux.attributes.gti_assessment.severity | The threat severity level. | keyword |
| gti.linux.attributes.gti_assessment.threat_score | The Google Threat Intelligence score is a function of the verdict and severity, and leverages additional internal factors to generate the score. | long |
| gti.linux.attributes.gti_assessment.verdict | Indicates the assessed threat verdict, which can be benign, undetected, suspicious, malicious, or unknown. | keyword |
| gti.linux.attributes.jarm | A JARM hash representing the entity's TLS fingerprint, used for identifying and classifying servers. | keyword |
| gti.linux.attributes.last_analysis_date | The most recent scan date. | date |
| gti.linux.attributes.last_analysis_results.engine | The name of the security engine that performed the analysis. | keyword |
| gti.linux.attributes.last_analysis_results.result | The outcome of the analysis performed by the security engine. | keyword |
| gti.linux.attributes.last_analysis_stats.harmless | Number of reports saying that is harmless. | long |
| gti.linux.attributes.last_analysis_stats.malicious | Number of reports saying that is malicious. | long |
| gti.linux.attributes.last_analysis_stats.suspicious | Number of reports saying that is suspicious. | long |
| gti.linux.attributes.last_analysis_stats.timeout | Number of reports saying that is timeout. | long |
| gti.linux.attributes.last_analysis_stats.undetected | Number of reports saying that is undetected. | long |
| gti.linux.attributes.last_final_url | The URL if the original URL redirects, where does it end. | keyword |
| gti.linux.attributes.last_http_response_code | The HTTP response code of the last response. | long |
| gti.linux.attributes.last_modification_date | The date when the object itself was last modified. | date |
| gti.linux.attributes.last_submission_date | The most recent date the entity was submitted for analysis. | date |
| gti.linux.attributes.md5 | The file's MD5 hash. | keyword |
| gti.linux.attributes.meaningful_name | The most interesting name out of all file's names. | keyword |
| gti.linux.attributes.names | All file names associated with the file. | keyword |
| gti.linux.attributes.network | The IPv4 network range to which the IP belongs. | keyword |
| gti.linux.attributes.outgoing_links | Containing links to different domains. | keyword |
| gti.linux.attributes.positives | The number of security engines that flagged the entity as malicious. | long |
| gti.linux.attributes.regional_internet_registry | One of the current RIRs. | keyword |
| gti.linux.attributes.tags | A list of representative attributes. | keyword |
| gti.linux.attributes.times_submitted | The number of times the entity has been submitted for analysis. | long |
| gti.linux.attributes.title | The webpage title. | keyword |
| gti.linux.attributes.top_level_domain | The highest level of the domain name (e.g., .com, .org). | keyword |
| gti.linux.attributes.type_tags | The broader tags related to the specific file type. | keyword |
| gti.linux.attributes.url | The original URL to be scanned. | keyword |
| gti.linux.attributes.vhash | An in-house similarity clustering algorithm value, based on a simple structural feature hash allows you to find similar files. | keyword |
| gti.linux.id | The unique ID associated with the entity. | keyword |
| gti.linux.relationships.campaigns.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.linux.relationships.campaigns.attributes.name | Campaign's name. | keyword |
| gti.linux.relationships.campaigns.id | The unique identifier associated with a specific relationship entry. | keyword |
| gti.linux.relationships.campaigns.type | The category of relationship. | keyword |
| gti.linux.relationships.collections.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.linux.relationships.collections.attributes.name | Collection's name. | keyword |
| gti.linux.relationships.collections.id | Unique identifier for the collection grouping related entities. | keyword |
| gti.linux.relationships.collections.type | The category of relationship. | keyword |
| gti.linux.relationships.malware_families.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.linux.relationships.malware_families.attributes.name | Malware family's name. | keyword |
| gti.linux.relationships.malware_families.id | Unique identifier for the malware family associated with the entity. | keyword |
| gti.linux.relationships.malware_families.type | The category of relationship. | keyword |
| gti.linux.relationships.reports.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.linux.relationships.reports.attributes.name | Report's title. | keyword |
| gti.linux.relationships.reports.id | Unique identifier for the report detailing the entity's analysis. | keyword |
| gti.linux.relationships.reports.type | The category of relationship. | keyword |
| gti.linux.relationships.software_toolkits.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.linux.relationships.software_toolkits.attributes.name | Software or toolkit's name. | keyword |
| gti.linux.relationships.software_toolkits.id | Unique identifier for the software or toolkit associated with the entity. | keyword |
| gti.linux.relationships.software_toolkits.type | The category of relationship. | keyword |
| gti.linux.relationships.threat_actors.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.linux.relationships.threat_actors.attributes.name | Threat actor's name. | keyword |
| gti.linux.relationships.threat_actors.id | Unique identifier for the threat actor associated with the entity. | keyword |
| gti.linux.relationships.threat_actors.type | The category of relationship. | keyword |
| gti.linux.relationships.vulnerabilities.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.linux.relationships.vulnerabilities.attributes.name | Vulnerability's name. | keyword |
| gti.linux.relationships.vulnerabilities.id | Unique identifier for the vulnerability associated with the entity. | keyword |
| gti.linux.relationships.vulnerabilities.type | The category of relationship. | keyword |
| gti.linux.type | Specifies the nature of the entity, such as file, domain, IP, or URL. | keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| log.offset | Log offset. | long |


### Malicious Network Infra

This is the `Malicious Network Infra` dataset.

#### Example

An example event for `malicious_network_infrastructure` looks as following:

```json
{
    "@timestamp": "2025-01-27T19:51:31.000Z",
    "agent": {
        "ephemeral_id": "902a93a9-790a-4b5e-a6b8-cd6ad3b9994f",
        "id": "68580c81-e7dc-4305-a5e7-963bb0ca7a5a",
        "name": "elastic-agent-55395",
        "type": "filebeat",
        "version": "8.17.3"
    },
    "data_stream": {
        "dataset": "ti_google_threat_intelligence.malicious_network_infrastructure",
        "namespace": "78822",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "68580c81-e7dc-4305-a5e7-963bb0ca7a5a",
        "snapshot": false,
        "version": "8.17.3"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat",
            "network"
        ],
        "dataset": "ti_google_threat_intelligence.malicious_network_infrastructure",
        "ingested": "2025-05-25T14:56:19Z",
        "kind": "enrichment",
        "original": "{\"data\":{\"attributes\":{\"first_submission_date\":1582817050,\"gti_assessment\":{\"severity\":{\"value\":\"SEVERITY_NONE\"},\"threat_score\":{\"value\":1},\"verdict\":{\"value\":\"VERDICT_UNDETECTED\"}},\"last_analysis_date\":1582817050,\"last_analysis_stats\":{\"harmless\":55,\"malicious\":8,\"undetected\":8},\"last_http_response_code\":200,\"last_modification_date\":1738007491,\"last_submission_date\":1582817050,\"positives\":8,\"times_submitted\":1,\"tld\":\"ru\",\"url\":\"http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin\"},\"id\":\"0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c\",\"relationships\":{},\"type\":\"url\"}}",
        "type": [
            "indicator",
            "info"
        ]
    },
    "gti": {
        "malicious_network_infrastructure": {
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
        "hash": [
            "0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c"
        ],
        "hosts": [
            "securepasswel.ru"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "google_threat_intelligence-malicious_network_infrastructure"
    ],
    "threat": {
        "feed": {
            "name": "Malicious Network Infra"
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
| gti.malicious_network_infrastructure.attributes.as_number | The autonomous system number to which the IP belongs. | long |
| gti.malicious_network_infrastructure.attributes.as_owner | The owner of the autonomous system to which the IP belongs. | keyword |
| gti.malicious_network_infrastructure.attributes.categories | Categories based on the predefined criteria. | keyword |
| gti.malicious_network_infrastructure.attributes.continent | The continent where the IP is placed (ISO-3166 continent code). | keyword |
| gti.malicious_network_infrastructure.attributes.country | The country where the IP is placed (ISO-3166 country code). | keyword |
| gti.malicious_network_infrastructure.attributes.creation_date | The date when the IOC was created. | date |
| gti.malicious_network_infrastructure.attributes.first_submission_date | The UTC timestamp of the date when the URL was first submitted to Google Threat Intelligence. | date |
| gti.malicious_network_infrastructure.attributes.gti_assessment.severity | The threat severity level. | keyword |
| gti.malicious_network_infrastructure.attributes.gti_assessment.threat_score | The Google Threat Intelligence score is a function of the verdict and severity, and leverages additional internal factors to generate the score. | long |
| gti.malicious_network_infrastructure.attributes.gti_assessment.verdict | Indicates the assessed threat verdict, which can be benign, undetected, suspicious, malicious, or unknown. | keyword |
| gti.malicious_network_infrastructure.attributes.jarm | A JARM hash representing the entity's TLS fingerprint, used for identifying and classifying servers. | keyword |
| gti.malicious_network_infrastructure.attributes.last_analysis_date | The most recent scan date. | date |
| gti.malicious_network_infrastructure.attributes.last_analysis_results.engine | The name of the security engine that performed the analysis. | keyword |
| gti.malicious_network_infrastructure.attributes.last_analysis_results.result | The outcome of the analysis performed by the security engine. | keyword |
| gti.malicious_network_infrastructure.attributes.last_analysis_stats.harmless | Number of reports saying that is harmless. | long |
| gti.malicious_network_infrastructure.attributes.last_analysis_stats.malicious | Number of reports saying that is malicious. | long |
| gti.malicious_network_infrastructure.attributes.last_analysis_stats.suspicious | Number of reports saying that is suspicious. | long |
| gti.malicious_network_infrastructure.attributes.last_analysis_stats.timeout | Number of reports saying that is timeout. | long |
| gti.malicious_network_infrastructure.attributes.last_analysis_stats.undetected | Number of reports saying that is undetected. | long |
| gti.malicious_network_infrastructure.attributes.last_final_url | The URL if the original URL redirects, where does it end. | keyword |
| gti.malicious_network_infrastructure.attributes.last_http_response_code | The HTTP response code of the last response. | long |
| gti.malicious_network_infrastructure.attributes.last_modification_date | The date when the object itself was last modified. | date |
| gti.malicious_network_infrastructure.attributes.last_submission_date | The most recent date the entity was submitted for analysis. | date |
| gti.malicious_network_infrastructure.attributes.md5 | The file's MD5 hash. | keyword |
| gti.malicious_network_infrastructure.attributes.meaningful_name | The most interesting name out of all file's names. | keyword |
| gti.malicious_network_infrastructure.attributes.names | All file names associated with the file. | keyword |
| gti.malicious_network_infrastructure.attributes.network | The IPv4 network range to which the IP belongs. | keyword |
| gti.malicious_network_infrastructure.attributes.outgoing_links | Containing links to different domains. | keyword |
| gti.malicious_network_infrastructure.attributes.positives | The number of security engines that flagged the entity as malicious. | long |
| gti.malicious_network_infrastructure.attributes.regional_internet_registry | One of the current RIRs. | keyword |
| gti.malicious_network_infrastructure.attributes.tags | A list of representative attributes. | keyword |
| gti.malicious_network_infrastructure.attributes.times_submitted | The number of times the entity has been submitted for analysis. | long |
| gti.malicious_network_infrastructure.attributes.title | The webpage title. | keyword |
| gti.malicious_network_infrastructure.attributes.top_level_domain | The highest level of the domain name (e.g., .com, .org). | keyword |
| gti.malicious_network_infrastructure.attributes.type_tags | The broader tags related to the specific file type. | keyword |
| gti.malicious_network_infrastructure.attributes.url | The original URL to be scanned. | keyword |
| gti.malicious_network_infrastructure.attributes.vhash | An in-house similarity clustering algorithm value, based on a simple structural feature hash allows you to find similar files. | keyword |
| gti.malicious_network_infrastructure.id | The unique ID associated with the entity. | keyword |
| gti.malicious_network_infrastructure.relationships.campaigns.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.malicious_network_infrastructure.relationships.campaigns.attributes.name | Campaign's name. | keyword |
| gti.malicious_network_infrastructure.relationships.campaigns.id | The unique identifier associated with a specific relationship entry. | keyword |
| gti.malicious_network_infrastructure.relationships.campaigns.type | The category of relationship. | keyword |
| gti.malicious_network_infrastructure.relationships.collections.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.malicious_network_infrastructure.relationships.collections.attributes.name | Collection's name. | keyword |
| gti.malicious_network_infrastructure.relationships.collections.id | Unique identifier for the collection grouping related entities. | keyword |
| gti.malicious_network_infrastructure.relationships.collections.type | The category of relationship. | keyword |
| gti.malicious_network_infrastructure.relationships.malware_families.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.malicious_network_infrastructure.relationships.malware_families.attributes.name | Malware family's name. | keyword |
| gti.malicious_network_infrastructure.relationships.malware_families.id | Unique identifier for the malware family associated with the entity. | keyword |
| gti.malicious_network_infrastructure.relationships.malware_families.type | The category of relationship. | keyword |
| gti.malicious_network_infrastructure.relationships.reports.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.malicious_network_infrastructure.relationships.reports.attributes.name | Report's title. | keyword |
| gti.malicious_network_infrastructure.relationships.reports.id | Unique identifier for the report detailing the entity's analysis. | keyword |
| gti.malicious_network_infrastructure.relationships.reports.type | The category of relationship. | keyword |
| gti.malicious_network_infrastructure.relationships.software_toolkits.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.malicious_network_infrastructure.relationships.software_toolkits.attributes.name | Software or toolkit's name. | keyword |
| gti.malicious_network_infrastructure.relationships.software_toolkits.id | Unique identifier for the software or toolkit associated with the entity. | keyword |
| gti.malicious_network_infrastructure.relationships.software_toolkits.type | The category of relationship. | keyword |
| gti.malicious_network_infrastructure.relationships.threat_actors.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.malicious_network_infrastructure.relationships.threat_actors.attributes.name | Threat actor's name. | keyword |
| gti.malicious_network_infrastructure.relationships.threat_actors.id | Unique identifier for the threat actor associated with the entity. | keyword |
| gti.malicious_network_infrastructure.relationships.threat_actors.type | The category of relationship. | keyword |
| gti.malicious_network_infrastructure.relationships.vulnerabilities.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.malicious_network_infrastructure.relationships.vulnerabilities.attributes.name | Vulnerability's name. | keyword |
| gti.malicious_network_infrastructure.relationships.vulnerabilities.id | Unique identifier for the vulnerability associated with the entity. | keyword |
| gti.malicious_network_infrastructure.relationships.vulnerabilities.type | The category of relationship. | keyword |
| gti.malicious_network_infrastructure.type | Specifies the nature of the entity, such as file, domain, IP, or URL. | keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| log.offset | Log offset. | long |


### Malware

This is the `Malware` dataset.

#### Example

An example event for `malware` looks as following:

```json
{
    "@timestamp": "2025-01-27T19:51:31.000Z",
    "agent": {
        "ephemeral_id": "155d046c-55f3-42b1-8490-3bb03cb23f34",
        "id": "7a0848bd-9142-4e0c-bf5c-0431c307729a",
        "name": "elastic-agent-96548",
        "type": "filebeat",
        "version": "8.17.3"
    },
    "data_stream": {
        "dataset": "ti_google_threat_intelligence.malware",
        "namespace": "78464",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "7a0848bd-9142-4e0c-bf5c-0431c307729a",
        "snapshot": false,
        "version": "8.17.3"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat",
            "malware"
        ],
        "dataset": "ti_google_threat_intelligence.malware",
        "ingested": "2025-05-25T14:59:00Z",
        "kind": "enrichment",
        "original": "{\"data\":{\"attributes\":{\"first_submission_date\":1582817050,\"gti_assessment\":{\"severity\":{\"value\":\"SEVERITY_NONE\"},\"threat_score\":{\"value\":1},\"verdict\":{\"value\":\"VERDICT_UNDETECTED\"}},\"last_analysis_date\":1582817050,\"last_analysis_stats\":{\"harmless\":55,\"malicious\":8,\"undetected\":8},\"last_http_response_code\":200,\"last_modification_date\":1738007491,\"last_submission_date\":1582817050,\"positives\":8,\"times_submitted\":1,\"tld\":\"ru\",\"url\":\"http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin\"},\"id\":\"0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c\",\"relationships\":{},\"type\":\"url\"}}",
        "type": [
            "indicator",
            "info"
        ]
    },
    "gti": {
        "malware": {
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
        "hash": [
            "0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c"
        ],
        "hosts": [
            "securepasswel.ru"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "google_threat_intelligence-malware"
    ],
    "threat": {
        "feed": {
            "name": "Malware"
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
| gti.malware.attributes.as_number | The autonomous system number to which the IP belongs. | long |
| gti.malware.attributes.as_owner | The owner of the autonomous system to which the IP belongs. | keyword |
| gti.malware.attributes.categories | Categories based on the predefined criteria. | keyword |
| gti.malware.attributes.continent | The continent where the IP is placed (ISO-3166 continent code). | keyword |
| gti.malware.attributes.country | The country where the IP is placed (ISO-3166 country code). | keyword |
| gti.malware.attributes.creation_date | The date when the IOC was created. | date |
| gti.malware.attributes.first_submission_date | The UTC timestamp of the date when the URL was first submitted to Google Threat Intelligence. | date |
| gti.malware.attributes.gti_assessment.severity | The threat severity level. | keyword |
| gti.malware.attributes.gti_assessment.threat_score | The Google Threat Intelligence score is a function of the verdict and severity, and leverages additional internal factors to generate the score. | long |
| gti.malware.attributes.gti_assessment.verdict | Indicates the assessed threat verdict, which can be benign, undetected, suspicious, malicious, or unknown. | keyword |
| gti.malware.attributes.jarm | A JARM hash representing the entity's TLS fingerprint, used for identifying and classifying servers. | keyword |
| gti.malware.attributes.last_analysis_date | The most recent scan date. | date |
| gti.malware.attributes.last_analysis_results.engine | The name of the security engine that performed the analysis. | keyword |
| gti.malware.attributes.last_analysis_results.result | The outcome of the analysis performed by the security engine. | keyword |
| gti.malware.attributes.last_analysis_stats.harmless | Number of reports saying that is harmless. | long |
| gti.malware.attributes.last_analysis_stats.malicious | Number of reports saying that is malicious. | long |
| gti.malware.attributes.last_analysis_stats.suspicious | Number of reports saying that is suspicious. | long |
| gti.malware.attributes.last_analysis_stats.timeout | Number of reports saying that is timeout. | long |
| gti.malware.attributes.last_analysis_stats.undetected | Number of reports saying that is undetected. | long |
| gti.malware.attributes.last_final_url | The URL if the original URL redirects, where does it end. | keyword |
| gti.malware.attributes.last_http_response_code | The HTTP response code of the last response. | long |
| gti.malware.attributes.last_modification_date | The date when the object itself was last modified. | date |
| gti.malware.attributes.last_submission_date | The most recent date the entity was submitted for analysis. | date |
| gti.malware.attributes.md5 | The file's MD5 hash. | keyword |
| gti.malware.attributes.meaningful_name | The most interesting name out of all file's names. | keyword |
| gti.malware.attributes.names | All file names associated with the file. | keyword |
| gti.malware.attributes.network | The IPv4 network range to which the IP belongs. | keyword |
| gti.malware.attributes.outgoing_links | Containing links to different domains. | keyword |
| gti.malware.attributes.positives | The number of security engines that flagged the entity as malicious. | long |
| gti.malware.attributes.regional_internet_registry | One of the current RIRs. | keyword |
| gti.malware.attributes.tags | A list of representative attributes. | keyword |
| gti.malware.attributes.times_submitted | The number of times the entity has been submitted for analysis. | long |
| gti.malware.attributes.title | The webpage title. | keyword |
| gti.malware.attributes.top_level_domain | The highest level of the domain name (e.g., .com, .org). | keyword |
| gti.malware.attributes.type_tags | The broader tags related to the specific file type. | keyword |
| gti.malware.attributes.url | The original URL to be scanned. | keyword |
| gti.malware.attributes.vhash | An in-house similarity clustering algorithm value, based on a simple structural feature hash allows you to find similar files. | keyword |
| gti.malware.id | The unique ID associated with the entity. | keyword |
| gti.malware.relationships.campaigns.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.malware.relationships.campaigns.attributes.name | Campaign's name. | keyword |
| gti.malware.relationships.campaigns.id | The unique identifier associated with a specific relationship entry. | keyword |
| gti.malware.relationships.campaigns.type | The category of relationship. | keyword |
| gti.malware.relationships.collections.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.malware.relationships.collections.attributes.name | Collection's name. | keyword |
| gti.malware.relationships.collections.id | Unique identifier for the collection grouping related entities. | keyword |
| gti.malware.relationships.collections.type | The category of relationship. | keyword |
| gti.malware.relationships.malware_families.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.malware.relationships.malware_families.attributes.name | Malware family's name. | keyword |
| gti.malware.relationships.malware_families.id | Unique identifier for the malware family associated with the entity. | keyword |
| gti.malware.relationships.malware_families.type | The category of relationship. | keyword |
| gti.malware.relationships.reports.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.malware.relationships.reports.attributes.name | Report's title. | keyword |
| gti.malware.relationships.reports.id | Unique identifier for the report detailing the entity's analysis. | keyword |
| gti.malware.relationships.reports.type | The category of relationship. | keyword |
| gti.malware.relationships.software_toolkits.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.malware.relationships.software_toolkits.attributes.name | Software or toolkit's name. | keyword |
| gti.malware.relationships.software_toolkits.id | Unique identifier for the software or toolkit associated with the entity. | keyword |
| gti.malware.relationships.software_toolkits.type | The category of relationship. | keyword |
| gti.malware.relationships.threat_actors.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.malware.relationships.threat_actors.attributes.name | Threat actor's name. | keyword |
| gti.malware.relationships.threat_actors.id | Unique identifier for the threat actor associated with the entity. | keyword |
| gti.malware.relationships.threat_actors.type | The category of relationship. | keyword |
| gti.malware.relationships.vulnerabilities.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.malware.relationships.vulnerabilities.attributes.name | Vulnerability's name. | keyword |
| gti.malware.relationships.vulnerabilities.id | Unique identifier for the vulnerability associated with the entity. | keyword |
| gti.malware.relationships.vulnerabilities.type | The category of relationship. | keyword |
| gti.malware.type | Specifies the nature of the entity, such as file, domain, IP, or URL. | keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| log.offset | Log offset. | long |


### Mobile

This is the `Mobile` dataset.

#### Example

An example event for `mobile` looks as following:

```json
{
    "@timestamp": "2025-01-27T19:51:31.000Z",
    "agent": {
        "ephemeral_id": "43e638c8-0c88-492d-a828-63f34faedab1",
        "id": "251b5b7b-36ba-4a10-aa28-8d8bd480b47a",
        "name": "elastic-agent-98806",
        "type": "filebeat",
        "version": "8.17.3"
    },
    "data_stream": {
        "dataset": "ti_google_threat_intelligence.mobile",
        "namespace": "88304",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "251b5b7b-36ba-4a10-aa28-8d8bd480b47a",
        "snapshot": false,
        "version": "8.17.3"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_google_threat_intelligence.mobile",
        "ingested": "2025-05-25T15:01:40Z",
        "kind": "enrichment",
        "original": "{\"data\":{\"attributes\":{\"first_submission_date\":1582817050,\"gti_assessment\":{\"severity\":{\"value\":\"SEVERITY_NONE\"},\"threat_score\":{\"value\":1},\"verdict\":{\"value\":\"VERDICT_UNDETECTED\"}},\"last_analysis_date\":1582817050,\"last_analysis_stats\":{\"harmless\":55,\"malicious\":8,\"undetected\":8},\"last_http_response_code\":200,\"last_modification_date\":1738007491,\"last_submission_date\":1582817050,\"positives\":8,\"times_submitted\":1,\"tld\":\"ru\",\"url\":\"http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin\"},\"id\":\"0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c\",\"relationships\":{},\"type\":\"url\"}}",
        "type": [
            "indicator"
        ]
    },
    "gti": {
        "mobile": {
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
        "hash": [
            "0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c"
        ],
        "hosts": [
            "securepasswel.ru"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "google_threat_intelligence-mobile"
    ],
    "threat": {
        "feed": {
            "name": "Mobile"
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
| gti.mobile.attributes.as_number | The autonomous system number to which the IP belongs. | long |
| gti.mobile.attributes.as_owner | The owner of the autonomous system to which the IP belongs. | keyword |
| gti.mobile.attributes.categories | Categories based on the predefined criteria. | keyword |
| gti.mobile.attributes.continent | The continent where the IP is placed (ISO-3166 continent code). | keyword |
| gti.mobile.attributes.country | The country where the IP is placed (ISO-3166 country code). | keyword |
| gti.mobile.attributes.creation_date | The date when the IOC was created. | date |
| gti.mobile.attributes.first_submission_date | The UTC timestamp of the date when the URL was first submitted to Google Threat Intelligence. | date |
| gti.mobile.attributes.gti_assessment.severity | The threat severity level. | keyword |
| gti.mobile.attributes.gti_assessment.threat_score | The Google Threat Intelligence score is a function of the verdict and severity, and leverages additional internal factors to generate the score. | long |
| gti.mobile.attributes.gti_assessment.verdict | Indicates the assessed threat verdict, which can be benign, undetected, suspicious, malicious, or unknown. | keyword |
| gti.mobile.attributes.jarm | A JARM hash representing the entity's TLS fingerprint, used for identifying and classifying servers. | keyword |
| gti.mobile.attributes.last_analysis_date | The most recent scan date. | date |
| gti.mobile.attributes.last_analysis_results.engine | The name of the security engine that performed the analysis. | keyword |
| gti.mobile.attributes.last_analysis_results.result | The outcome of the analysis performed by the security engine. | keyword |
| gti.mobile.attributes.last_analysis_stats.harmless | Number of reports saying that is harmless. | long |
| gti.mobile.attributes.last_analysis_stats.malicious | Number of reports saying that is malicious. | long |
| gti.mobile.attributes.last_analysis_stats.suspicious | Number of reports saying that is suspicious. | long |
| gti.mobile.attributes.last_analysis_stats.timeout | Number of reports saying that is timeout. | long |
| gti.mobile.attributes.last_analysis_stats.undetected | Number of reports saying that is undetected. | long |
| gti.mobile.attributes.last_final_url | The URL if the original URL redirects, where does it end. | keyword |
| gti.mobile.attributes.last_http_response_code | The HTTP response code of the last response. | long |
| gti.mobile.attributes.last_modification_date | The date when the object itself was last modified. | date |
| gti.mobile.attributes.last_submission_date | The most recent date the entity was submitted for analysis. | date |
| gti.mobile.attributes.md5 | The file's MD5 hash. | keyword |
| gti.mobile.attributes.meaningful_name | The most interesting name out of all file's names. | keyword |
| gti.mobile.attributes.names | All file names associated with the file. | keyword |
| gti.mobile.attributes.network | The IPv4 network range to which the IP belongs. | keyword |
| gti.mobile.attributes.outgoing_links | Containing links to different domains. | keyword |
| gti.mobile.attributes.positives | The number of security engines that flagged the entity as malicious. | long |
| gti.mobile.attributes.regional_internet_registry | One of the current RIRs. | keyword |
| gti.mobile.attributes.tags | A list of representative attributes. | keyword |
| gti.mobile.attributes.times_submitted | The number of times the entity has been submitted for analysis. | long |
| gti.mobile.attributes.title | The webpage title. | keyword |
| gti.mobile.attributes.top_level_domain | The highest level of the domain name (e.g., .com, .org). | keyword |
| gti.mobile.attributes.type_tags | The broader tags related to the specific file type. | keyword |
| gti.mobile.attributes.url | The original URL to be scanned. | keyword |
| gti.mobile.attributes.vhash | An in-house similarity clustering algorithm value, based on a simple structural feature hash allows you to find similar files. | keyword |
| gti.mobile.id | The unique ID associated with the entity. | keyword |
| gti.mobile.relationships.campaigns.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.mobile.relationships.campaigns.attributes.name | Campaign's name. | keyword |
| gti.mobile.relationships.campaigns.id | The unique identifier associated with a specific relationship entry. | keyword |
| gti.mobile.relationships.campaigns.type | The category of relationship. | keyword |
| gti.mobile.relationships.collections.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.mobile.relationships.collections.attributes.name | Collection's name. | keyword |
| gti.mobile.relationships.collections.id | Unique identifier for the collection grouping related entities. | keyword |
| gti.mobile.relationships.collections.type | The category of relationship. | keyword |
| gti.mobile.relationships.malware_families.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.mobile.relationships.malware_families.attributes.name | Malware family's name. | keyword |
| gti.mobile.relationships.malware_families.id | Unique identifier for the malware family associated with the entity. | keyword |
| gti.mobile.relationships.malware_families.type | The category of relationship. | keyword |
| gti.mobile.relationships.reports.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.mobile.relationships.reports.attributes.name | Report's title. | keyword |
| gti.mobile.relationships.reports.id | Unique identifier for the report detailing the entity's analysis. | keyword |
| gti.mobile.relationships.reports.type | The category of relationship. | keyword |
| gti.mobile.relationships.software_toolkits.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.mobile.relationships.software_toolkits.attributes.name | Software or toolkit's name. | keyword |
| gti.mobile.relationships.software_toolkits.id | Unique identifier for the software or toolkit associated with the entity. | keyword |
| gti.mobile.relationships.software_toolkits.type | The category of relationship. | keyword |
| gti.mobile.relationships.threat_actors.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.mobile.relationships.threat_actors.attributes.name | Threat actor's name. | keyword |
| gti.mobile.relationships.threat_actors.id | Unique identifier for the threat actor associated with the entity. | keyword |
| gti.mobile.relationships.threat_actors.type | The category of relationship. | keyword |
| gti.mobile.relationships.vulnerabilities.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.mobile.relationships.vulnerabilities.attributes.name | Vulnerability's name. | keyword |
| gti.mobile.relationships.vulnerabilities.id | Unique identifier for the vulnerability associated with the entity. | keyword |
| gti.mobile.relationships.vulnerabilities.type | The category of relationship. | keyword |
| gti.mobile.type | Specifies the nature of the entity, such as file, domain, IP, or URL. | keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| log.offset | Log offset. | long |


### OS X

This is the `OS X` dataset.

#### Example

An example event for `osx` looks as following:

```json
{
    "@timestamp": "2025-01-27T19:51:31.000Z",
    "agent": {
        "ephemeral_id": "dceed577-7f00-4b9c-8ec7-e2e79fdde06d",
        "id": "c43eefa8-325c-4da8-9504-c64742834cdd",
        "name": "elastic-agent-81585",
        "type": "filebeat",
        "version": "8.17.3"
    },
    "data_stream": {
        "dataset": "ti_google_threat_intelligence.osx",
        "namespace": "89614",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "c43eefa8-325c-4da8-9504-c64742834cdd",
        "snapshot": false,
        "version": "8.17.3"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_google_threat_intelligence.osx",
        "ingested": "2025-05-25T15:04:20Z",
        "kind": "enrichment",
        "original": "{\"data\":{\"attributes\":{\"first_submission_date\":1582817050,\"gti_assessment\":{\"severity\":{\"value\":\"SEVERITY_NONE\"},\"threat_score\":{\"value\":1},\"verdict\":{\"value\":\"VERDICT_UNDETECTED\"}},\"last_analysis_date\":1582817050,\"last_analysis_stats\":{\"harmless\":55,\"malicious\":8,\"undetected\":8},\"last_http_response_code\":200,\"last_modification_date\":1738007491,\"last_submission_date\":1582817050,\"positives\":8,\"times_submitted\":1,\"tld\":\"ru\",\"url\":\"http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin\"},\"id\":\"0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c\",\"relationships\":{},\"type\":\"url\"}}",
        "type": [
            "indicator"
        ]
    },
    "gti": {
        "osx": {
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
        "hash": [
            "0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c"
        ],
        "hosts": [
            "securepasswel.ru"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "google_threat_intelligence-osx"
    ],
    "threat": {
        "feed": {
            "name": "OS X"
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
| gti.osx.attributes.as_number | The autonomous system number to which the IP belongs. | long |
| gti.osx.attributes.as_owner | The owner of the autonomous system to which the IP belongs. | keyword |
| gti.osx.attributes.categories | Categories based on the predefined criteria. | keyword |
| gti.osx.attributes.continent | The continent where the IP is placed (ISO-3166 continent code). | keyword |
| gti.osx.attributes.country | The country where the IP is placed (ISO-3166 country code). | keyword |
| gti.osx.attributes.creation_date | The date when the IOC was created. | date |
| gti.osx.attributes.first_submission_date | The UTC timestamp of the date when the URL was first submitted to Google Threat Intelligence. | date |
| gti.osx.attributes.gti_assessment.severity | The threat severity level. | keyword |
| gti.osx.attributes.gti_assessment.threat_score | The Google Threat Intelligence score is a function of the verdict and severity, and leverages additional internal factors to generate the score. | long |
| gti.osx.attributes.gti_assessment.verdict | Indicates the assessed threat verdict, which can be benign, undetected, suspicious, malicious, or unknown. | keyword |
| gti.osx.attributes.jarm | A JARM hash representing the entity's TLS fingerprint, used for identifying and classifying servers. | keyword |
| gti.osx.attributes.last_analysis_date | The most recent scan date. | date |
| gti.osx.attributes.last_analysis_results.engine | The name of the security engine that performed the analysis. | keyword |
| gti.osx.attributes.last_analysis_results.result | The outcome of the analysis performed by the security engine. | keyword |
| gti.osx.attributes.last_analysis_stats.harmless | Number of reports saying that is harmless. | long |
| gti.osx.attributes.last_analysis_stats.malicious | Number of reports saying that is malicious. | long |
| gti.osx.attributes.last_analysis_stats.suspicious | Number of reports saying that is suspicious. | long |
| gti.osx.attributes.last_analysis_stats.timeout | Number of reports saying that is timeout. | long |
| gti.osx.attributes.last_analysis_stats.undetected | Number of reports saying that is undetected. | long |
| gti.osx.attributes.last_final_url | The URL if the original URL redirects, where does it end. | keyword |
| gti.osx.attributes.last_http_response_code | The HTTP response code of the last response. | long |
| gti.osx.attributes.last_modification_date | The date when the object itself was last modified. | date |
| gti.osx.attributes.last_submission_date | The most recent date the entity was submitted for analysis. | date |
| gti.osx.attributes.md5 | The file's MD5 hash. | keyword |
| gti.osx.attributes.meaningful_name | The most interesting name out of all file's names. | keyword |
| gti.osx.attributes.names | All file names associated with the file. | keyword |
| gti.osx.attributes.network | The IPv4 network range to which the IP belongs. | keyword |
| gti.osx.attributes.outgoing_links | Containing links to different domains. | keyword |
| gti.osx.attributes.positives | The number of security engines that flagged the entity as malicious. | long |
| gti.osx.attributes.regional_internet_registry | One of the current RIRs. | keyword |
| gti.osx.attributes.tags | A list of representative attributes. | keyword |
| gti.osx.attributes.times_submitted | The number of times the entity has been submitted for analysis. | long |
| gti.osx.attributes.title | The webpage title. | keyword |
| gti.osx.attributes.top_level_domain | The highest level of the domain name (e.g., .com, .org). | keyword |
| gti.osx.attributes.type_tags | The broader tags related to the specific file type. | keyword |
| gti.osx.attributes.url | The original URL to be scanned. | keyword |
| gti.osx.attributes.vhash | An in-house similarity clustering algorithm value, based on a simple structural feature hash allows you to find similar files. | keyword |
| gti.osx.id | The unique ID associated with the entity. | keyword |
| gti.osx.relationships.campaigns.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.osx.relationships.campaigns.attributes.name | Campaign's name. | keyword |
| gti.osx.relationships.campaigns.id | The unique identifier associated with a specific relationship entry. | keyword |
| gti.osx.relationships.campaigns.type | The category of relationship. | keyword |
| gti.osx.relationships.collections.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.osx.relationships.collections.attributes.name | Collection's name. | keyword |
| gti.osx.relationships.collections.id | Unique identifier for the collection grouping related entities. | keyword |
| gti.osx.relationships.collections.type | The category of relationship. | keyword |
| gti.osx.relationships.malware_families.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.osx.relationships.malware_families.attributes.name | Malware family's name. | keyword |
| gti.osx.relationships.malware_families.id | Unique identifier for the malware family associated with the entity. | keyword |
| gti.osx.relationships.malware_families.type | The category of relationship. | keyword |
| gti.osx.relationships.reports.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.osx.relationships.reports.attributes.name | Report's title. | keyword |
| gti.osx.relationships.reports.id | Unique identifier for the report detailing the entity's analysis. | keyword |
| gti.osx.relationships.reports.type | The category of relationship. | keyword |
| gti.osx.relationships.software_toolkits.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.osx.relationships.software_toolkits.attributes.name | Software or toolkit's name. | keyword |
| gti.osx.relationships.software_toolkits.id | Unique identifier for the software or toolkit associated with the entity. | keyword |
| gti.osx.relationships.software_toolkits.type | The category of relationship. | keyword |
| gti.osx.relationships.threat_actors.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.osx.relationships.threat_actors.attributes.name | Threat actor's name. | keyword |
| gti.osx.relationships.threat_actors.id | Unique identifier for the threat actor associated with the entity. | keyword |
| gti.osx.relationships.threat_actors.type | The category of relationship. | keyword |
| gti.osx.relationships.vulnerabilities.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.osx.relationships.vulnerabilities.attributes.name | Vulnerability's name. | keyword |
| gti.osx.relationships.vulnerabilities.id | Unique identifier for the vulnerability associated with the entity. | keyword |
| gti.osx.relationships.vulnerabilities.type | The category of relationship. | keyword |
| gti.osx.type | Specifies the nature of the entity, such as file, domain, IP, or URL. | keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| log.offset | Log offset. | long |

