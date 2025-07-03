# Google Threat Intelligence

## Overview

[Google Threat Intelligence](https://gtidocs.virustotal.com/) is a security solution that helps organizations detect, analyze, and mitigate threats. It leverages Google's global telemetry, advanced analytics, and vast infrastructure to provide actionable insights. Key features include threat detection, malware and phishing analysis, and real-time threat alerts.

Google Threat Intelligence uses the **[Threat List API](https://gtidocs.virustotal.com/reference/get-hourly-threat-list)** to deliver hourly data chunks. The Threat Lists feature allows customers to consume **Indicators of Compromise (IOCs)** categorized by various threat types.

## Threat List API Feeds

The Threat List API provides the following types of threat feeds:

- **Cryptominers**
- **First Stage Delivery Vectors**
- **Infostealers**
- **Internet of Things (IoT)**

## GTI Subscription Tiers

Customers can access a subset of the available threat lists based on their **Google Threat Intelligence (GTI) tier**:

- **GTI Standard**: Ransomware, Malicious Network Infrastructure
- **GTI Enterprise**: Ransomware, Malicious Network Infrastructure, Malware, Threat Actor, Daily Top Trending
- **GTI Enterprise+**: Access to all available threat lists

## Data Streams

Data collection is available for four feed types: `cryptominer`, `first_stage_delivery_vectors`, `infostealer`, and `iot`, each provided through a separate data stream. Users can enable data streams based on their GTI subscription tier. If a user enables data collection for a data stream they do not have access to, it will result in an error log on the **Discover** page.

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

## Setup

### To collect logs through REST API, follow the below steps:

- VirusTotal URL will work as the base URL for this integration: https://www.virustotal.com
- An API key will be used to authenticate your request.
- **Time Selection of Initial Interval and Interval**:
  - Users need to specify the **initial interval** and **interval** in an hourly format, such as **2h**, **3h**, etc.
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

## Transforming Data for Up-to-Date Insights

To keep the collected data up to date, **Transforms** are used.

Users can view the transforms by navigating to **Management > Stack Management > Transforms**.

Follow **Steps to enable transforms** to enable transforms and populate `Threat Feed Overview` dashboard.

Here, users can see continuously running transforms and also view the latest transformed GTI data in the **Discover** section.

The `labels.is_transform_source` field indicates log origin:
- **False** for transformed index
- **True** for source index

Currently, four transforms are available across all 4 data streams.

The following are four transforms along with their associated pipelines:

| Transform Name                                                                                                                                                           | Description                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------- |
| IP Transform (ID: `logs-ti_google_threat_intelligence.ip_ioc`, Pipeline: `ti_google_threat_intelligence-latest_ip_ioc-transform-pipeline`)                               | Keeps IP entity type data up to date.                    |
| URL Transform (ID: `logs-ti_google_threat_intelligence.url_ioc`, Pipeline: `ti_google_threat_intelligence-latest_url_ioc-transform-pipeline`)                            | Keeps URL entity type data up to date.                   |
| Domain Transform (ID: `logs-ti_google_threat_intelligence.domain_ioc`, Pipeline: `ti_google_threat_intelligence-latest_domain_ioc-transform-pipeline`)                   | Keeps Domain entity type data up to date.                |
| File Transform (ID: `logs-ti_google_threat_intelligence.file_ioc`, Pipeline: `ti_google_threat_intelligence-latest_file_ioc-transform-pipeline`)                         | Keeps File entity type data up to date.                  |

For example:

- The query `event.module: ti_google_threat_intelligence and labels.is_transform_source: true` indicates that the logs originate from the **source index**.
- The query `event.module: ti_google_threat_intelligence and labels.is_transform_source: false` indicates that the logs originate from the **transformed index**.

A **retention policy** is used to remove data older than the default retention period. For more details, refer to the [Retention Policy Documentation](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-transform-put-transform#operation-transform-put-transform-body-application-json-retention_policy).

In this integration, all data streams have a **retention period of 30 days**.

### Enrichment with Detection Rules

Detection Rules match the user's Elastic environment data with GTI data, generating an alert if a match is found. To access detection rules:

1. Navigate to **Security > Rules > Detection Rules** and click on **Add Elastic Rules**.
2. Search for **Google Threat Intelligence** to find prebuilt Elastic detection rules.
3. Four detection rules are available for **IP, URL, File, and Domain**. Users can install one or more rules as needed.

To tailor a rule based on Elastic environment:

1. Click the three dots on the right side of any detection rule.
2. Select **Duplicate Rule**.
3. Modify the duplicated rule to tailor it to your Elastic environment:
   - **Index Pattern**: Add the index pattern relevant to your data. Keeping this specific ensures optimal performance.
   - **Custom Query**: Further refine rule conditions.
   - **Indicator Mapping**: Map relevant fields from your Elastic environment to GTI fields. Do not modify the **indicator index field**.
   - **Schedule Rules**:
     - **Set Runs Every** - Defines how frequently the rule runs.
     - **Additional Lookback Time** - Specifies how far back to check for matches.

Once saved, successfully executed rules will generate alerts. Users can view these alerts in the **Alerts** section.

**Note:** A transform runs in the background to filter relevant data from alerts. The `data_stream.dataset: ti_google_threat_intelligence.enriched_ioc` field represents logs for enriched threat intelligence data, which can be analyzed in the **Discover** section.

The following are the names of the four sample rules:

| Sample Rule Name                                      | Description                                                                                                                |
| ----------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Google Threat Intelligence URL IOC Correlation        | Detects and alerts on matches between URL IOCs collected by GTI data with user's selected Elastic environment data.        |
| Google Threat Intelligence Domain IOC Correlation     | Detects and alerts on matches between Domain IOCs collected by GTI data with user's selected Elastic environment data.     |
| Google Threat Intelligence File IOC Correlation       | Detects and alerts on matches between File IOCs collected by GTI data with user's selected Elastic environment data.       |
| Google Threat Intelligence IP Address IOC Correlation | Detects and alerts on matches between IP Address IOCs collected by GTI data with user's selected Elastic environment data. |

The following transform and its associated pipelines are used to filter relevant data from alerts. Follow **Steps to enable transforms** to enable these transforms and populate `Threat Intelligence` and `Adversary Intelligence` dashboards.

| Transform Name                                                                                                                                          | Description                                                                     |
| ------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| Detected IOC Transform  (ID: `logs-ti_google_threat_intelligence.rule`, Pipeline: `ti_google_threat_intelligence-correlation_detection_rule-pipeline`)  | Filters and extracts necessary information from Detected IOCs from threat feed. |

### Steps to enable transforms

1. Navigate to **Stack Management > Transforms** in Kibana.
2. Locate the transform you want to enable by searching for its **Transform ID**.
3. Click the **three dots** next to the transform, then select **Edit**.
4. Under the **Destination configuration** section, set the **Ingest Pipeline**:
   - Each transform in the **Google Threat Intelligence** integration has a corresponding ingest pipeline.
   - Refer to the **Transforms table** above for the appropriate pipeline name associated with transform.
   - Prefix the pipeline name with the integration version.  
     For example:  
     ```
     0.1.0-ti_google_threat_intelligence-latest_ip_ioc-transform-pipeline
     ```
   - Click **Update** to save the changes.
5. Click the **three dots** again next to the transform and select **Start** to activate it.

**Note:** After updating the integration, make sure to update the pipeline prefix accordingly.

## Limitations

1. If an event contains multiple matching mappings (e.g., two file hash fields within the same event match GTI data), only one alert per detection rule will be generated for that event.
2. If an IOC from the user's Elasticsearch index is enriched with GTI information, and the GTI information is updated later, the changes are not reflected in the dashboards because Elastic detection rules only run on live data.

## Troubleshooting

1. If you encounter a privilege error for a threat feed type, such as: `You are not authorized to perform the requested operation`, verify your privilege level and enable only the threat feeds you have access to.
2. If you see an error like `Package 2025031310 is not available until 2025-03-13 at 11:00 UTC because of privacy policy.`, ensure that your initial interval and interval are set in hours and are greater than one hour.
3. If events are not appearing in the transformed index, check if transforms are running without errors. If you encounter issues, refer to [Troubleshooting transforms](https://www.elastic.co/guide/en/elasticsearch/reference/current/transform-troubleshooting.html).
4. If detection rules take longer to run, ensure you have specified index patterns and applied queries to make your source events more specific.
   **Note:** More events in index patterns mean more time needed for detection rules to run.
5. Ensure that relevant fields are correctly mapped in the **Indicator Mapping** section. Verify that fields in the specified index pattern are properly mapped, and ensure entity-specific fields (e.g., IP fields to IP fields, keyword fields like file hash SHA256 to corresponding file hash SHA256 fields) are accurately configured.
6. If any transform is not in a **Healthy** state, try resetting it:
   - Click the **three dots** next to the transform, then select **Reset**.
   - After resetting, follow the **Steps to enable transforms** above to reconfigure and restart the transform.

## Logs Reference

### Cryptominers

This is the `Cryptominer` dataset.

#### Example

An example event for `cryptominer` looks as following:

```json
{
    "@timestamp": "2025-01-27T19:51:31.000Z",
    "agent": {
        "ephemeral_id": "6e343759-95b9-417e-856e-ace3c03853e6",
        "id": "0a800239-cd1a-495d-88fc-db204c4fdc07",
        "name": "elastic-agent-87123",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "dataset": "ti_google_threat_intelligence.cryptominer",
        "namespace": "74935",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "0a800239-cd1a-495d-88fc-db204c4fdc07",
        "snapshot": false,
        "version": "8.16.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_google_threat_intelligence.cryptominer",
        "ingested": "2025-06-03T07:03:00Z",
        "kind": "enrichment",
        "original": "{\"data\":{\"attributes\":{\"first_submission_date\":1582817050,\"gti_assessment\":{\"severity\":{\"value\":\"SEVERITY_NONE\"},\"threat_score\":{\"value\":1},\"verdict\":{\"value\":\"VERDICT_UNDETECTED\"}},\"last_analysis_date\":1582817050,\"last_analysis_stats\":{\"harmless\":55,\"malicious\":8,\"undetected\":8},\"last_http_response_code\":200,\"last_modification_date\":1738007491,\"last_submission_date\":1582817050,\"positives\":8,\"times_submitted\":1,\"tld\":\"ru\",\"url\":\"http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin\"},\"id\":\"0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c\",\"relationships\":{},\"type\":\"url\"}}",
        "type": [
            "indicator"
        ]
    },
    "gti": {
        "cryptominer": {
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
        "google_threat_intelligence-cryptominer"
    ],
    "threat": {
        "feed": {
            "name": "Cryptominer"
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
| gti.cryptominer.attributes.as_number | The autonomous system number to which the IP belongs. | long |
| gti.cryptominer.attributes.as_owner | The owner of the autonomous system to which the IP belongs. | keyword |
| gti.cryptominer.attributes.categories | Categories based on the predefined criteria. | keyword |
| gti.cryptominer.attributes.continent | The continent where the IP is placed (ISO-3166 continent code). | keyword |
| gti.cryptominer.attributes.country | The country where the IP is placed (ISO-3166 country code). | keyword |
| gti.cryptominer.attributes.creation_date | The date when the IOC was created. | date |
| gti.cryptominer.attributes.first_submission_date | The UTC timestamp of the date when the URL was first submitted to Google Threat Intelligence. | date |
| gti.cryptominer.attributes.gti_assessment.severity | The threat severity level. | keyword |
| gti.cryptominer.attributes.gti_assessment.threat_score | The Google Threat Intelligence score is a function of the verdict and severity, and leverages additional internal factors to generate the score. | long |
| gti.cryptominer.attributes.gti_assessment.verdict | Indicates the assessed threat verdict, which can be benign, undetected, suspicious, malicious, or unknown. | keyword |
| gti.cryptominer.attributes.jarm | A JARM hash representing the entity's TLS fingerprint, used for identifying and classifying servers. | keyword |
| gti.cryptominer.attributes.last_analysis_date | The most recent scan date. | date |
| gti.cryptominer.attributes.last_analysis_results.engine | The name of the security engine that performed the analysis. | keyword |
| gti.cryptominer.attributes.last_analysis_results.result | The outcome of the analysis performed by the security engine. | keyword |
| gti.cryptominer.attributes.last_analysis_stats.harmless | Number of reports saying that is harmless. | long |
| gti.cryptominer.attributes.last_analysis_stats.malicious | Number of reports saying that is malicious. | long |
| gti.cryptominer.attributes.last_analysis_stats.suspicious | Number of reports saying that is suspicious. | long |
| gti.cryptominer.attributes.last_analysis_stats.timeout | Number of reports saying that is timeout. | long |
| gti.cryptominer.attributes.last_analysis_stats.undetected | Number of reports saying that is undetected. | long |
| gti.cryptominer.attributes.last_final_url | The URL if the original URL redirects, where does it end. | keyword |
| gti.cryptominer.attributes.last_http_response_code | The HTTP response code of the last response. | long |
| gti.cryptominer.attributes.last_modification_date | The date when the object itself was last modified. | date |
| gti.cryptominer.attributes.last_submission_date | The most recent date the entity was submitted for analysis. | date |
| gti.cryptominer.attributes.md5 | The file's MD5 hash. | keyword |
| gti.cryptominer.attributes.meaningful_name | The most interesting name out of all file's names. | keyword |
| gti.cryptominer.attributes.names | All file names associated with the file. | keyword |
| gti.cryptominer.attributes.network | The IPv4 network range to which the IP belongs. | keyword |
| gti.cryptominer.attributes.outgoing_links | Containing links to different domains. | keyword |
| gti.cryptominer.attributes.positives | The number of security engines that flagged the entity as malicious. | long |
| gti.cryptominer.attributes.regional_internet_registry | One of the current RIRs. | keyword |
| gti.cryptominer.attributes.tags | A list of representative attributes. | keyword |
| gti.cryptominer.attributes.times_submitted | The number of times the entity has been submitted for analysis. | long |
| gti.cryptominer.attributes.title | The webpage title. | keyword |
| gti.cryptominer.attributes.top_level_domain | The highest level of the domain name (e.g., .com, .org). | keyword |
| gti.cryptominer.attributes.type_tags | The broader tags related to the specific file type. | keyword |
| gti.cryptominer.attributes.url | The original URL to be scanned. | keyword |
| gti.cryptominer.attributes.vhash | An in-house similarity clustering algorithm value, based on a simple structural feature hash allows you to find similar files. | keyword |
| gti.cryptominer.id | The unique ID associated with the entity. | keyword |
| gti.cryptominer.relationships.campaigns.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.cryptominer.relationships.campaigns.attributes.name | Campaign's name. | keyword |
| gti.cryptominer.relationships.campaigns.id | The unique identifier associated with a specific relationship entry. | keyword |
| gti.cryptominer.relationships.campaigns.type | The category of relationship. | keyword |
| gti.cryptominer.relationships.collections.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.cryptominer.relationships.collections.attributes.name | Collection's name. | keyword |
| gti.cryptominer.relationships.collections.id | Unique identifier for the collection grouping related entities. | keyword |
| gti.cryptominer.relationships.collections.type | The category of relationship. | keyword |
| gti.cryptominer.relationships.malware_families.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.cryptominer.relationships.malware_families.attributes.name | Malware family's name. | keyword |
| gti.cryptominer.relationships.malware_families.id | Unique identifier for the malware family associated with the entity. | keyword |
| gti.cryptominer.relationships.malware_families.type | The category of relationship. | keyword |
| gti.cryptominer.relationships.reports.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.cryptominer.relationships.reports.attributes.name | Report's title. | keyword |
| gti.cryptominer.relationships.reports.id | Unique identifier for the report detailing the entity's analysis. | keyword |
| gti.cryptominer.relationships.reports.type | The category of relationship. | keyword |
| gti.cryptominer.relationships.software_toolkits.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.cryptominer.relationships.software_toolkits.attributes.name | Software or toolkit's name. | keyword |
| gti.cryptominer.relationships.software_toolkits.id | Unique identifier for the software or toolkit associated with the entity. | keyword |
| gti.cryptominer.relationships.software_toolkits.type | The category of relationship. | keyword |
| gti.cryptominer.relationships.threat_actors.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.cryptominer.relationships.threat_actors.attributes.name | Threat actor's name. | keyword |
| gti.cryptominer.relationships.threat_actors.id | Unique identifier for the threat actor associated with the entity. | keyword |
| gti.cryptominer.relationships.threat_actors.type | The category of relationship. | keyword |
| gti.cryptominer.relationships.vulnerabilities.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.cryptominer.relationships.vulnerabilities.attributes.name | Vulnerability's name. | keyword |
| gti.cryptominer.relationships.vulnerabilities.id | Unique identifier for the vulnerability associated with the entity. | keyword |
| gti.cryptominer.relationships.vulnerabilities.type | The category of relationship. | keyword |
| gti.cryptominer.type | Specifies the nature of the entity, such as file, domain, IP, or URL. | keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| log.offset | Log offset. | long |


### First Stage Delivery Vectors

This is the `First Stage Delivery Vectors` dataset.

#### Example

An example event for `first_stage_delivery_vectors` looks as following:

```json
{
    "@timestamp": "2025-01-27T19:51:31.000Z",
    "agent": {
        "ephemeral_id": "faf4f769-0b42-4cfe-97bf-3612a293b7d5",
        "id": "ec755067-12d9-4668-a6db-5ad73d3bc0d5",
        "name": "elastic-agent-36721",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "dataset": "ti_google_threat_intelligence.first_stage_delivery_vectors",
        "namespace": "53284",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "ec755067-12d9-4668-a6db-5ad73d3bc0d5",
        "snapshot": false,
        "version": "8.16.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_google_threat_intelligence.first_stage_delivery_vectors",
        "ingested": "2025-06-03T07:03:50Z",
        "kind": "enrichment",
        "original": "{\"data\":{\"attributes\":{\"first_submission_date\":1582817050,\"gti_assessment\":{\"severity\":{\"value\":\"SEVERITY_NONE\"},\"threat_score\":{\"value\":1},\"verdict\":{\"value\":\"VERDICT_UNDETECTED\"}},\"last_analysis_date\":1582817050,\"last_analysis_stats\":{\"harmless\":55,\"malicious\":8,\"undetected\":8},\"last_http_response_code\":200,\"last_modification_date\":1738007491,\"last_submission_date\":1582817050,\"positives\":8,\"times_submitted\":1,\"tld\":\"ru\",\"url\":\"http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin\"},\"id\":\"0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c\",\"relationships\":{},\"type\":\"url\"}}",
        "type": [
            "indicator"
        ]
    },
    "gti": {
        "first_stage_delivery_vectors": {
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
        "google_threat_intelligence-first_stage_delivery_vectors"
    ],
    "threat": {
        "feed": {
            "name": "First Stage Delivery Vectors"
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
| gti.first_stage_delivery_vectors.attributes.as_number | The autonomous system number to which the IP belongs. | long |
| gti.first_stage_delivery_vectors.attributes.as_owner | The owner of the autonomous system to which the IP belongs. | keyword |
| gti.first_stage_delivery_vectors.attributes.categories | Categories based on the predefined criteria. | keyword |
| gti.first_stage_delivery_vectors.attributes.continent | The continent where the IP is placed (ISO-3166 continent code). | keyword |
| gti.first_stage_delivery_vectors.attributes.country | The country where the IP is placed (ISO-3166 country code). | keyword |
| gti.first_stage_delivery_vectors.attributes.creation_date | The date when the IOC was created. | date |
| gti.first_stage_delivery_vectors.attributes.first_submission_date | The UTC timestamp of the date when the URL was first submitted to Google Threat Intelligence. | date |
| gti.first_stage_delivery_vectors.attributes.gti_assessment.severity | The threat severity level. | keyword |
| gti.first_stage_delivery_vectors.attributes.gti_assessment.threat_score | The Google Threat Intelligence score is a function of the verdict and severity, and leverages additional internal factors to generate the score. | long |
| gti.first_stage_delivery_vectors.attributes.gti_assessment.verdict | Indicates the assessed threat verdict, which can be benign, undetected, suspicious, malicious, or unknown. | keyword |
| gti.first_stage_delivery_vectors.attributes.jarm | A JARM hash representing the entity's TLS fingerprint, used for identifying and classifying servers. | keyword |
| gti.first_stage_delivery_vectors.attributes.last_analysis_date | The most recent scan date. | date |
| gti.first_stage_delivery_vectors.attributes.last_analysis_results.engine | The name of the security engine that performed the analysis. | keyword |
| gti.first_stage_delivery_vectors.attributes.last_analysis_results.result | The outcome of the analysis performed by the security engine. | keyword |
| gti.first_stage_delivery_vectors.attributes.last_analysis_stats.harmless | Number of reports saying that is harmless. | long |
| gti.first_stage_delivery_vectors.attributes.last_analysis_stats.malicious | Number of reports saying that is malicious. | long |
| gti.first_stage_delivery_vectors.attributes.last_analysis_stats.suspicious | Number of reports saying that is suspicious. | long |
| gti.first_stage_delivery_vectors.attributes.last_analysis_stats.timeout | Number of reports saying that is timeout. | long |
| gti.first_stage_delivery_vectors.attributes.last_analysis_stats.undetected | Number of reports saying that is undetected. | long |
| gti.first_stage_delivery_vectors.attributes.last_final_url | The URL if the original URL redirects, where does it end. | keyword |
| gti.first_stage_delivery_vectors.attributes.last_http_response_code | The HTTP response code of the last response. | long |
| gti.first_stage_delivery_vectors.attributes.last_modification_date | The date when the object itself was last modified. | date |
| gti.first_stage_delivery_vectors.attributes.last_submission_date | The most recent date the entity was submitted for analysis. | date |
| gti.first_stage_delivery_vectors.attributes.md5 | The file's MD5 hash. | keyword |
| gti.first_stage_delivery_vectors.attributes.meaningful_name | The most interesting name out of all file's names. | keyword |
| gti.first_stage_delivery_vectors.attributes.names | All file names associated with the file. | keyword |
| gti.first_stage_delivery_vectors.attributes.network | The IPv4 network range to which the IP belongs. | keyword |
| gti.first_stage_delivery_vectors.attributes.outgoing_links | Containing links to different domains. | keyword |
| gti.first_stage_delivery_vectors.attributes.positives | The number of security engines that flagged the entity as malicious. | long |
| gti.first_stage_delivery_vectors.attributes.regional_internet_registry | One of the current RIRs. | keyword |
| gti.first_stage_delivery_vectors.attributes.tags | A list of representative attributes. | keyword |
| gti.first_stage_delivery_vectors.attributes.times_submitted | The number of times the entity has been submitted for analysis. | long |
| gti.first_stage_delivery_vectors.attributes.title | The webpage title. | keyword |
| gti.first_stage_delivery_vectors.attributes.top_level_domain | The highest level of the domain name (e.g., .com, .org). | keyword |
| gti.first_stage_delivery_vectors.attributes.type_tags | The broader tags related to the specific file type. | keyword |
| gti.first_stage_delivery_vectors.attributes.url | The original URL to be scanned. | keyword |
| gti.first_stage_delivery_vectors.attributes.vhash | An in-house similarity clustering algorithm value, based on a simple structural feature hash allows you to find similar files. | keyword |
| gti.first_stage_delivery_vectors.id | The unique ID associated with the entity. | keyword |
| gti.first_stage_delivery_vectors.relationships.campaigns.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.first_stage_delivery_vectors.relationships.campaigns.attributes.name | Campaign's name. | keyword |
| gti.first_stage_delivery_vectors.relationships.campaigns.id | The unique identifier associated with a specific relationship entry. | keyword |
| gti.first_stage_delivery_vectors.relationships.campaigns.type | The category of relationship. | keyword |
| gti.first_stage_delivery_vectors.relationships.collections.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.first_stage_delivery_vectors.relationships.collections.attributes.name | Collection's name. | keyword |
| gti.first_stage_delivery_vectors.relationships.collections.id | Unique identifier for the collection grouping related entities. | keyword |
| gti.first_stage_delivery_vectors.relationships.collections.type | The category of relationship. | keyword |
| gti.first_stage_delivery_vectors.relationships.malware_families.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.first_stage_delivery_vectors.relationships.malware_families.attributes.name | Malware family's name. | keyword |
| gti.first_stage_delivery_vectors.relationships.malware_families.id | Unique identifier for the malware family associated with the entity. | keyword |
| gti.first_stage_delivery_vectors.relationships.malware_families.type | The category of relationship. | keyword |
| gti.first_stage_delivery_vectors.relationships.reports.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.first_stage_delivery_vectors.relationships.reports.attributes.name | Report's title. | keyword |
| gti.first_stage_delivery_vectors.relationships.reports.id | Unique identifier for the report detailing the entity's analysis. | keyword |
| gti.first_stage_delivery_vectors.relationships.reports.type | The category of relationship. | keyword |
| gti.first_stage_delivery_vectors.relationships.software_toolkits.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.first_stage_delivery_vectors.relationships.software_toolkits.attributes.name | Software or toolkit's name. | keyword |
| gti.first_stage_delivery_vectors.relationships.software_toolkits.id | Unique identifier for the software or toolkit associated with the entity. | keyword |
| gti.first_stage_delivery_vectors.relationships.software_toolkits.type | The category of relationship. | keyword |
| gti.first_stage_delivery_vectors.relationships.threat_actors.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.first_stage_delivery_vectors.relationships.threat_actors.attributes.name | Threat actor's name. | keyword |
| gti.first_stage_delivery_vectors.relationships.threat_actors.id | Unique identifier for the threat actor associated with the entity. | keyword |
| gti.first_stage_delivery_vectors.relationships.threat_actors.type | The category of relationship. | keyword |
| gti.first_stage_delivery_vectors.relationships.vulnerabilities.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.first_stage_delivery_vectors.relationships.vulnerabilities.attributes.name | Vulnerability's name. | keyword |
| gti.first_stage_delivery_vectors.relationships.vulnerabilities.id | Unique identifier for the vulnerability associated with the entity. | keyword |
| gti.first_stage_delivery_vectors.relationships.vulnerabilities.type | The category of relationship. | keyword |
| gti.first_stage_delivery_vectors.type | Specifies the nature of the entity, such as file, domain, IP, or URL. | keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| log.offset | Log offset. | long |


### Infostealers

This is the `Infostealers` dataset.

#### Example

An example event for `infostealer` looks as following:

```json
{
    "@timestamp": "2025-01-27T19:51:31.000Z",
    "agent": {
        "ephemeral_id": "ed53e573-351f-46b6-8f81-76a36fbb7ffd",
        "id": "5541f854-d3c3-4ef2-9c45-81926f60678a",
        "name": "elastic-agent-96027",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "dataset": "ti_google_threat_intelligence.infostealer",
        "namespace": "65942",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "5541f854-d3c3-4ef2-9c45-81926f60678a",
        "snapshot": false,
        "version": "8.16.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_google_threat_intelligence.infostealer",
        "ingested": "2025-06-03T07:04:41Z",
        "kind": "enrichment",
        "original": "{\"data\":{\"attributes\":{\"first_submission_date\":1582817050,\"gti_assessment\":{\"severity\":{\"value\":\"SEVERITY_NONE\"},\"threat_score\":{\"value\":1},\"verdict\":{\"value\":\"VERDICT_UNDETECTED\"}},\"last_analysis_date\":1582817050,\"last_analysis_stats\":{\"harmless\":55,\"malicious\":8,\"undetected\":8},\"last_http_response_code\":200,\"last_modification_date\":1738007491,\"last_submission_date\":1582817050,\"positives\":8,\"times_submitted\":1,\"tld\":\"ru\",\"url\":\"http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin\"},\"id\":\"0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c\",\"relationships\":{},\"type\":\"url\"}}",
        "type": [
            "indicator"
        ]
    },
    "gti": {
        "infostealer": {
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
        "google_threat_intelligence-infostealer"
    ],
    "threat": {
        "feed": {
            "name": "Infostealer"
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
| gti.infostealer.attributes.as_number | The autonomous system number to which the IP belongs. | long |
| gti.infostealer.attributes.as_owner | The owner of the autonomous system to which the IP belongs. | keyword |
| gti.infostealer.attributes.categories | Categories based on the predefined criteria. | keyword |
| gti.infostealer.attributes.continent | The continent where the IP is placed (ISO-3166 continent code). | keyword |
| gti.infostealer.attributes.country | The country where the IP is placed (ISO-3166 country code). | keyword |
| gti.infostealer.attributes.creation_date | The date when the IOC was created. | date |
| gti.infostealer.attributes.first_submission_date | The UTC timestamp of the date when the URL was first submitted to Google Threat Intelligence. | date |
| gti.infostealer.attributes.gti_assessment.severity | The threat severity level. | keyword |
| gti.infostealer.attributes.gti_assessment.threat_score | The Google Threat Intelligence score is a function of the verdict and severity, and leverages additional internal factors to generate the score. | long |
| gti.infostealer.attributes.gti_assessment.verdict | Indicates the assessed threat verdict, which can be benign, undetected, suspicious, malicious, or unknown. | keyword |
| gti.infostealer.attributes.jarm | A JARM hash representing the entity's TLS fingerprint, used for identifying and classifying servers. | keyword |
| gti.infostealer.attributes.last_analysis_date | The most recent scan date. | date |
| gti.infostealer.attributes.last_analysis_results.engine | The name of the security engine that performed the analysis. | keyword |
| gti.infostealer.attributes.last_analysis_results.result | The outcome of the analysis performed by the security engine. | keyword |
| gti.infostealer.attributes.last_analysis_stats.harmless | Number of reports saying that is harmless. | long |
| gti.infostealer.attributes.last_analysis_stats.malicious | Number of reports saying that is malicious. | long |
| gti.infostealer.attributes.last_analysis_stats.suspicious | Number of reports saying that is suspicious. | long |
| gti.infostealer.attributes.last_analysis_stats.timeout | Number of reports saying that is timeout. | long |
| gti.infostealer.attributes.last_analysis_stats.undetected | Number of reports saying that is undetected. | long |
| gti.infostealer.attributes.last_final_url | The URL if the original URL redirects, where does it end. | keyword |
| gti.infostealer.attributes.last_http_response_code | The HTTP response code of the last response. | long |
| gti.infostealer.attributes.last_modification_date | The date when the object itself was last modified. | date |
| gti.infostealer.attributes.last_submission_date | The most recent date the entity was submitted for analysis. | date |
| gti.infostealer.attributes.md5 | The file's MD5 hash. | keyword |
| gti.infostealer.attributes.meaningful_name | The most interesting name out of all file's names. | keyword |
| gti.infostealer.attributes.names | All file names associated with the file. | keyword |
| gti.infostealer.attributes.network | The IPv4 network range to which the IP belongs. | keyword |
| gti.infostealer.attributes.outgoing_links | Containing links to different domains. | keyword |
| gti.infostealer.attributes.positives | The number of security engines that flagged the entity as malicious. | long |
| gti.infostealer.attributes.regional_internet_registry | One of the current RIRs. | keyword |
| gti.infostealer.attributes.tags | A list of representative attributes. | keyword |
| gti.infostealer.attributes.times_submitted | The number of times the entity has been submitted for analysis. | long |
| gti.infostealer.attributes.title | The webpage title. | keyword |
| gti.infostealer.attributes.top_level_domain | The highest level of the domain name (e.g., .com, .org). | keyword |
| gti.infostealer.attributes.type_tags | The broader tags related to the specific file type. | keyword |
| gti.infostealer.attributes.url | The original URL to be scanned. | keyword |
| gti.infostealer.attributes.vhash | An in-house similarity clustering algorithm value, based on a simple structural feature hash allows you to find similar files. | keyword |
| gti.infostealer.id | The unique ID associated with the entity. | keyword |
| gti.infostealer.relationships.campaigns.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.infostealer.relationships.campaigns.attributes.name | Campaign's name. | keyword |
| gti.infostealer.relationships.campaigns.id | The unique identifier associated with a specific relationship entry. | keyword |
| gti.infostealer.relationships.campaigns.type | The category of relationship. | keyword |
| gti.infostealer.relationships.collections.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.infostealer.relationships.collections.attributes.name | Collection's name. | keyword |
| gti.infostealer.relationships.collections.id | Unique identifier for the collection grouping related entities. | keyword |
| gti.infostealer.relationships.collections.type | The category of relationship. | keyword |
| gti.infostealer.relationships.malware_families.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.infostealer.relationships.malware_families.attributes.name | Malware family's name. | keyword |
| gti.infostealer.relationships.malware_families.id | Unique identifier for the malware family associated with the entity. | keyword |
| gti.infostealer.relationships.malware_families.type | The category of relationship. | keyword |
| gti.infostealer.relationships.reports.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.infostealer.relationships.reports.attributes.name | Report's title. | keyword |
| gti.infostealer.relationships.reports.id | Unique identifier for the report detailing the entity's analysis. | keyword |
| gti.infostealer.relationships.reports.type | The category of relationship. | keyword |
| gti.infostealer.relationships.software_toolkits.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.infostealer.relationships.software_toolkits.attributes.name | Software or toolkit's name. | keyword |
| gti.infostealer.relationships.software_toolkits.id | Unique identifier for the software or toolkit associated with the entity. | keyword |
| gti.infostealer.relationships.software_toolkits.type | The category of relationship. | keyword |
| gti.infostealer.relationships.threat_actors.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.infostealer.relationships.threat_actors.attributes.name | Threat actor's name. | keyword |
| gti.infostealer.relationships.threat_actors.id | Unique identifier for the threat actor associated with the entity. | keyword |
| gti.infostealer.relationships.threat_actors.type | The category of relationship. | keyword |
| gti.infostealer.relationships.vulnerabilities.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.infostealer.relationships.vulnerabilities.attributes.name | Vulnerability's name. | keyword |
| gti.infostealer.relationships.vulnerabilities.id | Unique identifier for the vulnerability associated with the entity. | keyword |
| gti.infostealer.relationships.vulnerabilities.type | The category of relationship. | keyword |
| gti.infostealer.type | Specifies the nature of the entity, such as file, domain, IP, or URL. | keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| log.offset | Log offset. | long |


### Internet of Things

This is the `Internet of Things` dataset.

#### Example

An example event for `iot` looks as following:

```json
{
    "@timestamp": "2025-01-27T19:51:31.000Z",
    "agent": {
        "ephemeral_id": "e0a0f286-496f-4ffd-9c9c-54be65d8b4cc",
        "id": "88d27132-b45a-4362-aa86-b5fd57ad3d98",
        "name": "elastic-agent-57924",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "dataset": "ti_google_threat_intelligence.iot",
        "namespace": "45128",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "88d27132-b45a-4362-aa86-b5fd57ad3d98",
        "snapshot": false,
        "version": "8.16.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_google_threat_intelligence.iot",
        "ingested": "2025-06-03T07:07:52Z",
        "kind": "enrichment",
        "original": "{\"data\":{\"attributes\":{\"first_submission_date\":1582817050,\"gti_assessment\":{\"severity\":{\"value\":\"SEVERITY_NONE\"},\"threat_score\":{\"value\":1},\"verdict\":{\"value\":\"VERDICT_UNDETECTED\"}},\"last_analysis_date\":1582817050,\"last_analysis_stats\":{\"harmless\":55,\"malicious\":8,\"undetected\":8},\"last_http_response_code\":200,\"last_modification_date\":1738007491,\"last_submission_date\":1582817050,\"positives\":8,\"times_submitted\":1,\"tld\":\"ru\",\"url\":\"http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin\"},\"id\":\"0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c\",\"relationships\":{},\"type\":\"url\"}}",
        "type": [
            "indicator"
        ]
    },
    "gti": {
        "iot": {
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
        "google_threat_intelligence-iot"
    ],
    "threat": {
        "feed": {
            "name": "IOT"
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
| gti.iot.attributes.as_number | The autonomous system number to which the IP belongs. | long |
| gti.iot.attributes.as_owner | The owner of the autonomous system to which the IP belongs. | keyword |
| gti.iot.attributes.categories | Categories based on the predefined criteria. | keyword |
| gti.iot.attributes.continent | The continent where the IP is placed (ISO-3166 continent code). | keyword |
| gti.iot.attributes.country | The country where the IP is placed (ISO-3166 country code). | keyword |
| gti.iot.attributes.creation_date | The date when the IOC was created. | date |
| gti.iot.attributes.first_submission_date | The UTC timestamp of the date when the URL was first submitted to Google Threat Intelligence. | date |
| gti.iot.attributes.gti_assessment.severity | The threat severity level. | keyword |
| gti.iot.attributes.gti_assessment.threat_score | The Google Threat Intelligence score is a function of the verdict and severity, and leverages additional internal factors to generate the score. | long |
| gti.iot.attributes.gti_assessment.verdict | Indicates the assessed threat verdict, which can be benign, undetected, suspicious, malicious, or unknown. | keyword |
| gti.iot.attributes.jarm | A JARM hash representing the entity's TLS fingerprint, used for identifying and classifying servers. | keyword |
| gti.iot.attributes.last_analysis_date | The most recent scan date. | date |
| gti.iot.attributes.last_analysis_results.engine | The name of the security engine that performed the analysis. | keyword |
| gti.iot.attributes.last_analysis_results.result | The outcome of the analysis performed by the security engine. | keyword |
| gti.iot.attributes.last_analysis_stats.harmless | Number of reports saying that is harmless. | long |
| gti.iot.attributes.last_analysis_stats.malicious | Number of reports saying that is malicious. | long |
| gti.iot.attributes.last_analysis_stats.suspicious | Number of reports saying that is suspicious. | long |
| gti.iot.attributes.last_analysis_stats.timeout | Number of reports saying that is timeout. | long |
| gti.iot.attributes.last_analysis_stats.undetected | Number of reports saying that is undetected. | long |
| gti.iot.attributes.last_final_url | The URL if the original URL redirects, where does it end. | keyword |
| gti.iot.attributes.last_http_response_code | The HTTP response code of the last response. | long |
| gti.iot.attributes.last_modification_date | The date when the object itself was last modified. | date |
| gti.iot.attributes.last_submission_date | The most recent date the entity was submitted for analysis. | date |
| gti.iot.attributes.md5 | The file's MD5 hash. | keyword |
| gti.iot.attributes.meaningful_name | The most interesting name out of all file's names. | keyword |
| gti.iot.attributes.names | All file names associated with the file. | keyword |
| gti.iot.attributes.network | The IPv4 network range to which the IP belongs. | keyword |
| gti.iot.attributes.outgoing_links | Containing links to different domains. | keyword |
| gti.iot.attributes.positives | The number of security engines that flagged the entity as malicious. | long |
| gti.iot.attributes.regional_internet_registry | One of the current RIRs. | keyword |
| gti.iot.attributes.tags | A list of representative attributes. | keyword |
| gti.iot.attributes.times_submitted | The number of times the entity has been submitted for analysis. | long |
| gti.iot.attributes.title | The webpage title. | keyword |
| gti.iot.attributes.top_level_domain | The highest level of the domain name (e.g., .com, .org). | keyword |
| gti.iot.attributes.type_tags | The broader tags related to the specific file type. | keyword |
| gti.iot.attributes.url | The original URL to be scanned. | keyword |
| gti.iot.attributes.vhash | An in-house similarity clustering algorithm value, based on a simple structural feature hash allows you to find similar files. | keyword |
| gti.iot.id | The unique ID associated with the entity. | keyword |
| gti.iot.relationships.campaigns.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.iot.relationships.campaigns.attributes.name | Campaign's name. | keyword |
| gti.iot.relationships.campaigns.id | The unique identifier associated with a specific relationship entry. | keyword |
| gti.iot.relationships.campaigns.type | The category of relationship. | keyword |
| gti.iot.relationships.collections.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.iot.relationships.collections.attributes.name | Collection's name. | keyword |
| gti.iot.relationships.collections.id | Unique identifier for the collection grouping related entities. | keyword |
| gti.iot.relationships.collections.type | The category of relationship. | keyword |
| gti.iot.relationships.malware_families.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.iot.relationships.malware_families.attributes.name | Malware family's name. | keyword |
| gti.iot.relationships.malware_families.id | Unique identifier for the malware family associated with the entity. | keyword |
| gti.iot.relationships.malware_families.type | The category of relationship. | keyword |
| gti.iot.relationships.reports.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.iot.relationships.reports.attributes.name | Report's title. | keyword |
| gti.iot.relationships.reports.id | Unique identifier for the report detailing the entity's analysis. | keyword |
| gti.iot.relationships.reports.type | The category of relationship. | keyword |
| gti.iot.relationships.software_toolkits.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.iot.relationships.software_toolkits.attributes.name | Software or toolkit's name. | keyword |
| gti.iot.relationships.software_toolkits.id | Unique identifier for the software or toolkit associated with the entity. | keyword |
| gti.iot.relationships.software_toolkits.type | The category of relationship. | keyword |
| gti.iot.relationships.threat_actors.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.iot.relationships.threat_actors.attributes.name | Threat actor's name. | keyword |
| gti.iot.relationships.threat_actors.id | Unique identifier for the threat actor associated with the entity. | keyword |
| gti.iot.relationships.threat_actors.type | The category of relationship. | keyword |
| gti.iot.relationships.vulnerabilities.attributes.collection_type | Identifies the type of the object. | keyword |
| gti.iot.relationships.vulnerabilities.attributes.name | Vulnerability's name. | keyword |
| gti.iot.relationships.vulnerabilities.id | Unique identifier for the vulnerability associated with the entity. | keyword |
| gti.iot.relationships.vulnerabilities.type | The category of relationship. | keyword |
| gti.iot.type | Specifies the nature of the entity, such as file, domain, IP, or URL. | keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| log.offset | Log offset. | long |

