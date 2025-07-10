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
- **Linux**
- **Malicious Network Infrastructure**
- **Malware**
- **Mobile**
- **OS X**

## GTI Subscription Tiers

Customers can access a subset of the available threat lists based on their **Google Threat Intelligence (GTI) tier**:

- **GTI Standard**: Ransomware, Malicious Network Infrastructure
- **GTI Enterprise**: Ransomware, Malicious Network Infrastructure, Malware, Threat Actor, Daily Top Trending
- **GTI Enterprise+**: Access to all available threat lists

## Data Streams

Data collection is available for all nine feed types: `cryptominer`, `first_stage_delivery_vectors`, `infostealer`, `iot`, `linux`, `malicious_network_infrastructure`, `malware`, `mobile` and `osx`, each with a separate data stream. By default, **Malicious Network Infrastructure** is enabled. Users can enable additional data streams based on their GTI subscription tier. If a user enables data collection for a data stream they do not have access to, it will result in an error log on the **Discover** page.

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

Currently, four transforms are available across all 9 data streams.

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
     0.2.0-ti_google_threat_intelligence-latest_ip_ioc-transform-pipeline
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
        "ephemeral_id": "4df7e827-0e86-458c-8ce4-750acbc29154",
        "id": "a9506a30-0a26-4a32-ae73-5ddde67eab3f",
        "name": "elastic-agent-56830",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "dataset": "ti_google_threat_intelligence.cryptominer",
        "namespace": "71400",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "a9506a30-0a26-4a32-ae73-5ddde67eab3f",
        "snapshot": false,
        "version": "8.16.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_google_threat_intelligence.cryptominer",
        "ingested": "2025-07-07T05:47:28Z",
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
            "dashboard_id": [
                "ti_google_threat_intelligence-0b0fb6b4-d250-4e31-a56a-bb872e4c7c4a",
                "ti_google_threat_intelligence-9e8de699-a623-4a1b-9f63-7d641116f531",
                "ti_google_threat_intelligence-95187e5c-b4a2-45ad-b6a4-d6ce68e1f43e"
            ],
            "name": "GTI Cryptominer"
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
        "ephemeral_id": "dbf9b140-abe3-4426-be73-00959e110f85",
        "id": "4e149935-09c2-48ff-8075-0fcf4e137d38",
        "name": "elastic-agent-66341",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "dataset": "ti_google_threat_intelligence.first_stage_delivery_vectors",
        "namespace": "45412",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "4e149935-09c2-48ff-8075-0fcf4e137d38",
        "snapshot": false,
        "version": "8.16.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_google_threat_intelligence.first_stage_delivery_vectors",
        "ingested": "2025-07-07T05:49:55Z",
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
            "dashboard_id": [
                "ti_google_threat_intelligence-0b0fb6b4-d250-4e31-a56a-bb872e4c7c4a",
                "ti_google_threat_intelligence-9e8de699-a623-4a1b-9f63-7d641116f531",
                "ti_google_threat_intelligence-95187e5c-b4a2-45ad-b6a4-d6ce68e1f43e"
            ],
            "name": "GTI First Stage Delivery Vectors"
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
        "ephemeral_id": "b02f0363-ff15-4dcd-a86c-e62ca61fb391",
        "id": "11ac410f-0bab-4240-8d08-4a0f8d52fdec",
        "name": "elastic-agent-78695",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "dataset": "ti_google_threat_intelligence.infostealer",
        "namespace": "41450",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "11ac410f-0bab-4240-8d08-4a0f8d52fdec",
        "snapshot": false,
        "version": "8.16.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_google_threat_intelligence.infostealer",
        "ingested": "2025-07-07T05:50:47Z",
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
            "dashboard_id": [
                "ti_google_threat_intelligence-0b0fb6b4-d250-4e31-a56a-bb872e4c7c4a",
                "ti_google_threat_intelligence-9e8de699-a623-4a1b-9f63-7d641116f531",
                "ti_google_threat_intelligence-95187e5c-b4a2-45ad-b6a4-d6ce68e1f43e"
            ],
            "name": "GTI Infostealer"
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
        "ephemeral_id": "4e985f33-dfb9-441f-aa53-501c137ec960",
        "id": "cea9ed24-567b-404d-98bf-a1fa5a693431",
        "name": "elastic-agent-29340",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "dataset": "ti_google_threat_intelligence.iot",
        "namespace": "52289",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "cea9ed24-567b-404d-98bf-a1fa5a693431",
        "snapshot": false,
        "version": "8.16.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_google_threat_intelligence.iot",
        "ingested": "2025-07-07T05:52:26Z",
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
            "dashboard_id": [
                "ti_google_threat_intelligence-0b0fb6b4-d250-4e31-a56a-bb872e4c7c4a",
                "ti_google_threat_intelligence-9e8de699-a623-4a1b-9f63-7d641116f531",
                "ti_google_threat_intelligence-95187e5c-b4a2-45ad-b6a4-d6ce68e1f43e"
            ],
            "name": "GTI IOT"
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


### Linux

This is the `Linux` dataset.

#### Example

An example event for `linux` looks as following:

```json
{
    "@timestamp": "2025-01-27T19:51:31.000Z",
    "agent": {
        "ephemeral_id": "654d1584-ffc3-45e8-a7d1-e3629e833825",
        "id": "088ef65e-9213-4703-ada1-523a8657b7ca",
        "name": "elastic-agent-90266",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "dataset": "ti_google_threat_intelligence.linux",
        "namespace": "32018",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "088ef65e-9213-4703-ada1-523a8657b7ca",
        "snapshot": false,
        "version": "8.16.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_google_threat_intelligence.linux",
        "ingested": "2025-07-07T05:53:14Z",
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
            "dashboard_id": [
                "ti_google_threat_intelligence-0b0fb6b4-d250-4e31-a56a-bb872e4c7c4a",
                "ti_google_threat_intelligence-9e8de699-a623-4a1b-9f63-7d641116f531",
                "ti_google_threat_intelligence-95187e5c-b4a2-45ad-b6a4-d6ce68e1f43e"
            ],
            "name": "GTI Linux"
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


### Malicious Network Infrastructure

This is the `Malicious Network Infrastructure` dataset.

#### Example

An example event for `malicious_network_infrastructure` looks as following:

```json
{
    "@timestamp": "2025-01-27T19:51:31.000Z",
    "agent": {
        "ephemeral_id": "0d190035-9a99-46f9-9766-d654623dcce9",
        "id": "10a19e63-f957-4230-8985-27786b68b035",
        "name": "elastic-agent-74860",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "dataset": "ti_google_threat_intelligence.malicious_network_infrastructure",
        "namespace": "15851",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "10a19e63-f957-4230-8985-27786b68b035",
        "snapshot": false,
        "version": "8.16.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat",
            "network"
        ],
        "dataset": "ti_google_threat_intelligence.malicious_network_infrastructure",
        "ingested": "2025-07-07T05:54:05Z",
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
            "dashboard_id": [
                "ti_google_threat_intelligence-0b0fb6b4-d250-4e31-a56a-bb872e4c7c4a",
                "ti_google_threat_intelligence-9e8de699-a623-4a1b-9f63-7d641116f531",
                "ti_google_threat_intelligence-95187e5c-b4a2-45ad-b6a4-d6ce68e1f43e"
            ],
            "name": "GTI Malicious Network Infrastructure"
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
        "ephemeral_id": "e77a1909-b653-48e6-b6b2-0b65c244c345",
        "id": "82a42c63-4888-44ab-a977-9f32026085f1",
        "name": "elastic-agent-79773",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "dataset": "ti_google_threat_intelligence.malware",
        "namespace": "85162",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "82a42c63-4888-44ab-a977-9f32026085f1",
        "snapshot": false,
        "version": "8.16.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat",
            "malware"
        ],
        "dataset": "ti_google_threat_intelligence.malware",
        "ingested": "2025-07-07T05:54:55Z",
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
            "dashboard_id": [
                "ti_google_threat_intelligence-0b0fb6b4-d250-4e31-a56a-bb872e4c7c4a",
                "ti_google_threat_intelligence-9e8de699-a623-4a1b-9f63-7d641116f531",
                "ti_google_threat_intelligence-95187e5c-b4a2-45ad-b6a4-d6ce68e1f43e"
            ],
            "name": "GTI Malware"
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
        "ephemeral_id": "13731a82-6ad9-4da4-904d-7d33f84f876c",
        "id": "66bf5c63-ac76-40e6-9dee-77874b99b1cc",
        "name": "elastic-agent-67914",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "dataset": "ti_google_threat_intelligence.mobile",
        "namespace": "39635",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "66bf5c63-ac76-40e6-9dee-77874b99b1cc",
        "snapshot": false,
        "version": "8.16.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_google_threat_intelligence.mobile",
        "ingested": "2025-07-07T05:57:13Z",
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
            "dashboard_id": [
                "ti_google_threat_intelligence-0b0fb6b4-d250-4e31-a56a-bb872e4c7c4a",
                "ti_google_threat_intelligence-9e8de699-a623-4a1b-9f63-7d641116f531",
                "ti_google_threat_intelligence-95187e5c-b4a2-45ad-b6a4-d6ce68e1f43e"
            ],
            "name": "GTI Mobile"
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
        "ephemeral_id": "d38337f2-991b-49c9-80ef-1da3c0defe18",
        "id": "48305c71-ea31-478c-b116-78ab617718b9",
        "name": "elastic-agent-84741",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "dataset": "ti_google_threat_intelligence.osx",
        "namespace": "35062",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "48305c71-ea31-478c-b116-78ab617718b9",
        "snapshot": false,
        "version": "8.16.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_google_threat_intelligence.osx",
        "ingested": "2025-07-07T05:59:36Z",
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
            "dashboard_id": [
                "ti_google_threat_intelligence-0b0fb6b4-d250-4e31-a56a-bb872e4c7c4a",
                "ti_google_threat_intelligence-9e8de699-a623-4a1b-9f63-7d641116f531",
                "ti_google_threat_intelligence-95187e5c-b4a2-45ad-b6a4-d6ce68e1f43e"
            ],
            "name": "GTI OS X"
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

