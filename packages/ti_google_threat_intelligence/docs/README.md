# Google Threat Intelligence

## Overview

[Google Threat Intelligence](https://gtidocs.virustotal.com/) is a security solution that helps organizations detect, analyze, and mitigate threats. It leverages Google's global telemetry, advanced analytics, and vast infrastructure to provide actionable insights. Key features include threat detection, malware and phishing analysis, and real-time threat alerts.

Google Threat Intelligence uses the **Threat List API** to deliver hourly data chunks. The Threat Lists feature allows customers to consume **Indicators of Compromise (IOCs)** categorized by various threat types.

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

The Google Threat Intelligence Integration allows data collection for all 14 feed types, each with a separate data stream. By default, **Ransomware** and **Malicious Network Infrastructure** are enabled. Users can enable additional data streams based on their GTI subscription tier. If a user enables data collection for a data stream they do not have access to, it will result in an error log on the **Discover** page.

## Requirements

- Elastic Agent must be installed.
- You can install only one Elastic Agent per host.
- Elastic Agent is required to stream data through the REST API and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent. For more information, refer to the Elastic Agent [installation guide](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

## Setup

### To collect logs through REST API, follow the below steps:

- VirusTotal URL will work as the base URL for this integration: https://www.virustotal.com
- An API key will be used to authenticate your request.
- **Time Selection of Initial Interval and Interval**:
  - The GTI Threat List API only accepts time in **yyyymmddhh** format.
  - Users need to specify the **initial interval** and **interval** in an hourly format, such as **2h, 3h**, etc.
**Note:** Please make sure both initial interval and interval are in hours and greater than 1 hour.

### Enabling the integration in Elastic:

1. In Kibana, go to **Management > Integrations**.
2. In the "Search for integrations" search bar, type **Google Threat Intelligence**.
3. Click on the **Google Threat Intelligence** integration from the search results.
4. Click on the **Add Google Threat Intelligence** button to add the integration.
5. While adding the integration, to collect logs via REST API, provide the following details:
   - Enable the type of threat feed you have access to.
   - Access Token
   - Initial Interval
   - Interval
   - (Optional) Query to add custom query filtering on relationship, GTI score, and positives.
6. Click on **Save and Continue** to save the integration.
**Note:** Please make only the threat feed types you have the privilege to access are enabled..

## Transforming Data for Up-to-Date Insights

To keep the collected data up to date, **Transforms** are used.

Users can view the transforms by navigating to **Management > Stack Management > Transforms**.

Here, users can see continuously running transforms and also view the latest transformed GTI data in the **Discover** section.

The `labels.is_transform_source` field indicates log origin:
- **False** for transformed index
- **True** for source index

Currently, four transforms are running across all 14 data streams:

| Transform Name                                                         | Description                               |
| ---------------------------------------------------------------------- | ----------------------------------------- |
| IP Transform (ID: `logs-ti_google_threat_intelligence.ip_ioc`)         | Keeps IP entity type data up to date.     |
| URL Transform (ID: `logs-ti_google_threat_intelligence.url_ioc`)       | Keeps URL entity type data up to date.    |
| Domain Transform (ID: `logs-ti_google_threat_intelligence.domain_ioc`) | Keeps Domain entity type data up to date. |
| File Transform (ID: `logs-ti_google_threat_intelligence.file_ioc`)     | Keeps File entity type data up to date.   |

For example:

- The query `event.module: ti_google_threat_intelligence and labels.is_transform_source: true` indicates that the logs originate from the **source index**.
- The query `event.module: ti_google_threat_intelligence and labels.is_transform_source: false` indicates that the logs originate from the **transformed index**.

A **retention policy** is used to remove data older than the default retention period. For more details, refer to the [Retention Policy Documentation](<https://www.elastic.co/guide/en/elasticsearch/reference/current/put-transform.html#:~:text=to%20false.-,retention_policy,-(Optional%2C%20object)%20Defines>).

In this integration, all data streams have a **retention period of 30 days**.

### Enrichment with Detection Rules

Detection Rules match the user's Elastic environment data with GTI data, generating an alert if a match is found. To access detection rules:

1. Navigate to **Security > Rules > Detection Rules** and click on **Add Elastic Rules**.
2. Search for **Google Threat Intelligence** to find prebuilt Elastic detection rules.
3. Four detection rules are available for **IP, URL, File, and Domain**. Users can install one or more rules as needed.

To tailor a rule based on elastic Environment:

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

## Limitations

1. If an event contains multiple matching mappings (e.g., two file hash fields within the same event match GTI data), only one alert will be generated for that event.
2. If an IOC from the user's Elasticsearch index is enriched with GTI information, and the GTI information is updated later, the changes are not reflected in the dashboards because Elastic detection rules only run on live data.

## Troubleshooting

1. If you encounter a privilege error for a threat feed type, such as: `Permission denied. <Threat Feed> event collection is restricted to Enterprise Plus subscriptions. Contact your administrator or upgrade your subscription to enable this feature.`, verify your privilege level and enable only the threat feeds you have access to.
2. If you see an error like `Package 2025031310 is not available until 2025-03-13 at 11:00 UTC because of privacy policy.`, ensure that your initial interval and interval are set in hours and are greater than one hour.
3. If events are not appearing in the transformed index, check if transforms are running without errors. If you encounter issues, refer to [Troubleshooting transforms](https://www.elastic.co/guide/en/elasticsearch/reference/current/transform-troubleshooting.html).
4. If detection rules take longer to run, ensure you have specified index patterns and applied queries to make your source events more specific.
   **Note:** More events in index patterns mean more time needed for detection rules to run.
5. Ensure that relevant fields are correctly mapped in the **Indicator Mapping** section. Verify that fields in the specified index pattern are properly mapped, and ensure entity-specific fields (e.g., IP fields to IP fields, keyword fields like file hash SHA256 to corresponding file hash SHA256 fields) are accurately configured.

## Logs Reference

### Phishing

This is the `Phishing` dataset.

#### Example

An example event for `phishing` looks as following:

```json
{
    "@timestamp": "2025-01-27T19:51:31.000Z",
    "agent": {
        "ephemeral_id": "27413c52-3adb-43d9-b9fc-a9a52f40f8d9",
        "id": "a7aad582-8c94-43ab-847e-146d0062777f",
        "name": "elastic-agent-61606",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "dataset": "ti_google_threat_intelligence.phishing",
        "namespace": "69319",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "a7aad582-8c94-43ab-847e-146d0062777f",
        "snapshot": false,
        "version": "8.16.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_google_threat_intelligence.phishing",
        "ingested": "2025-03-13T05:38:28Z",
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
            "id": {
                "url": "0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c"
            },
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
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "google_threat_intelligence-phishing"
    ],
    "threat": {
        "indicator": {
            "feed_type": "Phishing",
            "first_submission_date": "2020-02-27T15:24:10.000Z",
            "harmless": 55,
            "http_response_code": 200,
            "id": "0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c",
            "last_seen": "2020-02-27T15:24:10.000Z",
            "last_submission_date": "2020-02-27T15:24:10.000Z",
            "malicious": 8,
            "modified_at": "2025-01-27T19:51:31.000Z",
            "positives": 8,
            "score": 1,
            "severity": "SEVERITY_NONE",
            "times_submitted": 1,
            "top_level_domain": [
                "ru"
            ],
            "type": "url",
            "undetected": 8,
            "url": {
                "id": "0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c",
                "original": "http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin"
            },
            "user_tags": [
                "preserve_original_event",
                "preserve_duplicate_custom_fields",
                "forwarded",
                "google_threat_intelligence-phishing"
            ],
            "verdict": "VERDICT_UNDETECTED"
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
| gti.phishing.id.domain | The domain address associated with the entity. | keyword |
| gti.phishing.id.file | The file object ID (SHA256 hash) associated with the entity. | keyword |
| gti.phishing.id.ip | The IP address associated with the entity. | ip |
| gti.phishing.id.url | The URL address associated with the entity. | keyword |
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
| threat.indicator.as.owner |  | keyword |
| threat.indicator.attributes |  | keyword |
| threat.indicator.campaigns.attributes.collection_type |  | keyword |
| threat.indicator.campaigns.attributes.name |  | keyword |
| threat.indicator.campaigns.id |  | keyword |
| threat.indicator.campaigns.type |  | keyword |
| threat.indicator.categories |  | keyword |
| threat.indicator.collections.attributes.collection_type |  | keyword |
| threat.indicator.collections.attributes.name |  | keyword |
| threat.indicator.collections.id |  | keyword |
| threat.indicator.collections.type |  | keyword |
| threat.indicator.created |  | date |
| threat.indicator.domain |  | keyword |
| threat.indicator.feed_type |  | keyword |
| threat.indicator.first_submission_date |  | date |
| threat.indicator.harmless |  | long |
| threat.indicator.http_response_code |  | long |
| threat.indicator.id |  | keyword |
| threat.indicator.jarm |  | keyword |
| threat.indicator.last_analysis_results.engine |  | keyword |
| threat.indicator.last_analysis_results.result |  | keyword |
| threat.indicator.last_submission_date |  | date |
| threat.indicator.malicious |  | long |
| threat.indicator.malware_families.attributes.collection_type |  | keyword |
| threat.indicator.malware_families.attributes.name |  | keyword |
| threat.indicator.malware_families.id |  | keyword |
| threat.indicator.malware_families.type |  | keyword |
| threat.indicator.meaningful_name |  | keyword |
| threat.indicator.network |  | keyword |
| threat.indicator.outgoing_links |  | keyword |
| threat.indicator.positives |  | long |
| threat.indicator.regional_internet_registry |  | keyword |
| threat.indicator.reports.attributes.collection_type |  | keyword |
| threat.indicator.reports.attributes.name |  | keyword |
| threat.indicator.reports.id |  | keyword |
| threat.indicator.reports.type |  | keyword |
| threat.indicator.score |  | long |
| threat.indicator.severity |  | keyword |
| threat.indicator.software_toolkits.attributes.collection_type |  | keyword |
| threat.indicator.software_toolkits.attributes.name |  | keyword |
| threat.indicator.software_toolkits.id |  | keyword |
| threat.indicator.software_toolkits.type |  | keyword |
| threat.indicator.suspicious |  | long |
| threat.indicator.threat_actors.attributes.collection_type |  | keyword |
| threat.indicator.threat_actors.attributes.name |  | keyword |
| threat.indicator.threat_actors.id |  | keyword |
| threat.indicator.threat_actors.type |  | keyword |
| threat.indicator.timeout |  | long |
| threat.indicator.times_submitted |  | long |
| threat.indicator.top_level_domain |  | keyword |
| threat.indicator.type_tags |  | keyword |
| threat.indicator.undetected |  | long |
| threat.indicator.url.id |  | keyword |
| threat.indicator.user_tags |  | keyword |
| threat.indicator.verdict |  | keyword |
| threat.indicator.vhash |  | keyword |
| threat.indicator.vulnerabilities.attributes.collection_type |  | keyword |
| threat.indicator.vulnerabilities.attributes.name |  | keyword |
| threat.indicator.vulnerabilities.id |  | keyword |
| threat.indicator.vulnerabilities.type |  | keyword |
| threat.indicator.web_page_title |  | keyword |


### Ransomware

This is the `Ransomware` dataset.

#### Example

An example event for `ransomware` looks as following:

```json
{
    "@timestamp": "2025-01-27T19:51:31.000Z",
    "agent": {
        "ephemeral_id": "f57804e3-e4a3-4661-80e9-916b63e8602f",
        "id": "72eb94a2-7609-4ce6-b842-8dc2ca611ddd",
        "name": "elastic-agent-72021",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "dataset": "ti_google_threat_intelligence.ransomware",
        "namespace": "76458",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "72eb94a2-7609-4ce6-b842-8dc2ca611ddd",
        "snapshot": false,
        "version": "8.16.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_google_threat_intelligence.ransomware",
        "ingested": "2025-03-13T05:40:49Z",
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
            "id": {
                "url": "0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c"
            },
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
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "google_threat_intelligence-ransomware"
    ],
    "threat": {
        "indicator": {
            "feed_type": "Ransomware",
            "first_submission_date": "2020-02-27T15:24:10.000Z",
            "harmless": 55,
            "http_response_code": 200,
            "id": "0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c",
            "last_seen": "2020-02-27T15:24:10.000Z",
            "last_submission_date": "2020-02-27T15:24:10.000Z",
            "malicious": 8,
            "modified_at": "2025-01-27T19:51:31.000Z",
            "positives": 8,
            "score": 1,
            "severity": "SEVERITY_NONE",
            "times_submitted": 1,
            "top_level_domain": [
                "ru"
            ],
            "type": "url",
            "undetected": 8,
            "url": {
                "id": "0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c",
                "original": "http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin"
            },
            "user_tags": [
                "preserve_original_event",
                "preserve_duplicate_custom_fields",
                "forwarded",
                "google_threat_intelligence-ransomware"
            ],
            "verdict": "VERDICT_UNDETECTED"
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
| gti.ransomware.id.domain | The domain address associated with the entity. | keyword |
| gti.ransomware.id.file | The file object ID (SHA256 hash) associated with the entity. | keyword |
| gti.ransomware.id.ip | The IP address associated with the entity. | ip |
| gti.ransomware.id.url | The URL address associated with the entity. | keyword |
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
| threat.indicator.as.owner |  | keyword |
| threat.indicator.attributes |  | keyword |
| threat.indicator.campaigns.attributes.collection_type |  | keyword |
| threat.indicator.campaigns.attributes.name |  | keyword |
| threat.indicator.campaigns.id |  | keyword |
| threat.indicator.campaigns.type |  | keyword |
| threat.indicator.categories |  | keyword |
| threat.indicator.collections.attributes.collection_type |  | keyword |
| threat.indicator.collections.attributes.name |  | keyword |
| threat.indicator.collections.id |  | keyword |
| threat.indicator.collections.type |  | keyword |
| threat.indicator.created |  | date |
| threat.indicator.domain |  | keyword |
| threat.indicator.feed_type |  | keyword |
| threat.indicator.first_submission_date |  | date |
| threat.indicator.harmless |  | long |
| threat.indicator.http_response_code |  | long |
| threat.indicator.id |  | keyword |
| threat.indicator.jarm |  | keyword |
| threat.indicator.last_analysis_results.engine |  | keyword |
| threat.indicator.last_analysis_results.result |  | keyword |
| threat.indicator.last_submission_date |  | date |
| threat.indicator.malicious |  | long |
| threat.indicator.malware_families.attributes.collection_type |  | keyword |
| threat.indicator.malware_families.attributes.name |  | keyword |
| threat.indicator.malware_families.id |  | keyword |
| threat.indicator.malware_families.type |  | keyword |
| threat.indicator.meaningful_name |  | keyword |
| threat.indicator.network |  | keyword |
| threat.indicator.outgoing_links |  | keyword |
| threat.indicator.positives |  | long |
| threat.indicator.regional_internet_registry |  | keyword |
| threat.indicator.reports.attributes.collection_type |  | keyword |
| threat.indicator.reports.attributes.name |  | keyword |
| threat.indicator.reports.id |  | keyword |
| threat.indicator.reports.type |  | keyword |
| threat.indicator.score |  | long |
| threat.indicator.severity |  | keyword |
| threat.indicator.software_toolkits.attributes.collection_type |  | keyword |
| threat.indicator.software_toolkits.attributes.name |  | keyword |
| threat.indicator.software_toolkits.id |  | keyword |
| threat.indicator.software_toolkits.type |  | keyword |
| threat.indicator.suspicious |  | long |
| threat.indicator.threat_actors.attributes.collection_type |  | keyword |
| threat.indicator.threat_actors.attributes.name |  | keyword |
| threat.indicator.threat_actors.id |  | keyword |
| threat.indicator.threat_actors.type |  | keyword |
| threat.indicator.timeout |  | long |
| threat.indicator.times_submitted |  | long |
| threat.indicator.top_level_domain |  | keyword |
| threat.indicator.type_tags |  | keyword |
| threat.indicator.undetected |  | long |
| threat.indicator.url.id |  | keyword |
| threat.indicator.user_tags |  | keyword |
| threat.indicator.verdict |  | keyword |
| threat.indicator.vhash |  | keyword |
| threat.indicator.vulnerabilities.attributes.collection_type |  | keyword |
| threat.indicator.vulnerabilities.attributes.name |  | keyword |
| threat.indicator.vulnerabilities.id |  | keyword |
| threat.indicator.vulnerabilities.type |  | keyword |
| threat.indicator.web_page_title |  | keyword |


### Threat Actor

This is the `Threat Actor` dataset.

#### Example

An example event for `threat_actor` looks as following:

```json
{
    "@timestamp": "2025-01-27T19:51:31.000Z",
    "agent": {
        "ephemeral_id": "72c21ca5-753a-45b7-88d6-6be12162e3a1",
        "id": "089de387-d179-42c6-a9c9-0d4aefbc1345",
        "name": "elastic-agent-58450",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "dataset": "ti_google_threat_intelligence.threat_actor",
        "namespace": "81830",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "089de387-d179-42c6-a9c9-0d4aefbc1345",
        "snapshot": false,
        "version": "8.16.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_google_threat_intelligence.threat_actor",
        "ingested": "2025-03-13T05:43:09Z",
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
            "id": {
                "url": "0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c"
            },
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
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "google_threat_intelligence-threat_actor"
    ],
    "threat": {
        "indicator": {
            "feed_type": "Threat Actor",
            "first_submission_date": "2020-02-27T15:24:10.000Z",
            "harmless": 55,
            "http_response_code": 200,
            "id": "0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c",
            "last_seen": "2020-02-27T15:24:10.000Z",
            "last_submission_date": "2020-02-27T15:24:10.000Z",
            "malicious": 8,
            "modified_at": "2025-01-27T19:51:31.000Z",
            "positives": 8,
            "score": 1,
            "severity": "SEVERITY_NONE",
            "times_submitted": 1,
            "top_level_domain": [
                "ru"
            ],
            "type": "url",
            "undetected": 8,
            "url": {
                "id": "0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c",
                "original": "http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin"
            },
            "user_tags": [
                "preserve_original_event",
                "preserve_duplicate_custom_fields",
                "forwarded",
                "google_threat_intelligence-threat_actor"
            ],
            "verdict": "VERDICT_UNDETECTED"
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
| gti.threat_actor.id.domain | The domain address associated with the entity. | keyword |
| gti.threat_actor.id.file | The file object ID (SHA256 hash) associated with the entity. | keyword |
| gti.threat_actor.id.ip | The IP address associated with the entity. | ip |
| gti.threat_actor.id.url | The URL address associated with the entity. | keyword |
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
| threat.indicator.as.owner |  | keyword |
| threat.indicator.attributes |  | keyword |
| threat.indicator.campaigns.attributes.collection_type |  | keyword |
| threat.indicator.campaigns.attributes.name |  | keyword |
| threat.indicator.campaigns.id |  | keyword |
| threat.indicator.campaigns.type |  | keyword |
| threat.indicator.categories |  | keyword |
| threat.indicator.collections.attributes.collection_type |  | keyword |
| threat.indicator.collections.attributes.name |  | keyword |
| threat.indicator.collections.id |  | keyword |
| threat.indicator.collections.type |  | keyword |
| threat.indicator.created |  | date |
| threat.indicator.domain |  | keyword |
| threat.indicator.feed_type |  | keyword |
| threat.indicator.first_submission_date |  | date |
| threat.indicator.harmless |  | long |
| threat.indicator.http_response_code |  | long |
| threat.indicator.id |  | keyword |
| threat.indicator.jarm |  | keyword |
| threat.indicator.last_analysis_results.engine |  | keyword |
| threat.indicator.last_analysis_results.result |  | keyword |
| threat.indicator.last_submission_date |  | date |
| threat.indicator.malicious |  | long |
| threat.indicator.malware_families.attributes.collection_type |  | keyword |
| threat.indicator.malware_families.attributes.name |  | keyword |
| threat.indicator.malware_families.id |  | keyword |
| threat.indicator.malware_families.type |  | keyword |
| threat.indicator.meaningful_name |  | keyword |
| threat.indicator.network |  | keyword |
| threat.indicator.outgoing_links |  | keyword |
| threat.indicator.positives |  | long |
| threat.indicator.regional_internet_registry |  | keyword |
| threat.indicator.reports.attributes.collection_type |  | keyword |
| threat.indicator.reports.attributes.name |  | keyword |
| threat.indicator.reports.id |  | keyword |
| threat.indicator.reports.type |  | keyword |
| threat.indicator.score |  | long |
| threat.indicator.severity |  | keyword |
| threat.indicator.software_toolkits.attributes.collection_type |  | keyword |
| threat.indicator.software_toolkits.attributes.name |  | keyword |
| threat.indicator.software_toolkits.id |  | keyword |
| threat.indicator.software_toolkits.type |  | keyword |
| threat.indicator.suspicious |  | long |
| threat.indicator.threat_actors.attributes.collection_type |  | keyword |
| threat.indicator.threat_actors.attributes.name |  | keyword |
| threat.indicator.threat_actors.id |  | keyword |
| threat.indicator.threat_actors.type |  | keyword |
| threat.indicator.timeout |  | long |
| threat.indicator.times_submitted |  | long |
| threat.indicator.top_level_domain |  | keyword |
| threat.indicator.type_tags |  | keyword |
| threat.indicator.undetected |  | long |
| threat.indicator.url.id |  | keyword |
| threat.indicator.user_tags |  | keyword |
| threat.indicator.verdict |  | keyword |
| threat.indicator.vhash |  | keyword |
| threat.indicator.vulnerabilities.attributes.collection_type |  | keyword |
| threat.indicator.vulnerabilities.attributes.name |  | keyword |
| threat.indicator.vulnerabilities.id |  | keyword |
| threat.indicator.vulnerabilities.type |  | keyword |
| threat.indicator.web_page_title |  | keyword |


### Daily Top trending

This is the `Daily Top trending` dataset.

#### Example

An example event for `trending` looks as following:

```json
{
    "@timestamp": "2025-01-27T19:51:31.000Z",
    "agent": {
        "ephemeral_id": "4baf53e9-cf4a-4a9b-8ef1-9259f75a1a93",
        "id": "8d90e8ad-4581-4491-acfd-b3795cfae3f0",
        "name": "elastic-agent-53378",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "dataset": "ti_google_threat_intelligence.trending",
        "namespace": "76159",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "8d90e8ad-4581-4491-acfd-b3795cfae3f0",
        "snapshot": false,
        "version": "8.16.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_google_threat_intelligence.trending",
        "ingested": "2025-03-13T05:43:58Z",
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
            "id": {
                "url": "0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c"
            },
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
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "google_threat_intelligence-trending"
    ],
    "threat": {
        "indicator": {
            "feed_type": "Daily Top trending",
            "first_submission_date": "2020-02-27T15:24:10.000Z",
            "harmless": 55,
            "http_response_code": 200,
            "id": "0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c",
            "last_seen": "2020-02-27T15:24:10.000Z",
            "last_submission_date": "2020-02-27T15:24:10.000Z",
            "malicious": 8,
            "modified_at": "2025-01-27T19:51:31.000Z",
            "positives": 8,
            "score": 1,
            "severity": "SEVERITY_NONE",
            "times_submitted": 1,
            "top_level_domain": [
                "ru"
            ],
            "type": "url",
            "undetected": 8,
            "url": {
                "id": "0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c",
                "original": "http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin"
            },
            "user_tags": [
                "preserve_original_event",
                "preserve_duplicate_custom_fields",
                "forwarded",
                "google_threat_intelligence-trending"
            ],
            "verdict": "VERDICT_UNDETECTED"
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
| gti.trending.id.domain | The domain address associated with the entity. | keyword |
| gti.trending.id.file | The file object ID (SHA256 hash) associated with the entity. | keyword |
| gti.trending.id.ip | The IP address associated with the entity. | ip |
| gti.trending.id.url | The URL address associated with the entity. | keyword |
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
| threat.indicator.as.owner |  | keyword |
| threat.indicator.attributes |  | keyword |
| threat.indicator.campaigns.attributes.collection_type |  | keyword |
| threat.indicator.campaigns.attributes.name |  | keyword |
| threat.indicator.campaigns.id |  | keyword |
| threat.indicator.campaigns.type |  | keyword |
| threat.indicator.categories |  | keyword |
| threat.indicator.collections.attributes.collection_type |  | keyword |
| threat.indicator.collections.attributes.name |  | keyword |
| threat.indicator.collections.id |  | keyword |
| threat.indicator.collections.type |  | keyword |
| threat.indicator.created |  | date |
| threat.indicator.domain |  | keyword |
| threat.indicator.feed_type |  | keyword |
| threat.indicator.first_submission_date |  | date |
| threat.indicator.harmless |  | long |
| threat.indicator.http_response_code |  | long |
| threat.indicator.id |  | keyword |
| threat.indicator.jarm |  | keyword |
| threat.indicator.last_analysis_results.engine |  | keyword |
| threat.indicator.last_analysis_results.result |  | keyword |
| threat.indicator.last_submission_date |  | date |
| threat.indicator.malicious |  | long |
| threat.indicator.malware_families.attributes.collection_type |  | keyword |
| threat.indicator.malware_families.attributes.name |  | keyword |
| threat.indicator.malware_families.id |  | keyword |
| threat.indicator.malware_families.type |  | keyword |
| threat.indicator.meaningful_name |  | keyword |
| threat.indicator.network |  | keyword |
| threat.indicator.outgoing_links |  | keyword |
| threat.indicator.positives |  | long |
| threat.indicator.regional_internet_registry |  | keyword |
| threat.indicator.reports.attributes.collection_type |  | keyword |
| threat.indicator.reports.attributes.name |  | keyword |
| threat.indicator.reports.id |  | keyword |
| threat.indicator.reports.type |  | keyword |
| threat.indicator.score |  | long |
| threat.indicator.severity |  | keyword |
| threat.indicator.software_toolkits.attributes.collection_type |  | keyword |
| threat.indicator.software_toolkits.attributes.name |  | keyword |
| threat.indicator.software_toolkits.id |  | keyword |
| threat.indicator.software_toolkits.type |  | keyword |
| threat.indicator.suspicious |  | long |
| threat.indicator.threat_actors.attributes.collection_type |  | keyword |
| threat.indicator.threat_actors.attributes.name |  | keyword |
| threat.indicator.threat_actors.id |  | keyword |
| threat.indicator.threat_actors.type |  | keyword |
| threat.indicator.timeout |  | long |
| threat.indicator.times_submitted |  | long |
| threat.indicator.top_level_domain |  | keyword |
| threat.indicator.type_tags |  | keyword |
| threat.indicator.undetected |  | long |
| threat.indicator.url.id |  | keyword |
| threat.indicator.user_tags |  | keyword |
| threat.indicator.verdict |  | keyword |
| threat.indicator.vhash |  | keyword |
| threat.indicator.vulnerabilities.attributes.collection_type |  | keyword |
| threat.indicator.vulnerabilities.attributes.name |  | keyword |
| threat.indicator.vulnerabilities.id |  | keyword |
| threat.indicator.vulnerabilities.type |  | keyword |
| threat.indicator.web_page_title |  | keyword |


### Vulnerability Weaponization

This is the `Vulnerability Weaponization` dataset.

#### Example

An example event for `vulnerability_weaponization` looks as following:

```json
{
    "@timestamp": "2025-01-27T19:51:31.000Z",
    "agent": {
        "ephemeral_id": "574fd81d-6847-42b6-ae3d-8e410071889f",
        "id": "aae4553f-4785-4daf-843b-c770c8c1a557",
        "name": "elastic-agent-68076",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "dataset": "ti_google_threat_intelligence.vulnerability_weaponization",
        "namespace": "75340",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "aae4553f-4785-4daf-843b-c770c8c1a557",
        "snapshot": false,
        "version": "8.16.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat",
            "vulnerability"
        ],
        "dataset": "ti_google_threat_intelligence.vulnerability_weaponization",
        "ingested": "2025-03-13T05:44:49Z",
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
            "id": {
                "url": "0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c"
            },
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
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "google_threat_intelligence-vulnerability_weaponization"
    ],
    "threat": {
        "indicator": {
            "feed_type": "Vulnerability Weaponization",
            "first_submission_date": "2020-02-27T15:24:10.000Z",
            "harmless": 55,
            "http_response_code": 200,
            "id": "0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c",
            "last_seen": "2020-02-27T15:24:10.000Z",
            "last_submission_date": "2020-02-27T15:24:10.000Z",
            "malicious": 8,
            "modified_at": "2025-01-27T19:51:31.000Z",
            "positives": 8,
            "score": 1,
            "severity": "SEVERITY_NONE",
            "times_submitted": 1,
            "top_level_domain": [
                "ru"
            ],
            "type": "url",
            "undetected": 8,
            "url": {
                "id": "0146b3be6e724b10e620e8090821a8253772af779a4996145cdf295c01e0900c",
                "original": "http://securepasswel.ru/files/grapes_encrypted_87ed10f.bin"
            },
            "user_tags": [
                "preserve_original_event",
                "preserve_duplicate_custom_fields",
                "forwarded",
                "google_threat_intelligence-vulnerability_weaponization"
            ],
            "verdict": "VERDICT_UNDETECTED"
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
| gti.vulnerability_weaponization.id.domain | The domain address associated with the entity. | keyword |
| gti.vulnerability_weaponization.id.file | The file object ID (SHA256 hash) associated with the entity. | keyword |
| gti.vulnerability_weaponization.id.ip | The IP address associated with the entity. | ip |
| gti.vulnerability_weaponization.id.url | The URL address associated with the entity. | keyword |
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
| threat.indicator.as.owner |  | keyword |
| threat.indicator.attributes |  | keyword |
| threat.indicator.campaigns.attributes.collection_type |  | keyword |
| threat.indicator.campaigns.attributes.name |  | keyword |
| threat.indicator.campaigns.id |  | keyword |
| threat.indicator.campaigns.type |  | keyword |
| threat.indicator.categories |  | keyword |
| threat.indicator.collections.attributes.collection_type |  | keyword |
| threat.indicator.collections.attributes.name |  | keyword |
| threat.indicator.collections.id |  | keyword |
| threat.indicator.collections.type |  | keyword |
| threat.indicator.created |  | date |
| threat.indicator.domain |  | keyword |
| threat.indicator.feed_type |  | keyword |
| threat.indicator.first_submission_date |  | date |
| threat.indicator.harmless |  | long |
| threat.indicator.http_response_code |  | long |
| threat.indicator.id |  | keyword |
| threat.indicator.jarm |  | keyword |
| threat.indicator.last_analysis_results.engine |  | keyword |
| threat.indicator.last_analysis_results.result |  | keyword |
| threat.indicator.last_submission_date |  | date |
| threat.indicator.malicious |  | long |
| threat.indicator.malware_families.attributes.collection_type |  | keyword |
| threat.indicator.malware_families.attributes.name |  | keyword |
| threat.indicator.malware_families.id |  | keyword |
| threat.indicator.malware_families.type |  | keyword |
| threat.indicator.meaningful_name |  | keyword |
| threat.indicator.network |  | keyword |
| threat.indicator.outgoing_links |  | keyword |
| threat.indicator.positives |  | long |
| threat.indicator.regional_internet_registry |  | keyword |
| threat.indicator.reports.attributes.collection_type |  | keyword |
| threat.indicator.reports.attributes.name |  | keyword |
| threat.indicator.reports.id |  | keyword |
| threat.indicator.reports.type |  | keyword |
| threat.indicator.score |  | long |
| threat.indicator.severity |  | keyword |
| threat.indicator.software_toolkits.attributes.collection_type |  | keyword |
| threat.indicator.software_toolkits.attributes.name |  | keyword |
| threat.indicator.software_toolkits.id |  | keyword |
| threat.indicator.software_toolkits.type |  | keyword |
| threat.indicator.suspicious |  | long |
| threat.indicator.threat_actors.attributes.collection_type |  | keyword |
| threat.indicator.threat_actors.attributes.name |  | keyword |
| threat.indicator.threat_actors.id |  | keyword |
| threat.indicator.threat_actors.type |  | keyword |
| threat.indicator.timeout |  | long |
| threat.indicator.times_submitted |  | long |
| threat.indicator.top_level_domain |  | keyword |
| threat.indicator.type_tags |  | keyword |
| threat.indicator.undetected |  | long |
| threat.indicator.url.id |  | keyword |
| threat.indicator.user_tags |  | keyword |
| threat.indicator.verdict |  | keyword |
| threat.indicator.vhash |  | keyword |
| threat.indicator.vulnerabilities.attributes.collection_type |  | keyword |
| threat.indicator.vulnerabilities.attributes.name |  | keyword |
| threat.indicator.vulnerabilities.id |  | keyword |
| threat.indicator.vulnerabilities.type |  | keyword |
| threat.indicator.web_page_title |  | keyword |

