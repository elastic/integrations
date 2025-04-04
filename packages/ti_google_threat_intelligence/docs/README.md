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

### Linux

This is the `Linux` dataset.

#### Example

An example event for `linux` looks as following:

```json
{
    "@timestamp": "2025-01-27T19:51:31.000Z",
    "agent": {
        "ephemeral_id": "3b5a83ff-0f25-4ad0-bf83-59aeece6b52f",
        "id": "a7ac7bb9-f703-49b0-968b-56a74270bc3d",
        "name": "elastic-agent-51603",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "dataset": "ti_google_threat_intelligence.linux",
        "namespace": "63083",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "a7ac7bb9-f703-49b0-968b-56a74270bc3d",
        "snapshot": false,
        "version": "8.16.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_google_threat_intelligence.linux",
        "ingested": "2025-03-13T05:31:20Z",
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
        "google_threat_intelligence-linux"
    ],
    "threat": {
        "indicator": {
            "feed_type": "Linux",
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
                "google_threat_intelligence-linux"
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
| gti.linux.id.domain | The domain address associated with the entity. | keyword |
| gti.linux.id.file | The file object ID (SHA256 hash) associated with the entity. | keyword |
| gti.linux.id.ip | The IP address associated with the entity. | ip |
| gti.linux.id.url | The URL address associated with the entity. | keyword |
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


### Malicious Network Infra

This is the `Malicious Network Infra` dataset.

#### Example

An example event for `malicious_network_infrastructure` looks as following:

```json
{
    "@timestamp": "2025-01-27T19:51:31.000Z",
    "agent": {
        "ephemeral_id": "3ce08a1d-fc42-4f8a-a805-060b1303b610",
        "id": "9ba7d7e0-1dc3-468d-94bc-540f98a5f017",
        "name": "elastic-agent-42142",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "dataset": "ti_google_threat_intelligence.malicious_network_infrastructure",
        "namespace": "65057",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "9ba7d7e0-1dc3-468d-94bc-540f98a5f017",
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
        "ingested": "2025-03-13T05:33:39Z",
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
        "google_threat_intelligence-malicious_network_infrastructure"
    ],
    "threat": {
        "indicator": {
            "feed_type": "Malicious Network Infra",
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
                "google_threat_intelligence-malicious_network_infrastructure"
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
| gti.malicious_network_infrastructure.id.domain | The domain address associated with the entity. | keyword |
| gti.malicious_network_infrastructure.id.file | The file object ID (SHA256 hash) associated with the entity. | keyword |
| gti.malicious_network_infrastructure.id.ip | The IP address associated with the entity. | ip |
| gti.malicious_network_infrastructure.id.url | The URL address associated with the entity. | keyword |
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


### Malware

This is the `Malware` dataset.

#### Example

An example event for `malware` looks as following:

```json
{
    "@timestamp": "2025-01-27T19:51:31.000Z",
    "agent": {
        "ephemeral_id": "8a99a2c3-fa2e-46de-930f-5136e83db716",
        "id": "a62501e3-8584-4a1d-bb86-7a1254be6069",
        "name": "elastic-agent-41353",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "dataset": "ti_google_threat_intelligence.malware",
        "namespace": "91283",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "a62501e3-8584-4a1d-bb86-7a1254be6069",
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
        "ingested": "2025-03-13T05:34:29Z",
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
        "google_threat_intelligence-malware"
    ],
    "threat": {
        "indicator": {
            "feed_type": "Malware",
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
                "google_threat_intelligence-malware"
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
| gti.malware.id.domain | The domain address associated with the entity. | keyword |
| gti.malware.id.file | The file object ID (SHA256 hash) associated with the entity. | keyword |
| gti.malware.id.ip | The IP address associated with the entity. | ip |
| gti.malware.id.url | The URL address associated with the entity. | keyword |
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


### Mobile

This is the `Mobile` dataset.

#### Example

An example event for `mobile` looks as following:

```json
{
    "@timestamp": "2025-01-27T19:51:31.000Z",
    "agent": {
        "ephemeral_id": "99c4af11-dd81-4049-92f4-d392a009505a",
        "id": "e37492e3-61bb-4c93-a14a-670e07dbb0e9",
        "name": "elastic-agent-64159",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "dataset": "ti_google_threat_intelligence.mobile",
        "namespace": "69552",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "e37492e3-61bb-4c93-a14a-670e07dbb0e9",
        "snapshot": false,
        "version": "8.16.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_google_threat_intelligence.mobile",
        "ingested": "2025-03-13T05:35:18Z",
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
        "google_threat_intelligence-mobile"
    ],
    "threat": {
        "indicator": {
            "feed_type": "Mobile",
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
                "google_threat_intelligence-mobile"
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
| gti.mobile.id.domain | The domain address associated with the entity. | keyword |
| gti.mobile.id.file | The file object ID (SHA256 hash) associated with the entity. | keyword |
| gti.mobile.id.ip | The IP address associated with the entity. | ip |
| gti.mobile.id.url | The URL address associated with the entity. | keyword |
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


### OS X

This is the `OS X` dataset.

#### Example

An example event for `osx` looks as following:

```json
{
    "@timestamp": "2025-01-27T19:51:31.000Z",
    "agent": {
        "ephemeral_id": "698fe063-f10e-4181-9bda-23936a7c564c",
        "id": "92c55ad6-fd53-4f91-a532-574e948475b4",
        "name": "elastic-agent-35481",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "dataset": "ti_google_threat_intelligence.osx",
        "namespace": "62856",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "92c55ad6-fd53-4f91-a532-574e948475b4",
        "snapshot": false,
        "version": "8.16.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_google_threat_intelligence.osx",
        "ingested": "2025-03-13T05:37:38Z",
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
        "google_threat_intelligence-osx"
    ],
    "threat": {
        "indicator": {
            "feed_type": "OS X",
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
                "google_threat_intelligence-osx"
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
| gti.osx.id.domain | The domain address associated with the entity. | keyword |
| gti.osx.id.file | The file object ID (SHA256 hash) associated with the entity. | keyword |
| gti.osx.id.ip | The IP address associated with the entity. | ip |
| gti.osx.id.url | The URL address associated with the entity. | keyword |
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

