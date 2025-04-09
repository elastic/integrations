# Google Threat Intelligence

## Overview

[Google Threat Intelligence](https://gtidocs.virustotal.com/) is a security solution that helps organizations detect, analyze, and mitigate threats. It leverages Google's global telemetry, advanced analytics, and vast infrastructure to provide actionable insights. Key features include threat detection, malware and phishing analysis, and real-time threat alerts.

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

## Transforming Data for Up-to-Date Insights

To keep the collected data up to date, **Transforms** are used.

Users can view the transforms by navigating to **Management > Stack Management > Transforms**.

Here, users can see continuously running transforms and also view the latest transformed GTI data in the **Discover** section.

The `labels.is_transform_source` field indicates log origin:
- **False** for transformed index
- **True** for source index

Currently, four transforms are running across all 15 data streams:

| Transform Name                                                                        | Description                                              |
| ------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| IP IOC Stream Transform  (ID: `logs-ti_google_threat_intelligence.ip_ioc_st`)         | Keeps IP entity type data up to date for IOC Stream.     |
| URL IOC Stream Transform  (ID: `logs-ti_google_threat_intelligence.url_ioc_st`)       | Keeps URL entity type data up to date for IOC Stream.    |
| Domain IOC Stream Transform  (ID: `logs-ti_google_threat_intelligence.domain_ioc_st`) | Keeps Domain entity type data up to date for IOC Stream. |
| File IOC Stream Transform  (ID: `logs-ti_google_threat_intelligence.file_ioc_st`)     | Keeps File entity type data up to date for IOC Stream.   |

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

**Note:** One transforms run in the background to filter relevant data from alerts. The  `data_stream.dataset: ti_google_threat_intelligence.enriched_ioc_stream` field represents logs for enriched threat intelligence data, which can be analyzed in the **Discover** section.

The following are the names of the four sample rules:

| Sample Rule Name                                             | Description                                                                                                                           |
| ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------- |
| Google Threat Intelligence URL IOC Stream Correlation        | Detects and alerts on matches between URL IOCs collected by GTI IOC Stream data with user's selected Elastic environment data.        |
| Google Threat Intelligence Domain IOC Stream Correlation     | Detects and alerts on matches between Domain IOCs collected by GTI IOC Stream data with user's selected Elastic environment data.     |
| Google Threat Intelligence File IOC Stream Correlation       | Detects and alerts on matches between File IOCs collected by GTI IOC Stream data with user's selected Elastic environment data.       |
| Google Threat Intelligence IP Address IOC Stream Correlation | Detects and alerts on matches between IP Address IOCs collected by GTI IOC Stream data with user's selected Elastic environment data. |

## Limitations

1. If an event contains multiple matching mappings (e.g., two file hash fields within the same event match GTI data), only one alert per detection rule will be generated for that event.
2. If an IOC from the user's Elasticsearch index is enriched with GTI information, and the GTI information is updated later, the changes are not reflected in the dashboards because Elastic detection rules only run on live data.

## Troubleshooting

1. If you see an error like `Package 2025031310 is not available until 2025-03-13 at 11:00 UTC because of privacy policy.`, ensure that your initial interval and interval are set in hours and are greater than one hour.
2. If events are not appearing in the transformed index, check if transforms are running without errors. If you encounter issues, refer to [Troubleshooting transforms](https://www.elastic.co/guide/en/elasticsearch/reference/current/transform-troubleshooting.html).
3. If detection rules take longer to run, ensure you have specified index patterns and applied queries to make your source events more specific.
   **Note:** More events in index patterns mean more time needed for detection rules to run.
4. Ensure that relevant fields are correctly mapped in the **Indicator Mapping** section. Verify that fields in the specified index pattern are properly mapped, and ensure entity-specific fields (e.g., IP fields to IP fields, keyword fields like file hash SHA256 to corresponding file hash SHA256 fields) are accurately configured.

## Logs Reference

### IOC Stream

This is the `IOC Stream` dataset.

#### Example

An example event for `ioc_stream` looks as following:

```json
{
    "@timestamp": "2024-12-16T07:54:23.000Z",
    "agent": {
        "ephemeral_id": "434d6bd6-4006-4c6c-8325-dd518363845f",
        "id": "556b7d12-deac-4a67-bee5-fabebf19b583",
        "name": "elastic-agent-80119",
        "type": "filebeat",
        "version": "8.17.3"
    },
    "data_stream": {
        "dataset": "ti_google_threat_intelligence.ioc_stream",
        "namespace": "65550",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "556b7d12-deac-4a67-bee5-fabebf19b583",
        "snapshot": false,
        "version": "8.17.3"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "dataset": "ti_google_threat_intelligence.ioc_stream",
        "ingested": "2025-04-07T13:04:34Z",
        "kind": "enrichment",
        "original": "{\"attributes\":{\"available_tools\":[],\"downloadable\":true,\"exiftool\":{\"FileType\":\"TXT\",\"FileTypeExtension\":\"txt\",\"LineCount\":\"1\",\"MIMEEncoding\":\"us-ascii\",\"MIMEType\":\"text/plain\",\"Newlines\":\"(none)\",\"WordCount\":\"1\"},\"first_seen_itw_date\":1707511993,\"first_submission_date\":1648544390,\"gti_assessment\":{\"contributing_factors\":{\"associated_actor\":[\"source\",\"javascript\",\"js\"],\"mandiant_association_actor\":true,\"mandiant_confidence_score\":75},\"description\":\"This indicator did not match our detection criteria and there is currently no evidence of malicious activity.\",\"severity\":{\"value\":\"SEVERITY_NONE\"},\"threat_score\":{\"value\":1},\"verdict\":{\"value\":\"VERDICT_UNDETECTED\"}},\"last_analysis_date\":1648544390,\"last_analysis_stats\":{\"confirmed-timeout\":0,\"failure\":0,\"harmless\":0,\"malicious\":0,\"suspicious\":0,\"timeout\":0,\"type-unsupported\":16,\"undetected\":57},\"last_modification_date\":1734335663,\"last_seen_itw_date\":1707512002,\"last_submission_date\":1648544390,\"magic\":\"ASCII text, with no line terminators\",\"mandiant_ic_score\":75,\"md5\":\"1e1d23c4e7524bc15a0b3ced0caf9ffc\",\"meaningful_name\":\"Password[1].htm\",\"names\":[\"Password[1].htm\"],\"reputation\":0,\"sha1\":\"4e234b019b77a4f04c168734a60e0b1883989215\",\"sha256\":\"841d999a7a7f0b2cd8bc21e6550fedee985bf53a530fef1033d1c4810b0be5bc\",\"size\":11,\"ssdeep\":\"3:EsaM:t\",\"tags\":[\"javascript\"],\"times_submitted\":1,\"total_votes\":{\"harmless\":0,\"malicious\":0},\"type_description\":\"JavaScript\",\"type_extension\":\"js\",\"type_tag\":\"javascript\",\"type_tags\":[\"source\",\"javascript\",\"js\"],\"unique_sources\":1,\"vhash\":\"9eecb7db59d16c80417c72d1e1f4fbf1\"},\"context_attributes\":{\"hunting_info\":null,\"notification_date\":1742528463,\"notification_id\":\"21769600967\",\"origin\":\"subscriptions\",\"sources\":[{\"id\":\"threat-actor--bfd69ac3-0158-57d3-a101-42496712ddae\",\"label\":\"UNC4515\",\"type\":\"collection\"}],\"tags\":[]},\"id\":\"841d999a7a7f0b2cd8bc21e6550fedee985bf53a530fef1033d1c4810b0be5bc\",\"links\":{\"self\":\"https://www.virustotal.com/api/v3/files/841d999a7a7f0b2cd8bc21e6550fedee985bf53a530fef1033d1c4810b0be5bc\"},\"type\":\"file\"}",
        "type": [
            "indicator"
        ]
    },
    "file": {
        "attributes": [
            "Password[1].htm"
        ],
        "extension": "js",
        "hash": {
            "md5": "1e1d23c4e7524bc15a0b3ced0caf9ffc",
            "sha1": "4e234b019b77a4f04c168734a60e0b1883989215",
            "sha256": "841d999a7a7f0b2cd8bc21e6550fedee985bf53a530fef1033d1c4810b0be5bc"
        },
        "mime_type": "text/plain",
        "name": "Password[1].htm",
        "type": "JavaScript"
    },
    "gti": {
        "ioc_stream": {
            "attributes": {
                "assessment": {
                    "contributing_factors": {
                        "mandiant_confidence_score": 75
                    },
                    "description": "This indicator did not match our detection criteria and there is currently no evidence of malicious activity.",
                    "severity": "SEVERITY_NONE",
                    "threat_score": 1,
                    "verdict": "VERDICT_UNDETECTED"
                },
                "downloadable": true,
                "exiftool": {
                    "file": {
                        "type": "TXT",
                        "type_extension": "txt"
                    },
                    "line_count": 1,
                    "mime": {
                        "encoding": "us-ascii",
                        "type": "text/plain"
                    },
                    "newlines": "(none)",
                    "word_count": 1
                },
                "failure": 0,
                "first_seen_itw_date": "2024-02-09T20:53:13.000Z",
                "first_submission_date": "2022-03-29T08:59:50.000Z",
                "last_analysis_date": "2022-03-29T08:59:50.000Z",
                "last_analysis_stats": {
                    "confirmed_timeout": 0,
                    "harmless": 0,
                    "malicious": 0,
                    "suspicious": 0,
                    "timeout": 0,
                    "undetected": 57
                },
                "last_modification_date": "2024-12-16T07:54:23.000Z",
                "last_seen_itw_date": "2024-02-09T20:53:22.000Z",
                "last_submission_date": "2022-03-29T08:59:50.000Z",
                "magic": "ASCII text, with no line terminators",
                "mandiant_ic_score": 75,
                "md5": "1e1d23c4e7524bc15a0b3ced0caf9ffc",
                "meaningful_name": "Password[1].htm",
                "names": [
                    "Password[1].htm"
                ],
                "reputation": 0,
                "sha1": "4e234b019b77a4f04c168734a60e0b1883989215",
                "sha256": "841d999a7a7f0b2cd8bc21e6550fedee985bf53a530fef1033d1c4810b0be5bc",
                "size": 11,
                "ssdeep": "3:EsaM:t",
                "tags": [
                    "javascript"
                ],
                "times_submitted": 1,
                "total_votes": {
                    "harmless": 0,
                    "malicious": 0
                },
                "type_description": "JavaScript",
                "type_extension": "js",
                "type_tags": [
                    "source",
                    "javascript",
                    "js"
                ],
                "type_unsupported": 16,
                "unique_sources": 1
            },
            "context_attributes": {
                "notification_date": "2025-03-21T03:41:03.000Z",
                "notification_id": 21769600967,
                "origin": "subscriptions",
                "sources": [
                    {
                        "id": "threat-actor--bfd69ac3-0158-57d3-a101-42496712ddae",
                        "label": "UNC4515",
                        "type": "collection"
                    }
                ]
            },
            "id": "841d999a7a7f0b2cd8bc21e6550fedee985bf53a530fef1033d1c4810b0be5bc",
            "type": "file",
            "vhash": "9eecb7db59d16c80417c72d1e1f4fbf1"
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
            "1e1d23c4e7524bc15a0b3ced0caf9ffc",
            "4e234b019b77a4f04c168734a60e0b1883989215",
            "841d999a7a7f0b2cd8bc21e6550fedee985bf53a530fef1033d1c4810b0be5bc",
            "3:EsaM:t",
            "9eecb7db59d16c80417c72d1e1f4fbf1"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "google_threat_intelligence-ioc_stream"
    ],
    "threat": {
        "indicator": {
            "file": {
                "hash": {
                    "sha256": "841d999a7a7f0b2cd8bc21e6550fedee985bf53a530fef1033d1c4810b0be5bc"
                }
            },
            "id": [
                "841d999a7a7f0b2cd8bc21e6550fedee985bf53a530fef1033d1c4810b0be5bc"
            ],
            "type": "file"
        }
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
| gti.ioc_stream.attributes.as_owner | The name of the Autonomous System (AS) owner that controls the IP address associated with the analyzed entity. | keyword |
| gti.ioc_stream.attributes.asn | The Autonomous System Number (ASN) associated with the IP address. | long |
| gti.ioc_stream.attributes.assessment.contributing_factors.gavs_detections | Indicates detections from the Global Anti-Virus System (GAVS). | long |
| gti.ioc_stream.attributes.assessment.contributing_factors.malicious_sandbox_verdict | This field represents a malicious verdict assigned by sandbox analysis as part of GTI (Global Threat Intelligence) assessment in VirusTotal. | boolean |
| gti.ioc_stream.attributes.assessment.contributing_factors.mandiant_analyst_malicious | Reflects assessments from Mandiant analysts deeming the artifact as malicious. | boolean |
| gti.ioc_stream.attributes.assessment.contributing_factors.mandiant_analyst_observed_recent | Indicates recent observations by Mandiant analysts, suggesting current relevance or activity of the artifact. | boolean |
| gti.ioc_stream.attributes.assessment.contributing_factors.mandiant_association_actor | Denotes associations made by Mandiant linking the artifact to specific threat actors. | keyword |
| gti.ioc_stream.attributes.assessment.contributing_factors.mandiant_association_report | References reports from Mandiant associating the artifact with particular threat actors or campaigns. | keyword |
| gti.ioc_stream.attributes.assessment.contributing_factors.mandiant_confidence_score | Provides a confidence score from Mandiant regarding the artifact's assessment. | long |
| gti.ioc_stream.attributes.assessment.contributing_factors.normalised_categories | Lists normalized threat categories applicable to the artifact. | keyword |
| gti.ioc_stream.attributes.assessment.contributing_factors.pervasive_indicator | Indicates whether the file, URL, or domain has been observed widely distributed or frequently encountered across multiple threat intelligence sources. | boolean |
| gti.ioc_stream.attributes.assessment.contributing_factors.safebrowsing_verdict | Represents the Google Safe Browsing verdict for the domain or URL. | keyword |
| gti.ioc_stream.attributes.assessment.description | Offers a textual description of the artifact's assessment, summarizing its characteristics, behavior, or threat level. | keyword |
| gti.ioc_stream.attributes.assessment.severity | Indicates the severity level assigned to the artifact. | keyword |
| gti.ioc_stream.attributes.assessment.threat_score | Provides a numerical threat score, quantifying the risk associated with the artifact based on various factors and analyses. | long |
| gti.ioc_stream.attributes.assessment.verdict | Presents the final verdict on the artifact's status. | keyword |
| gti.ioc_stream.attributes.authentihash | A cryptographic hash of the file's Authenticode signature. | keyword |
| gti.ioc_stream.attributes.autostart_locations.entry | Specifies the particular autostart entry associated with the file, indicating how the file is configured to execute automatically upon system startup. | keyword |
| gti.ioc_stream.attributes.autostart_locations.location | Denotes the specific system location or registry path where the autostart entry is configured. | keyword |
| gti.ioc_stream.attributes.available_tools | Lists tools or utilities available for further analysis or interaction with the file. | keyword |
| gti.ioc_stream.attributes.categories.bitdefender | Categorization of the entity as determined by BitDefender, a cybersecurity vendor. | keyword |
| gti.ioc_stream.attributes.categories.sophos | Classification by Sophos, a cybersecurity vendor providing endpoint protection and threat intelligence. | keyword |
| gti.ioc_stream.attributes.categories.webroot | Verdict assigned by Webroot, a cybersecurity firm specializing in cloud-based threat intelligence. | keyword |
| gti.ioc_stream.attributes.continent | The continent where the IP address or domain is geographically located. | keyword |
| gti.ioc_stream.attributes.country | The country where the IP address or domain is registered or hosted. | keyword |
| gti.ioc_stream.attributes.creation_date | The timestamp indicating when the artifact was originally created. | date |
| gti.ioc_stream.attributes.crowdsourced_ai_results.analysis | Contains the outcome of AI-driven analyses performed by the community. | keyword |
| gti.ioc_stream.attributes.crowdsourced_ai_results.category | Classifies the file based on the AI analysis. | keyword |
| gti.ioc_stream.attributes.crowdsourced_ai_results.id | A unique identifier for the specific AI analysis result. | keyword |
| gti.ioc_stream.attributes.crowdsourced_ai_results.source | Identifies the origin or contributor of the AI analysis. | keyword |
| gti.ioc_stream.attributes.crowdsourced_ids_results.alert_context.dest_ip | The destination IP address contacted by the file, which triggered ids alerts by its activity. | ip |
| gti.ioc_stream.attributes.crowdsourced_ids_results.alert_context.dest_port | The destination port number used in the connection. | long |
| gti.ioc_stream.attributes.crowdsourced_ids_results.alert_context.hostname | The hostname associated with the network activity. | keyword |
| gti.ioc_stream.attributes.crowdsourced_ids_results.alert_context.ja3 | Represents the JA3 TLS fingerprint hash. | keyword |
| gti.ioc_stream.attributes.crowdsourced_ids_results.alert_context.src_ip | The source IP address from which the connection originated. | ip |
| gti.ioc_stream.attributes.crowdsourced_ids_results.alert_context.src_port | The source port number used in the connection. | long |
| gti.ioc_stream.attributes.crowdsourced_ids_results.alert_context.url | The protocol used for the network communication. | keyword |
| gti.ioc_stream.attributes.crowdsourced_ids_results.alert_severity | Indicates the severity level of the IDS alerts. | keyword |
| gti.ioc_stream.attributes.crowdsourced_ids_results.rule_category | Categorizes the type of rule that was triggered by the IDS alerts. | keyword |
| gti.ioc_stream.attributes.crowdsourced_ids_results.rule_id | A unique identifier for the IDS rule that was matched. | keyword |
| gti.ioc_stream.attributes.crowdsourced_ids_results.rule_msg | A message or description associated with the triggered rule. | keyword |
| gti.ioc_stream.attributes.crowdsourced_ids_results.rule_raw | Specifies the origin or source of the IDS rule. | keyword |
| gti.ioc_stream.attributes.crowdsourced_ids_results.rule_references | An array of URLs or identifiers that offer additional information about the IDS rule that was triggered. . | keyword |
| gti.ioc_stream.attributes.crowdsourced_ids_results.rule_source | Indicates the origin or provider of the Intrusion Detection System (IDS) rule that was triggered. | keyword |
| gti.ioc_stream.attributes.crowdsourced_ids_results.rule_url | Provides a direct link to an external source containing additional details about the specific Intrusion Detection System (IDS) rule that was triggered. | keyword |
| gti.ioc_stream.attributes.crowdsourced_ids_stats.high | Number of IDS alerts categorized as high severity. | long |
| gti.ioc_stream.attributes.crowdsourced_ids_stats.info | Number of IDS alerts categorized as informational. | long |
| gti.ioc_stream.attributes.crowdsourced_ids_stats.low | Number of IDS alerts categorized as low severity. | long |
| gti.ioc_stream.attributes.crowdsourced_ids_stats.medium | Number of IDS alerts categorized as medium severity. | long |
| gti.ioc_stream.attributes.crowdsourced_yara_results.author | The name or identifier of the author who wrote the YARA rule that matched the file. | keyword |
| gti.ioc_stream.attributes.crowdsourced_yara_results.description | A brief explanation of what the YARA rule detects. | keyword |
| gti.ioc_stream.attributes.crowdsourced_yara_results.match_date | The timestamp indicating when the YARA rule matched the file. | date |
| gti.ioc_stream.attributes.crowdsourced_yara_results.match_in_subfile | Indicates whether a YARA rule match was found inside a subfile of the scanned object. | boolean |
| gti.ioc_stream.attributes.crowdsourced_yara_results.rule_name | The specific name of the YARA rule that was triggered by the file. | keyword |
| gti.ioc_stream.attributes.crowdsourced_yara_results.ruleset_id | A unique identifier for the ruleset to which the matched YARA rule belongs. | keyword |
| gti.ioc_stream.attributes.crowdsourced_yara_results.ruleset_name | The name of the YARA ruleset that contains the matched rule. | keyword |
| gti.ioc_stream.attributes.crowdsourced_yara_results.ruleset_version | The versionof the YARA ruleset that contains the matched rule. | keyword |
| gti.ioc_stream.attributes.crowdsourced_yara_results.source | The origin of the YARA rule, indicating who contributed the rule. | keyword |
| gti.ioc_stream.attributes.detectiteasy.filetype | Indicates the primary file type as determined by Detect It Easy. | keyword |
| gti.ioc_stream.attributes.detectiteasy.values.info | Provides additional details or comments about the detected attribute. | keyword |
| gti.ioc_stream.attributes.detectiteasy.values.name | Specifies the name of the detected attribute, such as the packer, compiler, or protector used. | keyword |
| gti.ioc_stream.attributes.detectiteasy.values.type | Categorizes the nature of the detected attribute, indicating whether it's a 'Compiler', 'Packer', 'Protector', or another classification. | keyword |
| gti.ioc_stream.attributes.detectiteasy.values.version | Denotes the version number of the detected attribute. | keyword |
| gti.ioc_stream.attributes.downloadable | This boolean attribute indicates whether the file is available for download from VirusTotal. | boolean |
| gti.ioc_stream.attributes.exiftool.character_set | This field specifies the character encoding used in the file's metadata. | keyword |
| gti.ioc_stream.attributes.exiftool.code_size | Represents the size of the code section within the executable file. | long |
| gti.ioc_stream.attributes.exiftool.company_name | Denotes the name of the company or entity that developed or owns the software, as specified in the file's metadata. | keyword |
| gti.ioc_stream.attributes.exiftool.entry_point | Indicates the memory address where the execution of the program begins. | keyword |
| gti.ioc_stream.attributes.exiftool.file.description | This field provides a brief description of the file's purpose or functionality. | keyword |
| gti.ioc_stream.attributes.exiftool.file.flags_mask | Represents a set of binary flags indicating specific attributes or behaviors of the file. | keyword |
| gti.ioc_stream.attributes.exiftool.file.os | Specifies the operating system for which the file was designed. | keyword |
| gti.ioc_stream.attributes.exiftool.file.subtype | Provides additional granularity about the file's type. | keyword |
| gti.ioc_stream.attributes.exiftool.file.type | Identifies the general category of the file.. | keyword |
| gti.ioc_stream.attributes.exiftool.file.type_extension | Indicates the standard file extension associated with the file type. | keyword |
| gti.ioc_stream.attributes.exiftool.file.version | Denotes the version of the file as specified in its metadata. | keyword |
| gti.ioc_stream.attributes.exiftool.file.version_number | Represents the numerical value of the file's version. | keyword |
| gti.ioc_stream.attributes.exiftool.image.file_characteristics | Indicates specific attributes or features of the image file. | keyword |
| gti.ioc_stream.attributes.exiftool.image.version | Specifies the version of the image file format or the software used to create or modify the image. | keyword |
| gti.ioc_stream.attributes.exiftool.initialized_data_size | Represents the size of the initialized data section within an executable file, typically measured in bytes. | long |
| gti.ioc_stream.attributes.exiftool.internal_name | Denotes the internal name of the file, as specified in its metadata. | keyword |
| gti.ioc_stream.attributes.exiftool.language_code | Indicates the language code associated with the file. | keyword |
| gti.ioc_stream.attributes.exiftool.legal_copyright | Provides the legal copyright information for the file. | keyword |
| gti.ioc_stream.attributes.exiftool.line_count | Specifies the number of lines in a text file, providing insight into the file's length and structure. | long |
| gti.ioc_stream.attributes.exiftool.linker_version | Denotes the version of the linker used to create the executable file. | keyword |
| gti.ioc_stream.attributes.exiftool.machine_type | Indicates the type of machine or architecture for which the file is intended. | keyword |
| gti.ioc_stream.attributes.exiftool.mime.encoding | Specifies the character encoding used in the file. | keyword |
| gti.ioc_stream.attributes.exiftool.mime.type | Identifies the file's media type. | keyword |
| gti.ioc_stream.attributes.exiftool.newlines | Indicates the type of newline characters used in a text file. | keyword |
| gti.ioc_stream.attributes.exiftool.object_file_type | Indicates the type of object file. | keyword |
| gti.ioc_stream.attributes.exiftool.original_file_name | Specifies the original name of the file as defined in its metadata. | keyword |
| gti.ioc_stream.attributes.exiftool.os_version | Denotes the version of the operating system for which the file was designed. | keyword |
| gti.ioc_stream.attributes.exiftool.pe_type | Identifies the type of Portable Executable (PE) file. | keyword |
| gti.ioc_stream.attributes.exiftool.product.name | Provides the name of the product with which the file is associated. | keyword |
| gti.ioc_stream.attributes.exiftool.product.version | Indicates the version of the product with which the file is associated. | keyword |
| gti.ioc_stream.attributes.exiftool.product.version_number | Represents the numerical version of the product, often in a 'major.minor.build.revision' format. | keyword |
| gti.ioc_stream.attributes.exiftool.subsystem | Specifies the subsystem required to execute the file, indicating the environment in which the executable expects to run. | keyword |
| gti.ioc_stream.attributes.exiftool.subsystem_version | Denotes the version of the subsystem that is required to execute the file. | keyword |
| gti.ioc_stream.attributes.exiftool.timestamp | Records the date and time when the file was created or last modified. | date |
| gti.ioc_stream.attributes.exiftool.uninitialized_data_size | Indicates the size of the uninitialized data section within the executable file. | long |
| gti.ioc_stream.attributes.exiftool.word_count | Indicates the total number of words in the file. | long |
| gti.ioc_stream.attributes.failure | Count of antivirus engines that encountered a failure when analyzing the file. | long |
| gti.ioc_stream.attributes.favicon.dhash | A perceptual hash (dhash) of the favicon image. | keyword |
| gti.ioc_stream.attributes.favicon.raw_md5 | An MD5 hash of the raw favicon artifact . | keyword |
| gti.ioc_stream.attributes.filecondis.dhash | Represents a perceptual hash (dHash) of the file. | keyword |
| gti.ioc_stream.attributes.filecondis.raw_md5 | Provides the raw MD5 hash of the file. | keyword |
| gti.ioc_stream.attributes.first_seen_itw_date | Denotes the date when the artifact was first observed in real-world environments. | date |
| gti.ioc_stream.attributes.first_submission_date | Specifies the date when the artifact  was first submitted to VirusTotal for analysis. | date |
| gti.ioc_stream.attributes.has_content | The attributes.has_content field indicates whether the entity (file, URL, domain, or IP) has retrievable content in VirusTotal. | boolean |
| gti.ioc_stream.attributes.jarm | jarm is a fingerprint that uniquely identifies a TLS/SSL server based on how it responds to different encrypted handshake probes. | keyword |
| gti.ioc_stream.attributes.last_analysis_date | Specifies the date when the artifact was last analyzed by VirusTotal. | date |
| gti.ioc_stream.attributes.last_analysis_stats.confirmed_timeout | Number of antivirus engines that confirmed a timeout during analysis. | long |
| gti.ioc_stream.attributes.last_analysis_stats.harmless | Number of engines that determined the artifact to be harmless. | long |
| gti.ioc_stream.attributes.last_analysis_stats.malicious | Count of engines that flagged the artifact as malicious. | long |
| gti.ioc_stream.attributes.last_analysis_stats.suspicious | Number of engines that deemed the artifact suspicious. | long |
| gti.ioc_stream.attributes.last_analysis_stats.timeout | Count of engines that reached a timeout during analysis. | long |
| gti.ioc_stream.attributes.last_analysis_stats.undetected | Count of engines that did not detect any issues with the artifact. | long |
| gti.ioc_stream.attributes.last_dns_records.expire | last_dns_records array, the expire field specifies the duration (in seconds) that a secondary DNS server will cache the zone data before it must refresh it from the primary DNS server. | long |
| gti.ioc_stream.attributes.last_dns_records.minimum | This field represents the minimum TTL (Time-To-Live) value specified in the domain's DNS SOA (Start of Authority) record. | long |
| gti.ioc_stream.attributes.last_dns_records.priority | This field specifies the priority of the DNS record, primarily applicable to MX (Mail Exchange) records. | long |
| gti.ioc_stream.attributes.last_dns_records.refresh | This field indicates the interval (in seconds) that secondary DNS servers should wait before querying the primary DNS server to check for updates to the zone artifact. | long |
| gti.ioc_stream.attributes.last_dns_records.retry | This field specifies the interval (in seconds) that secondary DNS servers should wait before retrying to contact the primary DNS server after a failed attempt to refresh the zone artifact. | long |
| gti.ioc_stream.attributes.last_dns_records.rname | This field represents the "Responsible Name" (RNAME) in the SOA (Start of Authority) record. | keyword |
| gti.ioc_stream.attributes.last_dns_records.serial | This field holds the "Serial Number" from the domain's SOA record. | long |
| gti.ioc_stream.attributes.last_dns_records.ttl | Time-To-Live (TTL) value, specifying how long the DNS record should be cached by DNS resolvers before requesting an update. | long |
| gti.ioc_stream.attributes.last_dns_records.type | This field indicates the type of DNS record. | keyword |
| gti.ioc_stream.attributes.last_dns_records.value | The actual value associated with the DNS record. . | keyword |
| gti.ioc_stream.attributes.last_dns_records_date | This field represents the timestamp when VirusTotal last retrieved the DNS records for the domain. | date |
| gti.ioc_stream.attributes.last_final_url | The final URL after all redirections when the URL was last analyzed by VirusTotal. | keyword |
| gti.ioc_stream.attributes.last_http_response_code | The last HTTP response status code received when the URL was scanned by VirusTotal. | long |
| gti.ioc_stream.attributes.last_http_response_content_length | The size (in bytes) of the content returned in the last HTTP response when the URL was analyzed. | long |
| gti.ioc_stream.attributes.last_http_response_content_sha256 | The SHA-256 hash of the content retrieved from the URL during its last scan. | keyword |
| gti.ioc_stream.attributes.last_https_certificate.cert_signature.signature | The actual digital signature of the certificate, represented as a hexadecimal string. | keyword |
| gti.ioc_stream.attributes.last_https_certificate.cert_signature.signature_algorithm | The algorithm used to create the certificate's digital signature, such as "sha256RSA". | keyword |
| gti.ioc_stream.attributes.last_https_certificate.issuer.c | The country code (C) of the entity that issued the certificate. | keyword |
| gti.ioc_stream.attributes.last_https_certificate.issuer.cn | The Common Name (CN) of the certificate's issuer, typically the name of the Certificate Authority. | keyword |
| gti.ioc_stream.attributes.last_https_certificate.issuer.l | The locality (L) or city of the certificate's issuer. | keyword |
| gti.ioc_stream.attributes.last_https_certificate.issuer.o | The Organization (O) name of the certificate's issuer. | keyword |
| gti.ioc_stream.attributes.last_https_certificate.issuer.ou | The Organizational Unit (OU) within the issuing organization. | keyword |
| gti.ioc_stream.attributes.last_https_certificate.issuer.st | The state or province (ST) where the certificate's issuer is located. | keyword |
| gti.ioc_stream.attributes.last_https_certificate.public_key.algorithm | The algorithm used for the public key in the certificate, such as "RSA", "DSA", or "EC". | keyword |
| gti.ioc_stream.attributes.last_https_certificate.public_key.ec.oid | For Elliptic Curve (EC) public keys, this field specifies the object identifier (OID) of the elliptic curve used. | keyword |
| gti.ioc_stream.attributes.last_https_certificate.public_key.ec.pub | The public key for an Elliptic Curve (EC) certificate. | keyword |
| gti.ioc_stream.attributes.last_https_certificate.public_key.rsa.exponent | The exponent value of the RSA public key, typically 65537 (0x10001 in hexadecimal). | keyword |
| gti.ioc_stream.attributes.last_https_certificate.public_key.rsa.key_size | The size of the RSA public key in bits, commonly 2048 or 4096. | long |
| gti.ioc_stream.attributes.last_https_certificate.public_key.rsa.modulus | The modulus (n) of the RSA public key, a large integer used in the encryption process. | keyword |
| gti.ioc_stream.attributes.last_https_certificate.serial_number | The unique identifier assigned to the certificate by the Certificate Authority (CA). | keyword |
| gti.ioc_stream.attributes.last_https_certificate.signature_algorithm | The cryptographic algorithm used to sign the certificate, such as sha256RSA. | keyword |
| gti.ioc_stream.attributes.last_https_certificate.size | The size of the HTTPS certificate in bytes. | long |
| gti.ioc_stream.attributes.last_https_certificate.subject.cn | The Common Name (CN) of the certificate subject, which usually represents the domain name the certificate is issued for. | keyword |
| gti.ioc_stream.attributes.last_https_certificate.tags | A list of descriptive tags associated with the certificate, such as self-signed, wildcard, or Let's Encrypt. | keyword |
| gti.ioc_stream.attributes.last_https_certificate.thumbprint | The SHA-1 fingerprint (hash) of the certificate, used for quick identification. | keyword |
| gti.ioc_stream.attributes.last_https_certificate.thumbprint_sha256 | The SHA-256 fingerprint (hash) of the certificate, offering a more secure alternative to SHA-1. | keyword |
| gti.ioc_stream.attributes.last_https_certificate.validity.not_after | The expiration date of the certificate. | keyword |
| gti.ioc_stream.attributes.last_https_certificate.validity.not_before | The issue date of the certificate. | keyword |
| gti.ioc_stream.attributes.last_https_certificate.version | The X.509 version of the certificate (commonly 3 for modern certificates). | keyword |
| gti.ioc_stream.attributes.last_https_certificate_date | The timestamp indicating when VirusTotal last retrieved the HTTPS certificate for the domain. | date |
| gti.ioc_stream.attributes.last_modification_date | The date when the artifact was last modified, represented as a Unix epoch timestamp. | date |
| gti.ioc_stream.attributes.last_seen_itw_date | The most recent date the artifact was observed "in the wild," indicating its latest detection in real-world environments. | date |
| gti.ioc_stream.attributes.last_submission_date | The date when the artifact was last submitted to VirusTotal for analysis. | date |
| gti.ioc_stream.attributes.last_update_date | The timestamp of the last update for the given entity in VirusTotal’s dataset. | date |
| gti.ioc_stream.attributes.magic | A textual description of the file's format, derived from its magic number. | keyword |
| gti.ioc_stream.attributes.magika | Additional metadata about the file's format or structure, complementing the magic field. | keyword |
| gti.ioc_stream.attributes.main_icon.dhash | A perceptual hash of the file's main icon, used to identify visually similar icons. | keyword |
| gti.ioc_stream.attributes.main_icon.raw_md5 | The MD5 hash of the file's main icon, serving as a unique identifier for the icon's content. | keyword |
| gti.ioc_stream.attributes.mandiant_ic_score | A score assigned by Mandiant, reflecting the artifact's threat level based on their intelligence. | long |
| gti.ioc_stream.attributes.md5 | The MD5 hash of the file, providing a unique identifier based on its content. | keyword |
| gti.ioc_stream.attributes.meaningful_name | A human-readable name for the file, often derived from its metadata or content. | keyword |
| gti.ioc_stream.attributes.names | An array of names associated with the file, including aliases or detected names during analysis. | keyword |
| gti.ioc_stream.attributes.network | The network block (CIDR range) to which the analyzed IP address belongs. | keyword |
| gti.ioc_stream.attributes.outgoing_links | A list of URLs that were found as outgoing links from the analyzed page. | keyword |
| gti.ioc_stream.attributes.pe_info.compiler_product_versions | An array detailing the versions of compiler products used to build the file. | keyword |
| gti.ioc_stream.attributes.pe_info.debug.codeview.age | Represents the revision number of the debug information. | long |
| gti.ioc_stream.attributes.pe_info.debug.codeview.guid | A unique identifier that corresponds to the PDB (Program Database) file used during compilation. | keyword |
| gti.ioc_stream.attributes.pe_info.debug.codeview.name | The Program Database (PDB) file name. | keyword |
| gti.ioc_stream.attributes.pe_info.debug.codeview.signature | A unique identifier or hash used for verifying the debug information. | keyword |
| gti.ioc_stream.attributes.pe_info.debug.offset | The location of the debug information within the file. | long |
| gti.ioc_stream.attributes.pe_info.debug.reserved10.value | A reserved field in the debug structure that Represents a numerical placeholder value, often set to 0 or another integer. | keyword |
| gti.ioc_stream.attributes.pe_info.debug.size | The size of the debug information chunk. | long |
| gti.ioc_stream.attributes.pe_info.debug.timestamp | The date and time when the debug data was created. | keyword |
| gti.ioc_stream.attributes.pe_info.debug.type | An integer representing the format of the debugging information. | long |
| gti.ioc_stream.attributes.pe_info.debug.type_str | A human-readable string describing the debug type, corresponding to the type field. | keyword |
| gti.ioc_stream.attributes.pe_info.entry_point | The address of the executable's entry point, indicating where execution begins when the PE is loaded into memory. | long |
| gti.ioc_stream.attributes.pe_info.exports | A list of function names that the PE file exports, typically found in DLLs to provide functions for other modules. | keyword |
| gti.ioc_stream.attributes.pe_info.imphash | A hash value calculated based on the imported functions and libraries, used to identify similarities between different PE files. | keyword |
| gti.ioc_stream.attributes.pe_info.import_list.imported_functions | A list of function names imported from the specified library. | keyword |
| gti.ioc_stream.attributes.pe_info.import_list.library_name | The name of the DLL from which functions are imported. | keyword |
| gti.ioc_stream.attributes.pe_info.machine_type | An integer specifying the platform for which the executable is intended, such as IMAGE_FILE_MACHINE_I386 for Intel 386 or later processors. | long |
| gti.ioc_stream.attributes.pe_info.resource_details.chi2 | The chi-squared test value of the resource content, used to detect anomalies or non-standard data. | double |
| gti.ioc_stream.attributes.pe_info.resource_details.entropy | The entropy value of the resource content, indicating the randomness or complexity of the data. | double |
| gti.ioc_stream.attributes.pe_info.resource_details.filetype | The identified file format of the resource, if recognizable. | keyword |
| gti.ioc_stream.attributes.pe_info.resource_details.lang | The language of the resource, specified as a string. | keyword |
| gti.ioc_stream.attributes.pe_info.resource_details.sha256 | The SHA-256 hash of the resource's content, serving as a unique identifier for the specific resource data. | keyword |
| gti.ioc_stream.attributes.pe_info.resource_details.type | An integer indicating the type of the resource, corresponding to predefined resource types in the Windows API. | keyword |
| gti.ioc_stream.attributes.pe_info.resource_types.rt_group_icon | The count of 'group icon' resources in the PE file. | long |
| gti.ioc_stream.attributes.pe_info.resource_types.rt_icon | The count of 'icon' resources in the PE file. | long |
| gti.ioc_stream.attributes.pe_info.resource_types.rt_manifest | The count of 'manifest' resources in the PE file. | long |
| gti.ioc_stream.attributes.pe_info.resource_types.rt_version | The count of 'version' resources in the PE file. | long |
| gti.ioc_stream.attributes.pe_info.rich_pe_header_hash | A hash value calculated from the 'Rich' header of the PE file. | keyword |
| gti.ioc_stream.attributes.pe_info.sections.chi2 | The chi-squared test value of the section's content, used to detect anomalies or non-standard data distributions. | double |
| gti.ioc_stream.attributes.pe_info.sections.entropy | The entropy value of the section's content, indicating the randomness or complexity of the data. | double |
| gti.ioc_stream.attributes.pe_info.sections.flags | Characteristics of the section, represented as a bitmask. | keyword |
| gti.ioc_stream.attributes.pe_info.sections.md5 | The MD5 hash of the section's content, serving as a unique identifier for the specific data within the section. | keyword |
| gti.ioc_stream.attributes.pe_info.sections.name | The name of the section, typically limited to 8 characters. . | keyword |
| gti.ioc_stream.attributes.pe_info.sections.raw_size | The size of the section as it appears in the PE file on disk. | long |
| gti.ioc_stream.attributes.pe_info.sections.virtual_address | The address of the first byte of the section relative to the image base when the PE file is loaded into memory. | long |
| gti.ioc_stream.attributes.pe_info.sections.virtual_size | The total size of the section when loaded into memory. | long |
| gti.ioc_stream.attributes.pe_info.timestamp | This represents the compilation timestamp of the Portable Executable (PE) file. | date |
| gti.ioc_stream.attributes.popular_threat_classification.popular_threat_category.count | The number of times a specific threat category has been assigned to the file by various security vendors. | long |
| gti.ioc_stream.attributes.popular_threat_classification.popular_threat_category.value | The name of the threat category assigned to the file. | keyword |
| gti.ioc_stream.attributes.popular_threat_classification.popular_threat_name.count | The number of times a specific threat name has been assigned to the file by various security vendors. | long |
| gti.ioc_stream.attributes.popular_threat_classification.popular_threat_name.value | The specific threat name assigned to the file. | keyword |
| gti.ioc_stream.attributes.popular_threat_classification.suggested_threat_label | A recommended label for the threat based on the most commonly assigned categories and names. | keyword |
| gti.ioc_stream.attributes.redirection_chain | A list of URLs involved in redirections leading to the final destination. | keyword |
| gti.ioc_stream.attributes.regional_internet_registry | The name of the Regional Internet Registry (RIR) that assigned the IP address. | keyword |
| gti.ioc_stream.attributes.registrar | The name of the domain registrar responsible for managing the domain's registration. | keyword |
| gti.ioc_stream.attributes.reputation | A numerical score representing the artifact's reputation based on VirusTotal's internal scoring system. | long |
| gti.ioc_stream.attributes.severity_data.num_gav_detections | The number of Google antivirus detections, if available. | long |
| gti.ioc_stream.attributes.sha1 | The SHA-1 hash of the file, serving as a unique identifier for the file's content. | keyword |
| gti.ioc_stream.attributes.sha256 | The SHA-256 hash of the file, serving as a unique identifier for the file's content. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.Signature | Contains the name of the digital certificate used to sign the file or process. . | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.command_line | Captures command-line arguments from a detected process execution. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.company | Contains the official company name that signed or developed the file, based on metadata. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.creation_time | Represents the creation timestamp of the matched entity. | date |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.current_directory | Shows the working directory from which the detected file or process was executed. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.description | Describes why the Sigma rule was triggered. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.destination_hostname | The hostname of the destination system involved in the event. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.destination_ip | The IP address of the destination system involved in the event. | ip |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.destination_is_ipv6 | A booleanean value indicating whether the destination IP address is an IPv6 address. | boolean |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.destination_port | The network port number on the destination system involved in the event. | long |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.destination_port_name | The name associated with the destination port number, typically representing the service running on that port. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.details | This field typically contains additional information or context about the event that matched the Sigma rule. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.event_id | This field represents the unique identifier for the event within the logging system. | long |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.event_type | This field indicates the type or category of the event. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.file_version | Displays the version number of the file, extracted from its metadata. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.hashes | Contains various cryptographic hashes of the detected file, such as MD5, SHA-1, and SHA-256. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.image | This field typically contains the file path of the executable or script that was involved in the event. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.image_loaded | Refers to a DLL or executable file that was loaded into memory during process execution. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.initiated | This field indicates the timestamp or status of when the event was initiated. | boolean |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.integrity_level | Describes the security level assigned to the detected process by Windows. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.logon_guid | A globally unique identifier (GUID) assigned to a specific user logon session in Windows. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.original_file_name | Represents the original name of the file as specified in its metadata. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.param1 | Represents an extracted parameter from the event logs, process execution, or command-line arguments that triggered the Sigma rule. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.parentImage | The full path of the parent process that created or executed the detected process. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.parent_command_line | Captures the command line arguments of the parent process that executed the detected file. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.parent_process_guid | A globally unique identifier (GUID) assigned to the parent process of the detected activity. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.process_guid | This field represents the globally unique identifier (GUID) assigned to the process involved in the event. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.process_id | This field represents the unique identifier assigned by the operating system to the process involved in the event. . | long |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.product | Identifies the software product that the detected file belongs to, as extracted from its metadata. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.protocol | This field indicates the network protocol used in the event, such as TCP, UDP, or ICMP. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.query_name | Represents the type or name of the query executed as part of a suspicious detection. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.query_results | Represents the output or result data from an executed query. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.query_status | Represents the status or result of a query performed as part of Sigma rule detection. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.rule_name | This field contains the name of the Sigma rule that matched the event. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.signature_status | Indicates whether a file or process has a valid digital signature. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.signed | Indicates whether the file or process is digitally signed. | boolean |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.source_hostname | This field specifies the hostname of the source system involved in the event. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.source_ip | This field specifies the IP address of the source system involved in the event. | ip |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.source_is_ipv6 | This field is a boolean value indicating whether the source IP address is an IPv6 address. | boolean |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.source_port | This field indicates the network port number on the source system involved in the event. | long |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.source_port_name | This field provides the name associated with the source port number, typically representing the service running on that port . | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.target_file_name | Represents the filename or full file path that triggered the Sigma rule match. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.target_object | This field specifies the object targeted in the event, such as a file path, registry key, or other system resource. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.terminal_session_id | Indicates the session number assigned to the process by the Windows Terminal Services. | long |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.user | This field identifies the user account associated with the event. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.match_context.utc_time | This field records the date and time when the event occurred in Coordinated Universal Time. | date |
| gti.ioc_stream.attributes.sigma_analysis_results.rule_author | This field specifies the author of the Sigma rule, including their name and, optionally, contact information such as a Twitter handle or email address. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.rule_description | This field provides a brief explanation of what the rule is detecting, offering insight into its purpose and the conditions under which it will trigger. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.rule_id | This field contains a unique identifier for the Sigma rule, typically a randomly generated UUID (version 4), ensuring global uniqueness across all Sigma rules. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.rule_level | This field indicates the severity level of the rule, which can be "low," "medium," "high," or "critical," reflecting the potential impact of the detected activity. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.rule_source | This field specifies the origin or source of the rule, such as the ruleset or repository from which the rule was obtained. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_results.rule_title | This field provides a concise title summarizing the rule's purpose, offering a quick reference to what the rule is designed to detect. | keyword |
| gti.ioc_stream.attributes.sigma_analysis_stats.critical | Indicates the number of Sigma rules with a "critical" severity level that matched the file's behavior or logs. | long |
| gti.ioc_stream.attributes.sigma_analysis_stats.high | Indicates the number of Sigma rules with a "high" severity level that matched the file's behavior or logs. | long |
| gti.ioc_stream.attributes.sigma_analysis_stats.low | Indicates the number of Sigma rules with a "low" severity level that matched the file's behavior or logs. | long |
| gti.ioc_stream.attributes.sigma_analysis_stats.medium | Indicates the number of Sigma rules with a "medium" severity level that matched the file's behavior or logs. | long |
| gti.ioc_stream.attributes.signature_info.copyright | Contains the copyright notice associated with the file. | keyword |
| gti.ioc_stream.attributes.signature_info.description | Provides a brief description of the file's purpose or functionality. | keyword |
| gti.ioc_stream.attributes.signature_info.product | Denotes the name of the product with which the file is associated. | keyword |
| gti.ioc_stream.attributes.size | Specifies the size of the file in bytes. | long |
| gti.ioc_stream.attributes.ssdeep | Contains the SSDEEP hash of the file, which is a context-triggered piecewise hash used to identify similar files. | keyword |
| gti.ioc_stream.attributes.tags | List of representative attributes or labels associated with the artifact, providing quick insights into its characteristics or behaviors. | keyword |
| gti.ioc_stream.attributes.threat_severity.last_analysis_date | The timestamp indicating when the threat severity was last assessed. | date |
| gti.ioc_stream.attributes.threat_severity.level_description | Description summarizing the factors contributing to the assigned threat severity level. | keyword |
| gti.ioc_stream.attributes.threat_severity.threat_severity_data.belongs_to_bad_collection | Boolean indicating if the artifact is part of a known malicious collection. | boolean |
| gti.ioc_stream.attributes.threat_severity.threat_severity_data.belongs_to_threat_actor | Boolean indicating if the artifact is associated with a known threat actor. | boolean |
| gti.ioc_stream.attributes.threat_severity.threat_severity_data.domain_rank | The ranking of the domain based on its global popularity and usage, which can be used as a trust indicator. | long |
| gti.ioc_stream.attributes.threat_severity.threat_severity_data.has_bad_communicating_files_high | Boolean flag indicating whether the domain or IP has been observed communicating with artifact that have a high confidence of being malicious. | boolean |
| gti.ioc_stream.attributes.threat_severity.threat_severity_data.has_bad_communicating_files_medium | Boolean flag indicating whether the domain or IP has been observed communicating with artifact that have a medium confidence of being malicious. | boolean |
| gti.ioc_stream.attributes.threat_severity.threat_severity_level | The assigned threat severity level. | keyword |
| gti.ioc_stream.attributes.threat_severity.version | The version number of the threat severity assessment model used. | keyword |
| gti.ioc_stream.attributes.threat_severity_data.has_references | Boolean indicating if there are external references or reports related to the file. | boolean |
| gti.ioc_stream.attributes.threat_severity_data.has_vulnerabilities | Boolean indicating if the file is associated with known vulnerabilities (CVEs). | boolean |
| gti.ioc_stream.attributes.threat_severity_data.num_av_detections | The number of antivirus engines that detected the file as malicious during analysis. | long |
| gti.ioc_stream.attributes.threat_severity_data.num_detections | The number of detections associated with the domain/IP, representing how many security vendors flagged it as malicious. | long |
| gti.ioc_stream.attributes.times_submitted | The number of times the artifact has been submitted to VirusTotal for analysis. | long |
| gti.ioc_stream.attributes.title | The title of the analyzed entity (typically applicable to URLs and web pages). | keyword |
| gti.ioc_stream.attributes.tld | The top-level domain (TLD) of the analyzed domain or URL. | keyword |
| gti.ioc_stream.attributes.tlsh | The TLSH (Trend Micro Locality Sensitive Hash) of the file, used to identify similar files based on content. | keyword |
| gti.ioc_stream.attributes.total_votes.harmless | The number of votes from the community indicating the artifact is harmless. | long |
| gti.ioc_stream.attributes.total_votes.malicious | The number of votes from the community indicating the artifact is malicious. | long |
| gti.ioc_stream.attributes.trid.file_type | Specifies the file type identified by the TRiD tool, which uses a database of definitions to determine the file's type based on its binary signatures. | keyword |
| gti.ioc_stream.attributes.trid.probability | Indicates the confidence level (as a percentage) that the identified file type is correct. | double |
| gti.ioc_stream.attributes.type_description | Provides a human-readable description of the file's type, offering a general understanding of its format or purpose. | keyword |
| gti.ioc_stream.attributes.type_extension | Specifies the standard file extension associated with the file, indicating its expected format or usage. | keyword |
| gti.ioc_stream.attributes.type_tags | A list of broader tags related to the specific file type, providing additional context about its characteristics or associated platforms. | keyword |
| gti.ioc_stream.attributes.type_unsupported | Number of engines that do not support the file type. | long |
| gti.ioc_stream.attributes.unique_sources | Indicates the number of distinct sources that have submitted the file to VirusTotal. | long |
| gti.ioc_stream.attributes.url.full | The full URL of the analyzed entity. | keyword |
| gti.ioc_stream.attributes.whois_date | The timestamp of the last WHOIS record update for the domain. | date |
| gti.ioc_stream.context_attributes.hunting_info | Provides additional information for notifications originating from hunting activities. | keyword |
| gti.ioc_stream.context_attributes.notification_date | Timestamp (UTC) when the notification was generated. | date |
| gti.ioc_stream.context_attributes.notification_id | Unique identifier for the notification. | long |
| gti.ioc_stream.context_attributes.origin | Specifies the origin of the notification, such as "hunting" for Livehunt or Retrohunt matches. | keyword |
| gti.ioc_stream.context_attributes.sources.id | Identifier of the source object that triggered the notification. | keyword |
| gti.ioc_stream.context_attributes.sources.label | Label describing the source (if available). | keyword |
| gti.ioc_stream.context_attributes.sources.type | Type of the source object, e.g., "hunting_ruleset" or "collection". | keyword |
| gti.ioc_stream.domain.id | A unique identifier assigned to the specific domain in the stream. | keyword |
| gti.ioc_stream.id | A unique identifier assigned to the specific object in the stream. | keyword |
| gti.ioc_stream.type | Specifies the type of the object being reported in the stream. | keyword |
| gti.ioc_stream.url.id | A unique identifier assigned to the specific url in the stream. | keyword |
| gti.ioc_stream.vhash | Represents the VirusTotal hash, a hash-based signature uniquely identifying files with similar or identical content. | keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |

