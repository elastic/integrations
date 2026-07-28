# Trellix ePO On-Premises Integration for Elastic

## Overview

[Trellix ePolicy Orchestrator (ePO) On-Premises](https://www.trellix.com/products/epolicy-orchestrator/) is a centralized security management platform for managing endpoint policies, products, systems, and security events across an organization.

This integration collects event records forwarded by Trellix ePO over TCP or UDP syslog. It provides visibility into endpoint security detections, threat prevention activity, web control events, data loss prevention events, product events, user activity, and reputation changes across your Trellix ePO environment.

### How it works

The integration uses the Elastic Agent TCP or UDP input to receive events forwarded by Trellix ePO. For each received event, it:

1. Receives an RFC 5424 syslog message on the configured listen address and port.
2. Extracts the embedded XML payload from the syslog message.
3. Decodes the `EPOEvent` XML object and maps endpoint, network, file, user, registry, and threat details to Elastic Common Schema (ECS).
4. Emits each decoded record as an individual event for ingestion and enrichment by the built-in ingest pipeline.

## What data does this integration collect?

The Trellix ePO On-Premises integration collects the following type of data:

| Data stream | Description |
|---|---|
| `event` | Trellix ePO event-forwarder records, including endpoint security, threat prevention, web control, data loss prevention, product, authentication, and reputation events received over TCP or UDP syslog. |

### Supported use cases

* **Threat detection and investigation**: Monitor malware detections, prevention actions, threat severity, affected endpoints, files, users, and network activity.

* **Endpoint and administrative monitoring**: Analyze endpoint product events, policy-related activity, user actions, authentication events, and reputation changes reported through Trellix ePO.

## What do I need to use this integration?

### From Trellix ePO On-Premises

* **Trellix ePO deployment**: An active Trellix ePO On-Premises server capable of forwarding events over syslog.
* **Event forwarding enabled**: Configure Trellix ePO to forward RFC 5424 syslog messages containing XML `EPOEvent` payloads to the Elastic Agent host and port.
* **Network access**: The Trellix ePO server must be able to reach the Elastic Agent over the configured TCP or UDP port.
* **Elastic Agent**: An Elastic Agent enrolled in Fleet and installed on a host that can receive the forwarded syslog traffic.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to receive the syslog events and ship the data to Elastic, where the events are processed by the integration's ingest pipeline.

### Configure

1. In Kibana, navigate to **Fleet → Integrations** and search for **Trellix ePO On-Premises**.
2. Click **Add Trellix ePO On-Premises**.
3. Enable either the TCP or UDP input.
4. Set the **Listen Address** and **Listen Port** to the address and port that Trellix ePO will use as its syslog destination. The default port is `9514`.
5. For TCP with TLS, configure the certificate and key under **SSL Configuration**.
6. Configure Trellix ePO to forward events to the Elastic Agent host using the same protocol and port.
7. Select **Save and continue** to save the integration.
8. Add the integration to an existing Agent policy or create a new one.
9. Verify that Trellix ePO events are being ingested into Elasticsearch.

### Validation

#### Dashboard populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **Trellix ePO On-Premises**.
3. Open the **[Logs Trellix ePO On-Premises] Event Overview** dashboard.
4. Verify that the visualizations are populated with event data, including event trends, categories, actions, hosts, users, threats, files, and source locations.

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Troubleshooting

* **No data collected**: Verify that Trellix ePO event forwarding is enabled and points to the correct Elastic Agent host, protocol, and port. Confirm that network and firewall rules allow traffic to the configured listener.
* **XML payload is not decoded**: Confirm that forwarded messages contain an XML `EPOEvent` payload and that the complete event is delivered as a single syslog message.

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Reference

### Event

The `event` data stream provides Trellix ePO On-Premises event logs.

#### Event fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |
| trellix_epo_on_prem.event.EPOEvent.APIName | Inferred: API name reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.AccessRequested | Inferred: Access requested reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.ActionID | Inferred: Action id reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.AgentGUID | Inferred: Agent GUID reported in the 'EPOEvent.MachineInfo' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.Analyzer | Inferred: Analyzer reported in the 'EPOEvent.SoftwareInfo.CommonFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.AnalyzerDATVersion | Inferred: Analyzer DAT version reported in the 'EPOEvent.SoftwareInfo.CommonFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.AnalyzerDetectionMethod | Inferred: Analyzer detection method reported in the 'EPOEvent.SoftwareInfo.CommonFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.AnalyzerEngineVersion | Inferred: Analyzer engine version reported in the 'EPOEvent.SoftwareInfo.CommonFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.AnalyzerGTIQuery | Inferred: Analyzer GTI query reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.AnalyzerName | Inferred: Analyzer name reported in the 'EPOEvent.SoftwareInfo.CommonFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.AnalyzerVersion | Inferred: Analyzer version reported in the 'EPOEvent.SoftwareInfo.CommonFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.AttackVectorType | Inferred: Attack vector type reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.BadLinkRatingID | Inferred: Bad link rating id reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.BladeName | Inferred: Blade name reported in the 'EPOEvent.SoftwareInfo.Event.CustomFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.Cleanable | Inferred: Cleanable reported in the 'EPOEvent' source section. | long |
| trellix_epo_on_prem.event.EPOEvent.ContentFuncGroup | Inferred: Content func group reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.ContentName | Inferred: Content name reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.ContentRiskGroup | Inferred: Content risk group reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.Count | Inferred: Count reported in the 'EPOEvent' source section. | long |
| trellix_epo_on_prem.event.EPOEvent.DAT_Version | Inferred: DAT version reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.DetectedUTC | Inferred: Detected UTC reported in the 'EPOEvent.SoftwareInfo.Event.CommonFields' source section. | date |
| trellix_epo_on_prem.event.EPOEvent.DetectionMethod | Inferred: Detection method reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.DownloadRatingID | Inferred: Download rating id reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.DurationBeforeDetection | Inferred: Duration before detection reported in the 'EPOEvent' source section. | long |
| trellix_epo_on_prem.event.EPOEvent.EventType | Inferred: Event type reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.ExploitRatingID | Inferred: Exploit rating id reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.FirstActionStatus | Inferred: First action status reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.FirstAttemptedAction | Inferred: First attempted action reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.Hostname | Inferred: Hostname reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.ListID | Inferred: List id reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.ListType | Inferred: List type reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.MachineInfo.AgentGUID | Inferred: Agent GUID reported in the 'EPOEvent.MachineInfo' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.MachineInfo.TimeZoneBias | Inferred: Time zone bias reported in the 'EPOEvent.MachineInfo' source section. | long |
| trellix_epo_on_prem.event.EPOEvent.ObserverMode | Inferred: Observer mode reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.PhishingRatingID | Inferred: Phishing rating id reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.PopupRatingID | Inferred: Popup rating id reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.Priority | Inferred: Priority reported in the 'EPOEvent' source section. | long |
| trellix_epo_on_prem.event.EPOEvent.ProductFamily | Inferred: Product family reported in the 'EPOEvent.SoftwareInfo' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.Rating | Inferred: Rating reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.ReasonID | Inferred: Reason id reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.ReasonType | Inferred: Reason type reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.RegistryValue | Inferred: Registry value reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SecondActionStatus | Inferred: Second action status reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SecondAttemptedAction | Inferred: Second attempted action reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.ServerID | Inferred: Server id reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SignatureName | Inferred: Signature name reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SiteName | Inferred: Site name reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.CommonFields.Analyzer | Inferred: Analyzer reported in the 'EPOEvent.SoftwareInfo.CommonFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.CommonFields.AnalyzerDATVersion | Inferred: Analyzer DAT version reported in the 'EPOEvent.SoftwareInfo.CommonFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.CommonFields.AnalyzerDetectionMethod | Inferred: Analyzer detection method reported in the 'EPOEvent.SoftwareInfo.CommonFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.CommonFields.AnalyzerEngineVersion | Inferred: Analyzer engine version reported in the 'EPOEvent.SoftwareInfo.CommonFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.CommonFields.AnalyzerName | Inferred: Analyzer name reported in the 'EPOEvent.SoftwareInfo.CommonFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.CommonFields.AnalyzerVersion | Inferred: Analyzer version reported in the 'EPOEvent.SoftwareInfo.CommonFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.Event.CommonFields.DetectedUTC | Inferred: Detected UTC reported in the 'EPOEvent.SoftwareInfo.Event.CommonFields' source section. | date |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.Event.CommonFields.ThreatEventID | Inferred: Threat event id reported in the 'EPOEvent.SoftwareInfo.Event.CommonFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.Event.CommonFields.ThreatHandled | Inferred: Threat handled reported in the 'EPOEvent.SoftwareInfo.Event.CommonFields' source section. | boolean |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.Event.CommonFields.ThreatSeverity | Inferred: Threat severity reported in the 'EPOEvent.SoftwareInfo.Event.CommonFields' source section. | long |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.Event.CommonFields.ThreatType | Inferred: Threat type reported in the 'EPOEvent.SoftwareInfo.Event.CommonFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.Event.CustomFields.AnalyzerContentCreationDate | Inferred: Analyzer content creation date reported in the 'EPOEvent.SoftwareInfo.Event.CustomFields' source section. | date |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.Event.CustomFields.BladeName | Inferred: Blade name reported in the 'EPOEvent.SoftwareInfo.Event.CustomFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.Event.CustomFields.ThreatDetectedOnCreation | Inferred: Threat detected on creation reported in the 'EPOEvent.SoftwareInfo.Event.CustomFields' source section. | boolean |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.Event.CustomFields.target | Inferred: Target reported in the 'EPOEvent.SoftwareInfo.Event.CustomFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.Event.GMTTime | Inferred: GMT time reported in the 'EPOEvent.SoftwareInfo.Event' source section. | date |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.Event.Severity | Inferred: Severity reported in the 'EPOEvent.SoftwareInfo.Event' source section. | long |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.ProductFamily | Inferred: Product family reported in the 'EPOEvent.SoftwareInfo' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.ProductName | Inferred: Product name reported in the 'EPOEvent.SoftwareInfo' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SoftwareInfo.ProductVersion | Inferred: Product version reported in the 'EPOEvent.SoftwareInfo' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SourceFileSize | Inferred: Source file size reported in the 'EPOEvent' source section. | double |
| trellix_epo_on_prem.event.EPOEvent.SourceProcessName | Inferred: Source process name reported in the 'EPOEvent.SoftwareInfo.Event.CommonFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.SpamRatingID | Inferred: Spam rating id reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.Success | Inferred: Success reported in the 'EPOEvent' source section. | long |
| trellix_epo_on_prem.event.EPOEvent.TVDSeverity | Inferred: TVD severity reported in the 'EPOEvent' source section. | long |
| trellix_epo_on_prem.event.EPOEvent.TargetName | Inferred: Target name reported in the 'EPOEvent.SoftwareInfo.Event.CustomFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.TargetPath | Inferred: Target path reported in the 'EPOEvent.SoftwareInfo.Event.CustomFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.TaskName | Inferred: Task name reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.ThreatDetectedOnCreation | Inferred: Threat detected on creation reported in the 'EPOEvent.SoftwareInfo.Event.CustomFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.ThreatHandled | Inferred: Threat handled reported in the 'EPOEvent.SoftwareInfo.Event.CommonFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.ThreatSeverity | Inferred: Threat severity reported in the 'EPOEvent.SoftwareInfo.Event.CommonFields' source section. | long |
| trellix_epo_on_prem.event.EPOEvent.ThreatType | Inferred: Threat type reported in the 'EPOEvent.SoftwareInfo.Event.CommonFields' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.USBSerialNumber | Inferred: USB serial number reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.Vendor | Inferred: Vendor reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.Version | Inferred: Version reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.agentGuid | Inferred: Agent GUID reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.detectionTime | Inferred: Detection time recorded for the file reputation event. | date |
| trellix_epo_on_prem.event.EPOEvent.jtiObjectType | Inferred: JTI object type reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.jtiReputation | Inferred: JTI reputation reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.localReputation | Inferred: Local reputation reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.newReputations.trustLevel | Inferred: Trust level reported in the 'EPOEvent.newReputations' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.oldReputations.trustLevel | Inferred: Trust level reported in the 'EPOEvent.newReputations' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.remediationAction | Inferred: Remediation action reported in the 'EPOEvent' source section. | keyword |
| trellix_epo_on_prem.event.EPOEvent.siem_last_time | Inferred: Siem last time reported in the 'EPOEvent' source section. | date |
| trellix_epo_on_prem.event.EPOEvent.wpRating | Inferred: Wp rating reported in the 'EPOEvent' source section. | keyword |


### Example event

#### Event

An example event for `event` looks as following:

```json
{
    "@timestamp": "2021-05-03T06:27:04.753Z",
    "agent": {
        "ephemeral_id": "65449c36-6eda-4765-add1-3a87cda81043",
        "id": "9f2b2284-996f-428e-8a24-c7be32f5e8ce",
        "name": "elastic-agent-31545",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "trellix_epo_on_prem.event",
        "namespace": "80578",
        "type": "logs"
    },
    "destination": {
        "as": {
            "number": 64501,
            "organization": {
                "name": "Documentation ASN"
            }
        },
        "geo": {
            "city_name": "Amsterdam",
            "continent_name": "Europe",
            "country_iso_code": "NL",
            "country_name": "Netherlands",
            "location": {
                "lat": 52.37404,
                "lon": 4.88969
            },
            "region_iso_code": "NL-NH",
            "region_name": "North Holland"
        },
        "ip": [
            "198.51.100.10",
            "::ffff:198.51.100.10"
        ],
        "mac": "00-00-5E-00-53-24",
        "port": 443
    },
    "ecs": {
        "version": "9.4.0"
    },
    "elastic_agent": {
        "id": "9f2b2284-996f-428e-8a24-c7be32f5e8ce",
        "snapshot": false,
        "version": "8.19.0"
    },
    "event": {
        "action": "ids_alert_act_tak_del",
        "agent_id_status": "verified",
        "category": [
            "intrusion_detection",
            "web",
            "file",
            "malware",
            "host",
            "authentication"
        ],
        "dataset": "trellix_epo_on_prem.event",
        "id": "01234567-ABCD-ABCD-ABCD-ABCD01234567",
        "ingested": "2026-07-27T12:21:07Z",
        "kind": "event",
        "sequence": 17443183,
        "type": [
            "info",
            "start"
        ]
    },
    "file": {
        "hash": {
            "md5": "44d88612fea8a8f36de82e1278abb02f"
        },
        "name": "eicar.com",
        "path": "C:\\Temp",
        "size": 68
    },
    "host": {
        "name": "host-1.example.local"
    },
    "input": {
        "type": "udp"
    },
    "log": {
        "source": {
            "address": "192.168.242.3:44501"
        }
    },
    "message": "Malware Detected",
    "network": {
        "direction": "inbound",
        "transport": "tcp"
    },
    "observer": {
        "ip": [
            "198.51.100.10",
            "::ffff:198.51.100.10"
        ]
    },
    "process": {
        "name": "firefox.exe"
    },
    "registry": {
        "key": "HKLM\\Software\\Test\\Key"
    },
    "related": {
        "hash": [
            "44d88612fea8a8f36de82e1278abb02f"
        ],
        "hosts": [
            "host-1.example.local"
        ],
        "ip": [
            "::ffff:198.51.100.10",
            "198.51.100.10"
        ],
        "user": [
            "EXAMPLE\\alice.johnson"
        ]
    },
    "source": {
        "as": {
            "number": 64501,
            "organization": {
                "name": "Documentation ASN"
            }
        },
        "geo": {
            "city_name": "Amsterdam",
            "continent_name": "Europe",
            "country_iso_code": "NL",
            "country_name": "Netherlands",
            "location": {
                "lat": 52.37404,
                "lon": 4.88969
            },
            "region_iso_code": "NL-NH",
            "region_name": "North Holland"
        },
        "ip": [
            "198.51.100.10",
            "::ffff:198.51.100.10"
        ],
        "mac": "00-00-5E-00-53-23",
        "port": 12345,
        "user": {
            "domain": "EXAMPLE",
            "name": "alice.johnson"
        }
    },
    "tags": [
        "forwarded",
        "trellix_epo_on_prem-event"
    ],
    "trellix_epo_on_prem": {
        "event": {
            "EPOEvent": {
                "APIName": "CreateFile",
                "AccessRequested": "read",
                "AgentGUID": "01234567-ABCD-ABCD-ABCD-ABCD01234567",
                "Analyzer": "ENDP_AM_1120",
                "AnalyzerDetectionMethod": "On-Demand Scan",
                "AnalyzerEngineVersion": "5800.7501",
                "AnalyzerGTIQuery": "0",
                "AnalyzerName": "Trellix EndpointSecurity",
                "AnalyzerVersion": "198.51.100.10",
                "BladeName": "IDS_BLADE_NAME_SPB",
                "Cleanable": 0,
                "DetectedUTC": "2021-05-03T06:26:21.000Z",
                "FirstAttemptedAction": "IDS_ALERT_THACT_ATT_CLE",
                "ProductFamily": "HOSTIPS",
                "RegistryValue": "1",
                "SecondAttemptedAction": "IDS_ALERT_THACT_ATT_DEL",
                "ServerID": "epo-server-1.example.local",
                "SignatureName": "Buffer Overflow Detected",
                "SourceFileSize": 68,
                "SourceProcessName": "On-Demand Scan",
                "TargetName": "eicar.com",
                "TaskName": "Host IPS protection",
                "ThreatDetectedOnCreation": "0",
                "ThreatHandled": "1",
                "ThreatSeverity": 2,
                "ThreatType": "test",
                "Vendor": "Trellix",
                "siem_last_time": "2021-05-03T06:27:04.000Z"
            }
        }
    },
    "user": {
        "target": {
            "domain": "EXAMPLE",
            "name": "alice.johnson"
        }
    }
}
```

### Inputs used

These inputs can be used with this integration:
<details>
<summary>tcp</summary>

## Setup

For more details about the TCP input settings, check the [Filebeat documentation](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-tcp).

### Collecting logs from TCP

To collect logs via TCP, select **Collect logs via TCP** and configure the following parameters:

**Required Settings:**
- Host
- Port

**Common Optional Settings:**
- Max Message Size - Maximum size of incoming messages
- Max Connections - Maximum number of concurrent connections
- Timeout - How long to wait for data before closing idle connections
- Line Delimiter - Character(s) that separate log messages

## SSL/TLS Configuration

To enable encrypted connections, configure the following SSL settings:

**SSL Settings:**
- Enable SSL - Toggle to enable SSL/TLS encryption
- Certificate - Path to the SSL certificate file (`.crt` or `.pem`)
- Certificate Key - Path to the private key file (`.key`)
- Certificate Authorities - Path to CA certificate file for client certificate validation (optional)
- Client Authentication - Require client certificates (`none`, `optional`, or `required`)
- Supported Protocols - TLS versions to support (e.g., `TLSv1.2`, `TLSv1.3`)

**Example SSL Configuration:**
```yaml
ssl.enabled: true
ssl.certificate: "/path/to/server.crt"
ssl.key: "/path/to/server.key"
ssl.certificate_authorities: ["/path/to/ca.crt"]
ssl.client_authentication: "optional"
```
</details>
<details>
<summary>udp</summary>

## Setup

For more details about the UDP input settings, check the [Filebeat documentation](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-udp).

### Collecting logs from UDP

To collect logs via UDP, select **Collect logs via UDP** and configure the following parameters:

**Required Settings:**
- Host
- Port

**Common Optional Settings:**
- Max Message Size - Maximum size of UDP packets to accept (default: 10KB, max: 64KB)
- Read Buffer - UDP socket read buffer size for handling bursts of messages
- Read Timeout - How long to wait for incoming packets before checking for shutdown
</details>

