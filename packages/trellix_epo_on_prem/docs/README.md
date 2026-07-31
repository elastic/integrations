# Trellix ePO On-Prem Integration for Elastic

## Overview

[Trellix ePolicy Orchestrator (ePO) On-Prem](https://www.trellix.com/products/epolicy-orchestrator/) is a centralized security management platform for managing endpoint policies, products, systems, and security events across an organization. It provides visibility into endpoint security operations and threat activity across hybrid endpoint deployments.

The Trellix ePO On-Prem integration for Elastic collects threat event records using the **Web API** through the Elastic Agent CEL input and visualizes them in Kibana.

### Compatibility

The Trellix ePO On-Prem integration is compatible with **Trellix ePO On-Prem 5.10.0 and above** with Web API support enabled.

### How it works

This integration uses the Elastic Agent CEL input to poll the Trellix ePO Web API at configurable intervals. It queries the `EPExtendedEvent` target and retrieves fields from both `EPOEvents` and `EPExtendedEvent`, so only threat events with matching extended details are collected.

The integration implements pagination using `EPOEvents.ReceivedUTC` as an inclusive cursor. Repeated records at the cursor boundary receive a stable document ID from the ingest pipeline to prevent duplicate documents. Each threat event is mapped to Elastic Common Schema (ECS) and ingested as an individual event for processing by the built-in ingest pipeline.

## What data does this integration collect?

The Trellix ePO On-Prem integration collects the following type of data:

| Data stream | Description | Source |
|---|---|---|
| `threat_event` | Trellix ePO threat events and extended details, including endpoint detections, rules, actions, severity, network activity, files, processes, registry paths, and related entities. | `/remote/core.executeQuery` API |

### Supported use cases

Integrating Trellix ePO with Elastic provides centralized visibility into endpoint threat activity across managed systems. It supports threat investigation, detection and response, endpoint activity analysis, intrusion prevention monitoring, firewall traffic analysis, and correlation across hosts, users, IP addresses, files, processes, hashes, and rules in Kibana.

## What do I need to use this integration?

### From Trellix ePO On-Prem

To collect data through the Web API, you need the following:

1. **Trellix ePO server**: Trellix ePO On-Prem 5.10.0 or above with Web API support enabled.
2. **User account**: A Trellix ePO user account with:
   - Query permissions for the `EPOEvents` and `EPExtendedEvent` tables.
   - Sufficient role permissions to execute queries through the Web API.
3. **API credentials**: Username and password for HTTP Basic authentication.
4. **Server URL**: Base URL of the Trellix ePO server, for example `https://epo.example.com:8443`.
5. **Network access**: The Elastic Agent must have outbound HTTPS access to the Trellix ePO server.

For more information about configuring Web API access, refer to the [Trellix ePO Web API Scripting Reference Guide](https://docs.trellix.com/bundle/trellix-epolicy-orchestrator-on-prem-web-api-scripting-reference-guide/page/UUID-8df5c181-2be6-8b3e-f562-e5b292a385ca.html).

## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agentless-based installation

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

### Configure

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **Trellix ePO On-Prem**.
3. Select the **Trellix ePO On-Prem** integration from the search results.
4. Select **Add Trellix ePO On-Prem** to add the integration.
5. Enable and configure **Collect Trellix ePO threat event logs**.

   - Set **Trellix ePO URL** to the base URL of the Trellix ePO server, for example `https://epo.example.com:8443`.
   - Set **Username** and **Password** for an account with permission to query threat events.
   - Set **Initial Interval** to the lookback period used for the first API request. The default is `168h`.
   - Set **Interval** to the polling frequency. The default is `5m`.
   - Set **Page Size** to the number of threat events retrieved per API request. The default is `500`.
   - Optionally adjust **HTTP Client Timeout**, proxy, and SSL settings.

6. Select **Save and continue** to save the integration.

## Troubleshooting

- **No data collected**: Verify that the Trellix ePO URL is correct, the credentials are valid, and the Elastic Agent has network access to the ePO server. Confirm that the user account can query `EPOEvents` and `EPExtendedEvent`.
- **Authentication failures**: Ensure the username and password are correct and that the user account is active and has sufficient Web API permissions.
- **Missing expected threat events**: The query uses `EPExtendedEvent` as its target and collects only events with matching extended details.
- **Incomplete or missing fields**: Confirm that the ePO account can access all threat event fields requested by the CEL input.
- **Pagination issues**: If collection does not advance, verify that `EPOEvents.ReceivedUTC` is present in every returned event and that records are ordered by this field.
- **Collection timeouts**: Increase **HTTP Client Timeout** or reduce **Page Size**.
- **SSL certificate errors**: If the ePO server uses a private certificate authority, configure the issuing CA certificate in the integration's SSL settings.
- **Missing historical events**: Increase **Initial Interval** so that the first request covers the required lookback period.

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Validation

#### Dashboard populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **Trellix ePO On-Prem**, and verify that the dashboard is listed.
3. Open the **[Logs Trellix ePO On-Prem] Threat Event Overview** dashboard and verify that threat event data is populated.

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Vendor documentation links

- [Trellix ePO Web API Scripting Reference Guide](https://docs.trellix.com/bundle/trellix-epolicy-orchestrator-on-prem-web-api-scripting-reference-guide/page/UUID-8df5c181-2be6-8b3e-f562-e5b292a385ca.html)
- [Trellix ePO Web API Query Language](https://docs.trellix.com/bundle/trellix-epolicy-orchestrator-on-prem-web-api-scripting-reference-guide/page/UUID-cd01321d-b19b-5095-c79b-eabc7c0726bb.html)
- [Trellix ePO 5.10.0 Product Guide](https://docs.trellix.com/bundle/trellix-epolicy-orchestrator-on-prem-5.10.0-product-guide/page/UUID-3946078c-6e32-df76-6296-216ee05a2176.html)

### Threat event

The `threat_event` data stream provides Trellix ePO On-Prem threat event records and matching extended event details collected from the Web API.

#### Threat event fields

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
| observer.vendor | Vendor name of the observer that generated the event. | constant_keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.AMCoreContentVersion | AM Core Content Version value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.APIName | API Name value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.AccessRequested | Access Requested value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.AnalyzerContentCreationDate | Analyzer Content Creation Date value recorded in the extended threat-event details. | date |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.AnalyzerGTIQuery | Analyzer GTI Query value recorded in the extended threat-event details. | boolean |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.AnalyzerRegInfo | Analyzer Reg Info value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.AnalyzerTechnologyVersion | Analyzer Technology Version value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.AttackVectorType | Attack Vector Type value recorded in the extended threat-event details. | long |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.BladeName | Blade Name value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.Cleanable | Cleanable value recorded in the extended threat-event details. | boolean |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.Direction | Direction value recorded in the extended threat-event details. | long |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.DurationBeforeDetection | Duration Before Detection value recorded in the extended threat-event details. | long |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.EventAutoID | Event Auto ID value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.FirstActionStatus | First Action Status value recorded in the extended threat-event details. | boolean |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.FirstAttemptedAction | First Attempted Action value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.Location | Location value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.SecondActionStatus | Second Action Status value recorded in the extended threat-event details. | boolean |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.SecondAttemptedAction | Second Attempted Action value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.SourceDescription | Source Description value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.SourceDevicePID | Source Device PID value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.SourceDeviceSerialNumber | Source Device Serial Number value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.SourceDeviceVID | Source Device VID value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.SourceHash | Source Hash value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.SourceShareName | Source Share Name value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.SourceURLRatingCode | Source URL Rating Code value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.SourceURLWebCategory | Source URL Web Category value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.TargetCreateTime | Target Create Time value recorded in the extended threat-event details. | date |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.TargetDescription | Target Description value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.TargetDeviceDisplayName | Target Device Display Name value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.TargetDevicePID | Target Device PID value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.TargetDeviceSerialNumber | Target Device Serial Number value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.TargetDeviceVID | Target Device VID value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.TargetModifyTime | Target Modify Time value recorded in the extended threat-event details. | date |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.TargetParentProcessHash | Target Parent Process Hash value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.TargetParentProcessName | Target Parent Process Name value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.TargetParentProcessSigned | Target Parent Process Signed value recorded in the extended threat-event details. | boolean |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.TargetParentProcessSigner | Target Parent Process Signer value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.TargetShareName | Target Share Name value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.TargetURL | Target URL value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.TaskName | Task Name value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.ThreatDetectedOnCreation | Threat Detected On Creation value recorded in the extended threat-event details. | boolean |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.ThreatImpact | Threat Impact value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPExtendedEvent.Topic | Topic value recorded in the extended threat-event details. | keyword |
| trellix_epo_on_prem.threat_event.EPOEvents.AgentGUID | Agent GUID value recorded in the ePO threat event. | keyword |
| trellix_epo_on_prem.threat_event.EPOEvents.Analyzer | Analyzer value recorded in the ePO threat event. | keyword |
| trellix_epo_on_prem.threat_event.EPOEvents.AnalyzerDATVersion | Analyzer DAT Version value recorded in the ePO threat event. | keyword |
| trellix_epo_on_prem.threat_event.EPOEvents.AnalyzerEngineVersion | Analyzer Engine Version value recorded in the ePO threat event. | keyword |
| trellix_epo_on_prem.threat_event.EPOEvents.DetectedUTC | Detection time recorded in the ePO threat event. | date |
| trellix_epo_on_prem.threat_event.EPOEvents.EventTimeLocal | Event Time Local value recorded in the ePO threat event. | date |
| trellix_epo_on_prem.threat_event.EPOEvents.ServerID | Server ID value recorded in the ePO threat event. | keyword |
| trellix_epo_on_prem.threat_event.EPOEvents.SourceHostName | Source Host Name value recorded in the ePO threat event. | keyword |
| trellix_epo_on_prem.threat_event.EPOEvents.SourceURL | Source URL value recorded in the ePO threat event. | keyword |
| trellix_epo_on_prem.threat_event.EPOEvents.TargetProcessName | Target Process Name value recorded in the ePO threat event. | keyword |
| trellix_epo_on_prem.threat_event.EPOEvents.TenantId | Tenant ID value recorded in the ePO threat event. | keyword |
| trellix_epo_on_prem.threat_event.EPOEvents.ThreatActionTaken | Threat Action Taken value recorded in the ePO threat event. | keyword |
| trellix_epo_on_prem.threat_event.EPOEvents.ThreatCategory | Trellix threat-category identifier used to classify the event variant. | keyword |
| trellix_epo_on_prem.threat_event.EPOEvents.ThreatHandled | Threat Handled value recorded in the ePO threat event. | boolean |
| trellix_epo_on_prem.threat_event.EPOEvents.ThreatSeverity | Threat Severity value recorded in the ePO threat event. | long |
| trellix_epo_on_prem.threat_event.EPOEvents.ThreatType | Trellix threat-type identifier used as the primary event variant discriminator. | keyword |


### Example event

#### Threat event

An example event for `threat_event` looks as following:

```json
{
    "@timestamp": "2026-01-15T10:00:05.000Z",
    "agent": {
        "ephemeral_id": "e685331e-378f-41c0-8e50-840088515b5d",
        "id": "cc9a6076-2ba3-4636-93a6-14dc9970eb98",
        "name": "elastic-agent-77673",
        "type": "filebeat",
        "version": "8.19.0"
    },
    "data_stream": {
        "dataset": "trellix_epo_on_prem.threat_event",
        "namespace": "46494",
        "type": "logs"
    },
    "destination": {
        "ip": [
            "203.0.113.50",
            "0:0:0:0:0:FFFF:CB00:7132"
        ],
        "mac": "00-11-22-33-44-77",
        "port": 80
    },
    "device": {
        "product": {
            "name": "Example Virtual SCSI Disk Device"
        }
    },
    "ecs": {
        "version": "9.4.0"
    },
    "elastic_agent": {
        "id": "cc9a6076-2ba3-4636-93a6-14dc9970eb98",
        "snapshot": false,
        "version": "8.19.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "intrusion_detection"
        ],
        "code": "18063",
        "created": "2025-01-01T00:00:00.000Z",
        "dataset": "trellix_epo_on_prem.threat_event",
        "id": "11111111-1111-4111-8111-111111111106",
        "ingested": "2026-07-31T13:33:38Z",
        "kind": "alert",
        "original": "{\"EPExtendedEvent.AMCoreContentVersion\":\"1.0.0\",\"EPExtendedEvent.APIName\":\"SyntheticApiCall\",\"EPExtendedEvent.AccessRequested\":\"IDS_AAC_REQ_READ\",\"EPExtendedEvent.AnalyzerContentCreationDate\":\"2026-01-01T00:00:00+00:00\",\"EPExtendedEvent.AnalyzerContentVersion\":\"10.7.0.14078\",\"EPExtendedEvent.AnalyzerGTIQuery\":true,\"EPExtendedEvent.AnalyzerRegInfo\":\"Synthetic analyzer registry context\",\"EPExtendedEvent.AnalyzerRuleID\":\"complete-rule-001\",\"EPExtendedEvent.AnalyzerRuleName\":\"Synthetic complete coverage rule\",\"EPExtendedEvent.AnalyzerTechnologyVersion\":\"10.7.20.14030\",\"EPExtendedEvent.AttackVectorType\":3,\"EPExtendedEvent.BladeName\":\"IDS_BLADE_NAME_FW\",\"EPExtendedEvent.Cleanable\":true,\"EPExtendedEvent.Direction\":1,\"EPExtendedEvent.DurationBeforeDetection\":1200,\"EPExtendedEvent.EventAutoID\":6,\"EPExtendedEvent.FirstActionStatus\":true,\"EPExtendedEvent.FirstAttemptedAction\":\"blocked\",\"EPExtendedEvent.Location\":\"C:\\\\Example\\\\sample.exe\",\"EPExtendedEvent.NaturalLangDescription\":\"Synthetic complete field coverage system-test event\",\"EPExtendedEvent.SecondActionStatus\":false,\"EPExtendedEvent.SecondAttemptedAction\":\"quarantined\",\"EPExtendedEvent.SourceAccessTime\":\"2026-01-15T09:00:00+00:00\",\"EPExtendedEvent.SourceCreateTime\":\"2025-01-01T00:00:00+00:00\",\"EPExtendedEvent.SourceDescription\":\"EXAMPLE AGENT MODULE\",\"EPExtendedEvent.SourceDeviceDisplayName\":\"Example Virtual SCSI Disk Device\",\"EPExtendedEvent.SourceDevicePID\":\"PCI\\\\VEN_8086\\u0026DEV_1234\\u0026SUBSYS_00000000\\u0026REV_01\\\\4\\u0026abc\\u00260\\u002600A8\",\"EPExtendedEvent.SourceDeviceSerialNumber\":\"EXAMPLE-SOURCE-SERIAL-0001\",\"EPExtendedEvent.SourceDeviceVID\":\"PCI\\\\VEN_8086\\u0026DEV_1234\\u0026SUBSYS_00000000\\u0026REV_01\\\\4\\u0026abc\\u00260\\u002600A8\",\"EPExtendedEvent.SourceFilePath\":\"C:\\\\Program Files\\\\ExampleApp\",\"EPExtendedEvent.SourceFileSize\":524288,\"EPExtendedEvent.SourceHash\":\"DEADBEEF0123456789ABCDEFF0123456\",\"EPExtendedEvent.SourceModifyTime\":\"2025-01-01T00:00:00+00:00\",\"EPExtendedEvent.SourceParentProcessHash\":\"FEEDFACE0123456789ABCDEFF0123456\",\"EPExtendedEvent.SourceParentProcessName\":\"example-parent.exe\",\"EPExtendedEvent.SourceParentProcessSigned\":true,\"EPExtendedEvent.SourceParentProcessSigner\":\"C=US, O=Example Corp, CN=Example Publisher\",\"EPExtendedEvent.SourcePort\":52000,\"EPExtendedEvent.SourceProcessHash\":\"F6789012345678901234ABCDEF012345\",\"EPExtendedEvent.SourceProcessSigned\":true,\"EPExtendedEvent.SourceProcessSigner\":\"C=US, O=Example Corp, CN=Example Windows\",\"EPExtendedEvent.SourceShareName\":\"\\\\\\\\source-host.example.com\\\\share\",\"EPExtendedEvent.SourceSigned\":true,\"EPExtendedEvent.SourceSigner\":\"C=US, O=Example Corp, CN=Example Windows\",\"EPExtendedEvent.SourceURLRatingCode\":\"trusted\",\"EPExtendedEvent.SourceURLWebCategory\":\"business\",\"EPExtendedEvent.TargetAccessTime\":\"2026-01-15T09:57:00+00:00\",\"EPExtendedEvent.TargetCreateTime\":\"2025-04-01T08:00:00+00:00\",\"EPExtendedEvent.TargetDescription\":\"Synthetic target description\",\"EPExtendedEvent.TargetDeviceDisplayName\":\"Example Target Device\",\"EPExtendedEvent.TargetDevicePID\":\"DEV_5678\",\"EPExtendedEvent.TargetDeviceSerialNumber\":\"EXAMPLE-TARGET-SERIAL-0001\",\"EPExtendedEvent.TargetDeviceVID\":\"VEN_1234\",\"EPExtendedEvent.TargetFileSize\":102400,\"EPExtendedEvent.TargetHash\":\"6789012345678901234ABCDEF0123456\",\"EPExtendedEvent.TargetModifyTime\":\"2025-04-01T08:00:00+00:00\",\"EPExtendedEvent.TargetName\":\"example-document.pdf\",\"EPExtendedEvent.TargetParentProcessHash\":\"B2C3D4E5F6789012345678901234ABCD\",\"EPExtendedEvent.TargetParentProcessName\":\"parent-app.exe\",\"EPExtendedEvent.TargetParentProcessSigned\":true,\"EPExtendedEvent.TargetParentProcessSigner\":\"C=US, O=Example Corp, CN=Example Code Signing\",\"EPExtendedEvent.TargetPath\":\"C:\\\\Users\\\\Public\",\"EPExtendedEvent.TargetShareName\":\"\\\\\\\\target-host.example.com\\\\share\",\"EPExtendedEvent.TargetSigned\":false,\"EPExtendedEvent.TargetSigner\":\"C=US, O=Example Corp, CN=Example Windows Publisher\",\"EPExtendedEvent.TargetURL\":\"https://target.example.com/resource\",\"EPExtendedEvent.TaskName\":\"Synthetic Scan Task\",\"EPExtendedEvent.ThreatDetectedOnCreation\":true,\"EPExtendedEvent.ThreatImpact\":\"low\",\"EPExtendedEvent.Topic\":\"Synthetic threat topic\",\"EPOEvents.AgentGUID\":\"77777777-8888-4999-8AAA-BBBBBBBBBB07\",\"EPOEvents.Analyzer\":\"ENDP_TEST_1000\",\"EPOEvents.AnalyzerDATVersion\":\"9999.0\",\"EPOEvents.AnalyzerDetectionMethod\":\"Access Protection\",\"EPOEvents.AnalyzerEngineVersion\":\"1.2.3\",\"EPOEvents.AnalyzerHostName\":\"lab-host-complete.example.com\",\"EPOEvents.AnalyzerIPV4\":1177773066,\"EPOEvents.AnalyzerIPV6\":\"0:0:0:0:0:FFFF:C633:640A\",\"EPOEvents.AnalyzerMAC\":\"00aabbccddee\",\"EPOEvents.AnalyzerName\":\"Trellix Endpoint Security\",\"EPOEvents.AnalyzerVersion\":\"10.7.20.14066\",\"EPOEvents.AutoGUID\":\"11111111-1111-4111-8111-111111111106\",\"EPOEvents.AutoID\":6,\"EPOEvents.DetectedUTC\":\"2026-01-15T10:00:05+00:00\",\"EPOEvents.EventTimeLocal\":\"2026-01-15T10:00:05+00:00\",\"EPOEvents.ReceivedUTC\":\"2026-01-15T10:00:05+00:00\",\"EPOEvents.ServerID\":\"epo-server-01.example.com\",\"EPOEvents.SourceHostName\":\"source-host.example.com\",\"EPOEvents.SourceIPV4\":1177773066,\"EPOEvents.SourceIPV6\":\"0:0:0:0:0:FFFF:C633:640A\",\"EPOEvents.SourceMAC\":\"010203040506\",\"EPOEvents.SourceProcessName\":\"example-source-process.exe\",\"EPOEvents.SourceURL\":\"https://source.example.com/path\",\"EPOEvents.SourceUserName\":\"EXAMPLE\\\\source_user\",\"EPOEvents.TargetFileName\":\"C:\\\\Users\\\\Public\\\\example-document.pdf\",\"EPOEvents.TargetHostName\":\"target-host.example.com\",\"EPOEvents.TargetIPV4\":1258320178,\"EPOEvents.TargetIPV6\":\"0:0:0:0:0:FFFF:CB00:7132\",\"EPOEvents.TargetMAC\":\"001122334477\",\"EPOEvents.TargetPort\":80,\"EPOEvents.TargetProcessName\":\"example-target-process.exe\",\"EPOEvents.TargetProtocol\":\"TCP\",\"EPOEvents.TargetUserName\":\"EXAMPLE\\\\target_user\",\"EPOEvents.TenantId\":1,\"EPOEvents.ThreatActionTaken\":\"blocked\",\"EPOEvents.ThreatCategory\":\"hip.process\",\"EPOEvents.ThreatEventID\":18063,\"EPOEvents.ThreatHandled\":true,\"EPOEvents.ThreatName\":\"Synthetic complete system-test event\",\"EPOEvents.ThreatSeverity\":2,\"EPOEvents.ThreatType\":\"IDS_THREAT_TYPE_VALUE_SP\"}",
        "provider": "Access Protection",
        "reason": "Synthetic complete system-test event",
        "sequence": 6,
        "type": [
            "info"
        ]
    },
    "file": {
        "accessed": "2026-01-15T09:00:00.000Z",
        "code_signature": {
            "exists": true
        },
        "created": "2025-01-01T00:00:00.000Z",
        "hash": {
            "md5": "6789012345678901234ABCDEF0123456"
        },
        "mtime": "2025-01-01T00:00:00.000Z",
        "path": "C:\\Program Files\\ExampleApp",
        "size": 524288
    },
    "host": {
        "hostname": "lab-host-complete.example.com",
        "ip": [
            "198.51.100.10",
            "0:0:0:0:0:FFFF:C633:640A"
        ],
        "mac": [
            "00-AA-BB-CC-DD-EE"
        ],
        "target": {
            "hostname": "target-host.example.com"
        }
    },
    "input": {
        "type": "cel"
    },
    "message": "Synthetic complete field coverage system-test event",
    "network": {
        "transport": "tcp"
    },
    "observer": {
        "hostname": "lab-host-complete.example.com",
        "ip": [
            "198.51.100.10",
            "0:0:0:0:0:FFFF:C633:640A"
        ],
        "mac": [
            "00-AA-BB-CC-DD-EE"
        ],
        "product": "Trellix Endpoint Security",
        "version": "10.7.20.14066"
    },
    "process": {
        "code_signature": {
            "exists": true,
            "subject_name": "C=US, O=Example Corp, CN=Example Windows"
        },
        "hash": {
            "md5": "F6789012345678901234ABCDEF012345"
        },
        "name": "example-source-process.exe",
        "parent": {
            "code_signature": {
                "exists": true,
                "subject_name": "C=US, O=Example Corp, CN=Example Publisher"
            },
            "hash": {
                "md5": "FEEDFACE0123456789ABCDEFF0123456"
            },
            "name": "example-parent.exe"
        }
    },
    "related": {
        "hash": [
            "F6789012345678901234ABCDEF012345",
            "6789012345678901234ABCDEF0123456",
            "B2C3D4E5F6789012345678901234ABCD",
            "DEADBEEF0123456789ABCDEFF0123456",
            "FEEDFACE0123456789ABCDEFF0123456"
        ],
        "hosts": [
            "lab-host-complete.example.com",
            "epo-server-01.example.com"
        ],
        "ip": [
            "198.51.100.10",
            "0:0:0:0:0:FFFF:C633:640A",
            "203.0.113.50",
            "0:0:0:0:0:FFFF:CB00:7132"
        ],
        "user": [
            "EXAMPLE\\source_user",
            "EXAMPLE\\target_user"
        ]
    },
    "rule": {
        "id": "complete-rule-001",
        "name": "Synthetic complete coverage rule",
        "version": "10.7.0.14078"
    },
    "source": {
        "ip": [
            "198.51.100.10",
            "0:0:0:0:0:FFFF:C633:640A"
        ],
        "mac": "01-02-03-04-05-06",
        "port": 52000
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "trellix_epo_on_prem-threat_event"
    ],
    "threat": {
        "indicator": {
            "file": {
                "accessed": "2026-01-15T09:57:00.000Z",
                "code_signature": {
                    "exists": false,
                    "subject_name": "C=US, O=Example Corp, CN=Example Windows Publisher"
                },
                "directory": "C:\\Users\\Public",
                "name": "example-document.pdf",
                "path": "C:\\Users\\Public\\example-document.pdf",
                "size": 102400
            }
        }
    },
    "trellix_epo_on_prem": {
        "threat_event": {
            "EPExtendedEvent": {
                "AMCoreContentVersion": "1.0.0",
                "APIName": "SyntheticApiCall",
                "AccessRequested": "IDS_AAC_REQ_READ",
                "AnalyzerContentCreationDate": "2026-01-01T00:00:00.000Z",
                "AnalyzerGTIQuery": true,
                "AnalyzerRegInfo": "Synthetic analyzer registry context",
                "AnalyzerTechnologyVersion": "10.7.20.14030",
                "AttackVectorType": 3,
                "BladeName": "IDS_BLADE_NAME_FW",
                "Cleanable": true,
                "Direction": 1,
                "DurationBeforeDetection": 1200,
                "EventAutoID": "6",
                "FirstActionStatus": true,
                "FirstAttemptedAction": "blocked",
                "Location": "C:\\Example\\sample.exe",
                "SecondActionStatus": false,
                "SecondAttemptedAction": "quarantined",
                "SourceDescription": "EXAMPLE AGENT MODULE",
                "SourceDevicePID": "PCI\\VEN_8086&DEV_1234&SUBSYS_00000000&REV_01\\4&abc&0&00A8",
                "SourceDeviceSerialNumber": "EXAMPLE-SOURCE-SERIAL-0001",
                "SourceDeviceVID": "PCI\\VEN_8086&DEV_1234&SUBSYS_00000000&REV_01\\4&abc&0&00A8",
                "SourceHash": "DEADBEEF0123456789ABCDEFF0123456",
                "SourceShareName": "\\\\source-host.example.com\\share",
                "SourceURLRatingCode": "trusted",
                "SourceURLWebCategory": "business",
                "TargetCreateTime": "2025-04-01T08:00:00.000Z",
                "TargetDescription": "Synthetic target description",
                "TargetDeviceDisplayName": "Example Target Device",
                "TargetDevicePID": "DEV_5678",
                "TargetDeviceSerialNumber": "EXAMPLE-TARGET-SERIAL-0001",
                "TargetDeviceVID": "VEN_1234",
                "TargetModifyTime": "2025-04-01T08:00:00.000Z",
                "TargetParentProcessHash": "B2C3D4E5F6789012345678901234ABCD",
                "TargetParentProcessName": "parent-app.exe",
                "TargetParentProcessSigned": true,
                "TargetParentProcessSigner": "C=US, O=Example Corp, CN=Example Code Signing",
                "TargetShareName": "\\\\target-host.example.com\\share",
                "TargetURL": "https://target.example.com/resource",
                "TaskName": "Synthetic Scan Task",
                "ThreatDetectedOnCreation": true,
                "ThreatImpact": "low",
                "Topic": "Synthetic threat topic"
            },
            "EPOEvents": {
                "AgentGUID": "77777777-8888-4999-8AAA-BBBBBBBBBB07",
                "Analyzer": "ENDP_TEST_1000",
                "AnalyzerDATVersion": "9999.0",
                "AnalyzerEngineVersion": "1.2.3",
                "DetectedUTC": "2026-01-15T10:00:05.000Z",
                "EventTimeLocal": "2026-01-15T10:00:05.000Z",
                "ServerID": "epo-server-01.example.com",
                "SourceHostName": "source-host.example.com",
                "SourceURL": "https://source.example.com/path",
                "TargetProcessName": "example-target-process.exe",
                "TenantId": "1",
                "ThreatActionTaken": "blocked",
                "ThreatCategory": "hip.process",
                "ThreatHandled": true,
                "ThreatSeverity": 2,
                "ThreatType": "IDS_THREAT_TYPE_VALUE_SP"
            }
        }
    },
    "user": {
        "name": "EXAMPLE\\source_user",
        "target": {
            "name": "EXAMPLE\\target_user"
        }
    }
}
```

### Inputs used

These inputs are used in the integration:

- [CEL](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

This integration uses the following API:

- **Threat event**: Collects threat event records through the **Trellix ePO executeQuery API** at `/remote/core.executeQuery`. Records are queried using the `EPExtendedEvent` target, fields are selected from `EPOEvents` and `EPExtendedEvent`, and pagination uses `EPOEvents.ReceivedUTC` as an inclusive cursor.
