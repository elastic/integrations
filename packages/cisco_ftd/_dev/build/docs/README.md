# Cisco FTD Integration for Elastic

## Overview

The Cisco Firepower Threat Defense (FTD) integration for Elastic collects logs from Cisco FTD devices, enabling comprehensive monitoring, threat detection, and security analysis within the Elastic Stack. This integration parses syslog messages from Cisco FTD, providing real-time visibility into network traffic, security events, and system activity. By centralizing these logs, organizations can enhance their security posture, streamline incident response, and gain deep insights into their network's operations.

### Compatibility

This integration is compatible with Cisco FTD devices that support syslog export. It requires Elastic Stack version 8.11.0 or higher.

### How it works

The integration works by receiving syslog data sent from a Cisco FTD device. Elastic Agent can be configured to listen for these logs on a specific TCP or UDP port, or to read them directly from a log file. Once received, the agent processes and parses the logs before sending them to Elasticsearch.

## What data does this integration collect?

The Cisco FTD integration collects logs containing detailed information about:
*   **Connection Events**: Firewall traffic, network address translation (NAT), and connection summaries.
*   **Security Events**: Intrusion detection and prevention (IPS/IDS) alerts, file and malware protection events, and security intelligence data.
*   **System Events**: Device health, system status, and configuration changes.

### Supported use cases

- **Real-time Threat Detection**: Use Elastic SIEM to identify and respond to threats like malware, intrusions, and policy violations.
- **Network Traffic Analysis**: Visualize and analyze network traffic patterns to identify anomalies, troubleshoot connectivity issues, and optimize performance.
- **Security Auditing and Compliance**: Maintain a searchable archive of all firewall activity to support compliance requirements and forensic investigations.
- **Operational Monitoring**: Track the health and status of your FTD devices to ensure they are functioning correctly.

## What do I need to use this integration?

Elastic Agent must be installed on a host that is reachable by your Cisco FTD device over the network. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog or log file receiver and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

## How do I deploy this integration?

### Onboard / configure

#### 1. Configure Cisco FTD to send Syslog Data

You must configure your Cisco FTD device to forward syslog messages to the Elastic Agent. The specific steps may vary depending on whether you are using Firepower Device Manager (FDM) or Firepower Management Center (FMC).

1.  **Define the Elastic Agent as a Syslog Server**:
    *   In your FDM or FMC interface, navigate to the syslog configuration section (e.g., **Objects > Syslog Servers** or **Device > System Settings > Logging**).
    *   Add a new syslog server, providing the IP address and port of the machine where the Elastic Agent is running.
    *   Ensure the protocol (TCP or UDP) matches the input you configure in the integration.

2.  **Configure Logging Rules**:
    *   Create or edit a logging rule to send specific event classes to the newly configured syslog server.
    *   It is recommended to send all relevant message IDs to ensure comprehensive data collection.

3.  **Deploy Changes**:
    *   Save and deploy your configuration changes to the FTD device.

For detailed, step-by-step instructions, refer to the official Cisco documentation, such as [Configure Logging on FTD](https://www.cisco.com/c/en/us/td/docs/security/firepower/70/fdm/fptd-fdm-config-guide-700/fptd-fdm-logging.html).

#### 2. Add the Cisco FTD Integration in Elastic

1.  In Kibana, navigate to **Management > Integrations**.
2.  In the search bar, enter **Cisco FTD**.
3.  Click the integration to see more details and then click **Add integration**.
4.  Configure the integration settings. You must select the input method that matches your Cisco FTD configuration (TCP, UDP, or log file).
    *   **For TCP/UDP**: Specify the `host` and `port` where the Elastic Agent should listen for syslog messages. This must match the destination you configured on your FTD device.
    *   **For Log File**: Provide the file `paths` that the agent should monitor.
5.  Click **Save and continue** to add the integration policy to an Elastic Agent.

### Validation

To validate that the integration is working, navigate to the **Discover** tab in Kibana. Filter for the `cisco_ftd.log` dataset (`data_stream.dataset : "cisco_ftd.log"`) and verify that logs from your FTD device are being ingested. You can also check the pre-built dashboards for this integration by searching for "Cisco FTD" in the **Dashboards** section.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Handling `security` fields

A field named `cisco.ftd.security` contains a variable number of sub-fields, which is mapped as a [`flattened` datatype](https://www.elastic.co/guide/en/elasticsearch/reference/current/flattened.html). This mapping limits certain operations, such as aggregations, on its sub-fields.

To enable aggregations on common security-related fields, the integration automatically moves a known set of fields from `cisco.ftd.security` to a new field, `cisco.ftd.security_event`. If you need to perform aggregations on additional fields within `cisco.ftd.security`, you can create a custom ingest pipeline to move them.

To create this custom pipeline:
1.  In Kibana, navigate to **Stack Management > Ingest Pipelines**.
2.  Click **Create Pipeline > New Pipeline**.
3.  Set the `Name` to `logs-cisco_ftd.log@custom`.
4.  Add a **Rename** processor:
    *   Set `Field` to the source field, e.g., `cisco.ftd.security.threat_name`.
    *   Set `Target field` to the destination, e.g., `cisco.ftd.security_event.threat_name`.
5.  Add more processors as needed and save the pipeline. This `@custom` pipeline will be automatically applied to all incoming Cisco FTD logs.

## Reference

### log

The `log` data stream collects logs from Cisco Firepower Threat Defense (FTD) devices.

#### log fields

{{ fields "log" }}

#### log sample event

{{ event "log" }}


### Inputs used
{{ inputDocs }}
