# Gigamon Integration

Gigamon leverages deep packet inspection (DPI) to extract over 7500+ app related metadata attributes from the raw packets in the network. Gigamon Elastic Integration delivers intelligent security analytics and threat intelligence across the enterprise, and you get a single solution for attack detection, threat visibility, proactive hunting, and threat response.

## Data streams

The Gigamon integration collects logs from Application Metadata Intelligence (AMI), which generates rich contextual information about applications and protocols for further analysis.

The integration supports two collection methods:

- **JSON over HTTP**: Export metadata using Application Metadata Exporter (AMX).
- **CEF over UDP**: Export metadata using Application Metadata Intelligence (AMI) connected to a UDP tunnel targeting Elastic Agent.

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

### Setup

### JSON logs using AMX

To export JSON data to the Gigamon Elastic integration, follow these steps:

1. From Fabric Manager, deploy an AMX node with the traffic acquisition method set to "Customer Orchestrated Source".
2. Create a monitoring session with the following flow: REP In → AMX → REP Out.

To add the AMX application, follow these steps:

1. Drag and drop Application Metadata Exporter from APPLICATIONS to the graphical workspace. The Application quick view appears.
2. Enter the Alias for the application and a port number for the Cloud Tool Ingestor Port. Then, click the Add button for Cloud Tool Exports.
3. Enter the following details for the cloud tool export:

   - **Alias**: Enter the alias name for the cloud tool export.
   - **Cloud Tool**: Select the cloud tool from the drop-down menu. If it is not available, select "others".
   - **Endpoint**: Enter the URL of the Elastic Agent HTTP endpoint, including its listening port.
   - **Headers**: Enter the secret header and enable secure keys.
   - **Enable Export**: Enable this option to export the Application Metadata Intelligence output in JSON format.
   - **Zip**: Enable this option to compress the output file.
   - **Interval**: Specify the upload interval in seconds. The recommended minimum is 10 seconds and the maximum is 30 minutes.
   - **Parallel Writer**: Specify the number of simultaneous JSON exports.
   - **Export Retries**: Specify the number of export attempts. The recommended minimum is 4 and the maximum is 10.
   - **Maximum Entries**: Specify the number of JSON entries in a file. The minimum is 10, the maximum is 5000, and the default is 1000.
   - **Labels**: Click Add and enter the Key and Value.

4. Click Deploy. In the Select nodes to deploy the Monitoring Session dialog, select the GigaVUE V Series Node.
5. Select the interfaces for the REPs deployed in the monitoring session, then click Deploy.

### CEF logs using AMI

To export CEF data to the Gigamon Elastic integration, follow these steps:

1. Enable the CEF/UDP input in the Gigamon integration on Elastic Agent and configure the listening address and UDP port.
2. In Fabric Manager, add an Application Metadata Intelligence (AMI) application to the monitoring session and configure CEF export.
3. Create a UDP tunnel targeting the Elastic Agent host IP and the configured UDP listening port.
4. Connect the AMI application's CEF output to the UDP tunnel and deploy the monitoring session. Ensure the configured UDP port is accessible.

## Logs Reference

### ami

This is the `ami` dataset.

#### Example

{{event "ami"}}

{{fields "ami"}}