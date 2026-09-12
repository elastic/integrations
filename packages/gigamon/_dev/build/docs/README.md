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
2. In Fabric Manager, create a Monitoring Session and add an Application Metadata Intelligence (AMI) application. Configure CEF export. The completed topology will be `AMI → Tunnel`.
3. Add a tunnel to the monitoring session, select **UDP** as the tunnel type, and enter the following details:

   * **Alias**: Enter a unique name for the tunnel.
   * **Description**: Optionally enter a description of the tunnel.
   * **Admin State**: Set to **Enabled**.
   * **MTU**: Set the MTU appropriate for your network.
   * **Auto Assign Destination Address**: Set to **Disabled** to enter the Elastic Agent host IP address manually.
   * **Destination Address**: Enter the reachable IP address of the Elastic Agent host.
   * **Source L4 Port**: Enter the UDP source port for the exported traffic.
   * **Destination L4 Port**: Enter the UDP port configured for the CEF/UDP input on Elastic Agent.

4. Save the tunnel, connect the AMI application's CEF output to it, and deploy the monitoring session. Ensure the destination UDP port is accessible from the exporting node.

## Logs Reference

### ami

This is the `ami` dataset.

#### Example

{{event "ami"}}

{{fields "ami"}}