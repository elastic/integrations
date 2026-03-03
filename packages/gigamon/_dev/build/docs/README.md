# Gigamon Integration

Gigamon leverages deep packet inspection (DPI) to extract over 7500+ app related metadata attributes from the raw packets in the network. Gigamon Elastic Integration delivers intelligent security analytics and threat intelligence across the enterprise, and you get a single solution for attack detection, threat visibility, proactive hunting, and threat response.

## Data streams

The Gigamon Integration collects logs from AMI.

- **Application Metadata Intelligence(AMI)** generates rich contextual information about your applications and protocols which can be used for further analysis.

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

### Setup

To export data to Gigamon Elastic Integration, follow these steps:

1. From Fabric Manager, Deploy an AMX node with traffic acquisition method as "Customer Orchestrated Source".
2. Create an Monitoring Session with (Rep In ----> AMX ---> Rep Out).

To add AMX application, follow these steps:

1. Drag and drop Application Metadata Exporter from APPLICATIONS to the graphical workspace. The Application quick view appears.
2. Enter the Alias for the application. Enter a port number for the Cloud Tool Ingestor Port. Then, click the Add button for Cloud Tool Exports.
3. You can export your Application Metadata Intelligence output to cloud tools. Enter the following details for the Cloud tool export in the Application quick view:

	- **Alias**: Enter the alias name for the cloud tool export.

	- **Cloud Tool**: Select the Cloud tool from the drop-down menu.If it is not available click "others".

	- **Endpoint**: Give the URL of the cloud tool instance with the correct port number in which the port is listening.

	- **Headers**: Enter the secret header and enable secure keys

	- **Enable Export**: Enable the box to export the Application Metadata Intelligence output in JSON format.

	- **Zip**: Enable the box to compress the output file.

	- **Interval**: The time interval (in seconds) in which the data should be uploaded periodically. The recommended minimum time interval is 10 seconds and the maximum time interval is 30 minutes.

	- **Parallel Writer**: Specifies the number of simultaneous JSON exports done.

	- **Export Retries**: The number of times the application tries to export the entries to Cloud Tool. The recommended minimum value is 4 and the maximum is 10.

	- **Maximum Entries**: The number of JSON entries in a file. The maximum number of allowed entries is 5000 and the minimum is 10, however 1000 is the default value.

	- **Labels**: Click Add. Enter the following details:

		- Enter the **Key**.
		- Enter the **Value**.

4. Click Deploy to deploy the monitoring session. The Select nodes to deploy the Monitoring Session dialog box appears. Select the GigaVUE V Series Node for which you wish to deploy the monitoring session.
5. After selecting the V Series Node, select the interfaces for the REPs deployed in the monitoring session from the drop-down menu. Then, click Deploy.

## Logs Reference

### ami

This is the `ami` dataset.

#### Example

{{event "ami"}}

{{fields "ami"}}

