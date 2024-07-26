:# Gigamon Integration

Gigamon leverages deep packet inspection (DPI) to extract over 7500+ app related metadata attributes from the raw packets in the network. Gigamon Elastic Integration delivers intelligent security analytics and threat intelligence across the enterprise, and you get a single solution for attack detection, threat visibility, proactive hunting, and threat response.

## Data streams

The Gigamon integration currently provides a single
data stream: `ami`.

## Requirements

- Elastic Agent must be installed.
- You can install only one Elastic Agent per host.

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to
define, configure, and manage your agents in a central location. We recommend
using Fleet management because it makes the management and upgrade of your
agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent
locally on the system where it is installed. You are responsible for managing
and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or
standalone. Docker images for all versions of Elastic Agent are available
from the Elastic Docker registry, and we provide deployment manifests for
running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more
information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

The minimum **kibana.version** required is **8.12.0**.


### Setup

## Gigamon setup

To export data to Gigamon Elastic Integration.

1. From Fabric Manager, Deploy an AMX node with traffic acquisition method as "Customer Orchestrated Source".

2. Create an Monitoring Session with (Rep In ----> AMX ---> Rep Out).



To add AMX application:

1. Drag and drop Application Metadata Exporter from APPLICATIONS to the graphical workspace. The Application quick view appears.
2. Enter the Alias for the application. Enter a port number for the Cloud Tool Ingestor Port. Then, click the Add button for Cloud Tool Exports.
3. You can export your Application Metadata Intelligence output to cloud tools. Enter the following details for the Cloud tool export in the Application quick view:

Alias             Enter the alias name for the cloud tool export.

Cloud Tool        Select the Cloud tool from the drop-down menu.If it is not available click "others".

Endpoint          Give the URL of the cloud tool instance with the correct port number in which the port is listening.

Headers           Enter the secret header and enable secure keys

Enable Export     Enable the box to export the Application Metadata Intelligence output in JSON format.

Zip               Enable the box to compress the output file.

Interval          The time interval (in seconds) in which the data should be uploaded periodically. The recommended minimum time interval is 10 seconds and the maximum time interval is 30 minutes.

Parallel Writer   Specifies the number of simultaneous JSON exports done.

Export Retries    The number of times the application tries to export the entries to Cloud Tool. The recommended minimum value is 4 and the maximum is 10.

Maximum Entries   The number of JSON entries in a file. The maximum number of allowed entries is 5000 and the minimum is 10, however 1000 is the default value.

Labels             Click Add. Enter the following details:

			o	Enter the Key .
			o	Enter the Value.


4. Click Deploy to deploy the monitoring session. The Select nodes to deploy the Monitoring Session dialog box appears. Select the GigaVUE V Series Node for which you wish to deploy the monitoring session.
5. After selecting the V Series Node, select the interfaces for the REPs deployed in the monitoring session from the drop-down menu. Then, click Deploy.

## Logs Reference

### ami

This is the `ami` dataset.

#### Example

{{event "ami"}}

{{fields "ami"}}

