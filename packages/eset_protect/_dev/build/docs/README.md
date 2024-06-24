# ESET PROTECT

ESET PROTECT enables you to manage ESET products on workstations and servers in a networked environment with up to 50,000 devices from one central location. Using the ESET PROTECT Web Console, you can deploy ESET solutions, manage tasks, enforce security policies, monitor system status, and quickly respond to problems or threats on remote computers.

## Data streams

The ESET PROTECT integration collects three types of logs: Detection, Device Task and Event.

**[Detection](https://help.eset.com/protect_cloud/en-US/admin_ct.html?threats.html)** is used to retrieve detections via the [ESET Connect - Incident Management](https://eu.business-account.iam.eset.systems/swagger/?urls.primaryName=Incident%20Management).

**[Device Task](https://help.eset.com/protect_cloud/en-US/admin_ct.html?admin_ct.html)** is used to retrieve device tasks via the [ESET Connect - Automation](https://eu.business-account.iam.eset.systems/swagger/?urls.primaryName=Automation).

**Event** is used to retrieve Detection, Firewall, HIPS, Audit, and ESET Inspect logs using the [Syslog Server](https://help.eset.com/protect_cloud/en-US/events-exported-to-json-format.html?admin_server_settings_export_to_syslog.html).

## Requirements

Elastic Agent must be installed. For more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

This module has been tested against the **ESET PROTECT (version: 5.0.9.1)**.

## Setup

### To collect data from ESET Connect, follow the below steps:

1. [Create API User Account](https://help.eset.com/eset_connect/en-US/use_api_with_swagger.html?create_api_user_account.html)
2. Retrieve the username and password generated during the creation of an API user account.
3. Retrieve the region from the ESET Web Console URL.

### To collect data from ESET PROTECT via Syslog, follow the below steps:

1. Follow the steps to [configure syslog server](https://help.eset.com/protect_cloud/en-US/admin_server_settings_export_to_syslog.html?admin_server_settings_syslog.html).
   - Set the format of the payload to **JSON**.
   - Set the format of the envelope to **Syslog**.
   - Set the minimal log level to **Information** to collect all data.
   - Select all checkboxes to collect logs for all event types.
   - Enter the **IP Address** or **FQDN** of the Elastic Agent that is running the integration in the Destination IP field.

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations
2. In "Search for integrations" search bar, type ESET PROTECT
3. Click on the "ESET PROTECT" integration from the search results.
4. Click on the "Add ESET PROTECT" button to add the integration.
5. Configure all required integration parameters, including username, password, and region, to enable data collection from the ESET Connect REST API. For syslog data collection, provide parameters such as listen address, listen port, and SSL settings.
6. Save the integration.

## Logs Reference

### Detection

This is the `Detection` dataset.

#### Example

{{event "detection"}}

{{fields "detection"}}

### Device Task

This is the `Device Task` dataset.

#### Example

{{event "device_task"}}

{{fields "device_task"}}

### Event

This is the `Event` dataset.

#### Example

{{event "event"}}

{{fields "event"}}
