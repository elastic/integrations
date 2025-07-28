# ESET PROTECT

ESET PROTECT enables you to manage ESET products on workstations and servers in a networked environment with up to 50,000 devices from one central location. Using the ESET PROTECT Web Console, you can deploy ESET solutions, manage tasks, enforce security policies, monitor system status, and quickly respond to problems or threats on remote computers.

## Data streams

The ESET PROTECT integration collects three types of logs: Detection, Device Task and Event.

**[Detection](https://help.eset.com/protect_cloud/en-US/admin_ct.html?threats.html)** is used to retrieve detections via the [ESET Connect - Incident Management](https://eu.business-account.iam.eset.systems/swagger/?urls.primaryName=Incident%20Management).

**[Device Task](https://help.eset.com/protect_cloud/en-US/admin_ct.html?admin_ct.html)** is used to retrieve device tasks via the [ESET Connect - Automation](https://eu.business-account.iam.eset.systems/swagger/?urls.primaryName=Automation).

**Event** is used to retrieve Detection, Firewall, HIPS, Audit, and ESET Inspect logs using the [Syslog Server](https://help.eset.com/protect_cloud/en-US/events-exported-to-json-format.html?admin_server_settings_export_to_syslog.html). ESET notifications are also retrieved but in plain text.

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

This module has been tested against the **ESET PROTECT (version: 5.0.9.1)**.

## Setup

### Collect data from ESET Connect

1. [Create API User Account](https://help.eset.com/eset_connect/en-US/use_api_with_swagger.html?create_api_user_account.html)
2. Retrieve the username and password generated during the creation of an API user account.
3. Retrieve the region from the ESET Web Console URL.

### Collect data from ESET PROTECT via Syslog

Follow these steps to [configure syslog server](https://help.eset.com/protect_cloud/en-US/admin_server_settings_export_to_syslog.html?admin_server_settings_syslog.html):

1. Set the format of the payload to **JSON** (Hint: ESET Notifications are sent as plain text, regardless of the selection made https://help.eset.com/protect_admin/12.0/en-US/events-exported-to-json-format.html).
2. Set the format of the envelope to **Syslog**.
3. Set the minimal log level to **Information** to collect all data.
4. Select all checkboxes to collect logs for all event types.
5. Enter the **IP Address** or **FQDN** of the Elastic Agent that is running the integration in the Destination IP field.

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search bar, type **ESET PROTECT**.
3. Select the **ESET PROTECT** integration and add it.
4. Configure all required integration parameters, including username, password, and region, to enable data collection from the ESET Connect REST API. For syslog data collection, provide parameters such as listen address, listen port, and SSL settings.
5. Save the integration.

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
