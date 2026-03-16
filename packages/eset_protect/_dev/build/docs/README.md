# ESET PROTECT

ESET PROTECT enables you to manage ESET products on workstations and servers in a networked environment with up to 50,000 devices from one central location. Using the ESET PROTECT Web Console, you can deploy ESET solutions, manage tasks, enforce security policies, monitor system status, and quickly respond to problems or threats on remote computers.

## Data streams

The ESET PROTECT integration collects three types of logs: Detection, Device Task and Event.

**[Detection](https://help.eset.com/protect_cloud/en-US/admin_ct.html?threats.html)** is used to retrieve detections via the **Incident Management - List detections** ([v1](https://help.eset.com/eset_connect/en-US/incident_management_v1_detections_get.html) & [v2](https://help.eset.com/eset_connect/en-US/incident_management_v2_detections_get.html) endpoints).

**[Device Task](https://help.eset.com/protect_cloud/en-US/admin_ct.html?admin_ct.html)** is used to retrieve device tasks via the [Automation - List tasks](https://help.eset.com/eset_connect/en-US/automation_v1_device_tasks_get.html) endpoint.

**Event** is used to retrieve Detection, Firewall, HIPS, Audit, and ESET Inspect logs using the [Syslog Server](https://help.eset.com/protect_cloud/en-US/admin_server_settings_export_to_syslog.html). ESET notifications are also retrieved but in plain text.

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

## Setup

### Collect data from ESET Connect

1. [Create API User Account](https://help.eset.com/eset_connect/en-US/create_api_user_account.html)
2. Retrieve the username and password generated during the creation of an API user account.
3. Retrieve the region from the ESET Web Console URL.

**NOTE**: Detection logs can be collected using the v2 endpoint only after your API user has signed in to your ESET Cloud Office Security instance at least once; this ensures the account is recognized. Note that the v2 endpoint is not supported in the Japanese region.

### Collect data from ESET PROTECT via Syslog

Follow these steps to [configure syslog server](https://help.eset.com/protect_cloud/en-US/admin_server_settings_syslog.html):

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
