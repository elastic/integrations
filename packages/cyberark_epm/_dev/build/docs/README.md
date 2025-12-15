# CyberArk EPM

[CyberArk Endpoint Privilege Manager (EPM)](https://www.cyberark.com/products/endpoint-privilege-manager/) enforces least privilege and enables organizations to block and contain attacks on endpoint computers, reducing the risk of information being stolen or encrypted and held for ransom. A combination of privilege security, application control and credential theft prevention reduces the risk of malware infection.

The CyberArk EPM integration collects events (raw and aggregated), policy audit events (raw and aggregated), and admin audit logs using the REST API.

## Compatibility

This module has been tested against the CyberArk EPM version **24.12.0.4372**.

## Data streams

This integration collects the following logs:

- **[Raw Event](https://docs.cyberark.com/epm/latest/en/content/webservices/getdetailedrawevents.htm)** - This method enables users to retrieve raw events from EPM.
- **[Policy Audit Raw Event](https://docs.cyberark.com/epm/latest/en/content/webservices/getpolicyauditraweventdetails.htm)** - This method enables users to retrieve policy audit raw events from EPM.
- **[Aggregated Event](https://docs.cyberark.com/epm/latest/en/content/webservices/getaggregatedevents.htm)** - This method enables users to retrieve aggregated events from EPM.
- **[Policy Audit Aggregated Event](https://docs.cyberark.com/epm/latest/en/content/webservices/getaggregatedpolicyaudits.htm)** - This method enables users to retrieve aggregated policy audit events from EPM.
- **[Admin Audit](https://docs.cyberark.com/epm/latest/en/content/webservices/getadminauditdata.htm)** - This method enables users to retrieve the full list of actions carried out by EPM administrators in a specific set.

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

## Setup

### Collect data from the CyberArk EPM API

1. Navigate to **Administration > Account Management** and create a user. While creating the user, check the **Allow to manage Sets** option and provide **ViewOnlySetAdmin** for all the required sets.
2. Log in with the newly created user and navigate to **Administration > Account Configuration**. 
3. Update the **Timeout for inactive session** parameter, which is a prerequisite for creating an integration in Elastic.

NOTE: Set a high value for the **Timeout for inactive session** parameter to minimize multiple authentication calls.

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search bar, type **CyberArk EPM**.
3. Select the **CyberArk EPM** integration and add it.
4. Add all the required integration configuration parameters, including the URL, Username, Password, API Version, Session Timeout, Interval, and Initial Interval, to enable data collection.
5. Save the integration.

**Note**:
  - The default URL is `https://login.epm.cyberark.com`, but this may vary depending on your region. Please refer to the [Documentation](https://docs.cyberark.com/epm/latest/en/content/webservices/webservicesintro.htm#EPMdispatcherservername) to find the correct URL for your region.
  - If you encounter an error indicating that the usage limit has been reached, consider lowering the "Resource Rate Limit" parameter in the advanced section. For more details, please refer to the [documentation](https://docs.cyberark.com/epm/latest/en/content/webservices/webservicesintro.htm#APIlimitations).

## Logs reference

### Raw Event

This is the `raw_event` dataset.

#### Example

{{event "raw_event"}}

{{fields "raw_event"}}

### Policy Audit Raw Event

This is the `policyaudit_raw_event` dataset.

#### Example

{{event "policyaudit_raw_event"}}

{{fields "policyaudit_raw_event"}}

### Aggregated Event

This is the `aggregated_event` dataset.

#### Example

{{event "aggregated_event"}}

{{fields "aggregated_event"}}

### Policy Audit Aggregated Event

This is the `policyaudit_aggregated_event` dataset.

#### Example

{{event "policyaudit_aggregated_event"}}

{{fields "policyaudit_aggregated_event"}}

### Admin Audit

This is the `admin_audit` dataset.

#### Example

{{event "admin_audit"}}

{{fields "admin_audit"}}
