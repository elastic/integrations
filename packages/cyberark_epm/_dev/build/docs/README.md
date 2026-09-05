# CyberArk EPM

[CyberArk Endpoint Privilege Manager (EPM)](https://www.cyberark.com/products/endpoint-privilege-manager/) enforces least privilege and enables organizations to block and contain attacks on endpoint computers, reducing the risk of information being stolen or encrypted and held for ransom. A combination of privilege security, application control and credential theft prevention reduces the risk of malware infection.

The CyberArk EPM integration collects events (raw and aggregated), policy audit events (raw and aggregated), and admin audit logs using the REST API.

## Elastic Managed enabled integration

Elastic Managed integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Elastic Managed integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Elastic Managed integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).
Elastic Managed deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

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

The integration supports two authentication methods against the CyberArk EPM REST API. Complete the CyberArk-side setup for the method you intend to use.

### Option 1: EPM authentication

This method uses the native EPM logon API with an EPM username and password. It is the default and remains supported for tenants that are not connected to the CyberArk Identity Security Platform Shared Services (ISPSS).

1. Navigate to **Administration > Account Management** and create a user. While creating the user, check the **Allow to manage Sets** option and provide **ViewOnlySetAdmin** for all the required sets.
2. Log in with the newly created user and navigate to **Administration > Account Configuration**. 
3. Update the **Timeout for inactive session** parameter, which is a prerequisite for creating an integration in Elastic.

NOTE: Set a high value for the **Timeout for inactive session** parameter to minimize multiple authentication calls.

### Option 2: CyberArk Identity authentication

This method uses the OAuth2 client credentials flow with a CyberArk Identity service user. Use it when your EPM tenant is connected to ISPSS. For the full procedure, refer to [Set up API authentication for EPM REST APIs using Identity](https://docs.cyberark.com/epm/latest/en/content/webservices/authenticate-with-identity-administration.htm).

1. In Identity Administration, create a service user with **Is service user** and **Is OAuth confidential client** enabled. Note its login name, for example `svc_elastic@cyberark.cloud.1234`, and its password. These are used as `[Identity] Client ID` and `[Identity] Client Secret`.
2. Add the service user as a member of an EPM role that grants the EPM API permissions required for the data streams you want to collect.
3. In Identity Administration, go to **Apps & Widgets > Web Apps**, click **Add Web Apps**, and add the **CyberArk EPM API Client** app. Configure the required fields under the **Settings** tab and note the Application ID, which is used as `[Identity] Application ID`.
4. On the **Tokens** tab of the web app, define the token expiration period. On the **Permissions** tab, add the service user.
5. Note your Identity ID: click your user name, select **About**, and copy the **ID** shown under **Identity**, for example `ACF4874`. This is used as `[Identity] Identity ID`.
6. Note your EPM server name, which is the subdomain of your EPM console URL. For example, if the console URL is `https://na101.epm.cyberark.com/management-options`, then `[Identity] EPM Server URL` is `https://na101.epm.cyberark.com`.

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search bar, type **CyberArk EPM**.
3. Select the **CyberArk EPM** integration and add it.
4. Select the **Authentication Method** and fill in the parameters prefixed with the matching label. Parameters prefixed with the other label can be left empty.
    - **EPM**: `[EPM] URL`, `[EPM] Username`, `[EPM] Password` and `[EPM] Session Timeout`.
    - **CyberArk Identity**: `[Identity] EPM Server URL`, `[Identity] Identity ID`, `[Identity] Application ID`, `[Identity] Client ID` and `[Identity] Client Secret`.
5. Add the remaining configuration parameters, including the Interval and Initial Interval, to enable data collection.
6. Save the integration.

**Note**:
  - The default `[EPM] URL` is `https://login.epm.cyberark.com`, but this may vary depending on your region. Please refer to the [Documentation](https://docs.cyberark.com/epm/latest/en/content/webservices/webservicesintro.htm#EPMdispatcherservername) to find the correct URL for your region. This URL is the EPM dispatcher server and is only used with the **EPM** authentication method; the **CyberArk Identity** method uses `[Identity] EPM Server URL` instead.
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
