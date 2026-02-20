# Imperva device log integration

This integration is for Imperva device logs. It includes the
datasets for receiving logs over syslog or read from a file:
- `securesphere` dataset: supports Imperva SecureSphere logs.

## Data streams

The Imperva integration collects one type of data: securesphere.

**Securesphere** consists of alerts, violations, and system events. See more details about [alerts, violations, and events](https://docs.imperva.com/bundle/v14.7-web-application-firewall-user-guide/page/1024.htm)

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

The minimum **kibana.version** required is **8.10.1**.

## Setup

### Collect data from Imperva

1. The gateway and management server (MX) should have the relevant connectivity for sending logs using the Syslog server.

2. To send all security violations from the gateway to Elastic:

- Create a custom action set:

  - From a 'security violation–all', type and add the gateway security system log > gateway log security event to system log (syslog) using the CEF standard.
  - Configure the relevant name and parameters for the action set.

- Assign a followed action to a security - > policy rule.

3. To send all security alerts (aggregated violations) from the gateway to Elastic:

- Create a custom action set:

  - From an 'any event type', type and add the server system log > log security event to system log (syslog) using the CEF standard.
  - Configure the relevant name and parameters for the action set.

- Assign a followed action to a security - > policy rule.

4. To send all system events from the gateway to Elastic:

- Create a custom action set:

   - From an 'any event type', type and add the server system log > log system event to system log (syslog) using the CEF standard.
   - Configure the relevant name and parameters for the action set.

- Create system events policy.
- Assign a followed action to a system event policy.

For more information on working with action sets and followed actions, check the Imperva [documentation](https://docs.imperva.com/bundle/v15.0-waf-management-server-manager-user-guide/page/Working_with_Action_Sets_and_Followed_Actions.htm).

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search bar, type **Imperva**.
3. Select the **Imperva** integration and add it.
4. Enable the data collection mode from the following: Filestream, TCP, or UDP.
5. Add all the required configuration parameters, such as paths for the filestream or listen address and listen port for the TCP and UDP.
6. Save the integration.

## Logs Reference

### SecureSphere

This is the `Securesphere` dataset.

#### Example

{{event "securesphere"}}

{{fields "securesphere"}}