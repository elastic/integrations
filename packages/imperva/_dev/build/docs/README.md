# Imperva

This integration is for Imperva device logs. It includes the
datasets for receiving logs over syslog or read from a file:
- `securesphere` dataset: supports Imperva SecureSphere logs.

## Data streams

The Imperva integration collects one type of data: securesphere.

**Securesphere** consists of alerts, violations, and system events. See more details about [alerts, violations, and events](https://docs.imperva.com/bundle/v14.7-web-application-firewall-user-guide/page/1024.htm)

## Requirements

Elastic Agent must be installed. For more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent, and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

The minimum **kibana.version** required is **8.10.1**.

## Setup

### To collect data from Imperva, follow the required steps:

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

For more information on working with action sets and followed actions, refer to the Imperva relevant [documentation]( https://docs.imperva.com/bundle/v15.0-waf-management-server-manager-user-guide/page/Working_with_Action_Sets_and_Followed_Actions.htm).

### Enabling the integration in Elastic:

1. In Kibana, go to Management > Integrations
2. In the "Search for integrations" search bar, type Imperva.
3. Click on the "Imperva" integration from the search results.
4. Click on the "Add Imperva" button to add the integration.
5. Enable the data collection mode from the following: Filestream, TCP, or UDP.
6. Add all the required configuration parameters, such as paths for the filestream or listen address and listen port for the TCP and UDP.

## Logs Reference

### SecureSphere

This is the `Securesphere` dataset.

#### Example

{{event "securesphere"}}

{{fields "securesphere"}}