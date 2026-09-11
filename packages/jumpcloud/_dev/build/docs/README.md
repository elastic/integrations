# JumpCloud

The JumpCloud integration allows you to monitor events related to the JumpCloud Directory as a Service via the Directory Insights API.

You can find out more about JumpCloud and JumpCloud Directory Insights [here](https://jumpcloud.com/platform/directory-insights)

## Agentless Enabled Integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).
Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

## Data streams

A single data stream named "jumpcloud.events" is used by this integration.

## Requirements

An Elastic Stack with an Elastic Agent is a fundamental requirement.

An established JumpCloud tenancy with active users is the the other requirement. Basic Directory Insights API access is available to all subscription levels.

NOTE: The lowest level of subscription currently has retention limits, with access to Directory Insights events for the last 15 days at most. Other subscriptions levels provide 90 days or longer historical event access.

A JumpCloud API key is required, the JumpCloud documentation describing how to create one is [here](https://support.jumpcloud.com/s/article/jumpcloud-apis1)

This JumpCloud Directory Insights API is documented [here](https://docs.jumpcloud.com/api/insights/directory/1.0/index.html#section/Overview)

## Configuration

### JumpCloud API Key

Ensure you have created a JumpCloud admin API key that you have access to, refer to the link above which provides instructions how to create one.

### Enabling the integration in Elastic

1. In Kibana go to **Management > Integrations**
2. In "Search for integrations" search bar type **JumpCloud**
3. Click on "JumpCloud" integration from the search results.
4. Click on **Add JumpCloud** button to add the JumpCloud integration.
5. Configure the integration as appropriate
6. Assign the integration to a new Elastic Agent host, or an existing Elastic Agent host

![Example of Add JumpCloud Integration](../img/sample-add-integration.png)

## Supported services

The integration collects events from [JumpCloud's Directory Insights API](https://docs.jumpcloud.com/api/insights/directory/1.0/index.html). You can control which event categories are collected using the **services** setting. The default value is `all`, which collects events from every service.

The supported service values are:

| Service | Description |
|---|---|
| `all` | Events from all services. |
| `access_management` | Access management activity. |
| `aigw` | AI gateway activity. |
| `alert` | Alert service events. |
| `asset_management` | Asset management activity. |
| `di_events` | Generic Directory Insights events. |
| `directory` | Admin Portal and User Portal activity, including admin changes and authentications. |
| `genai` | Generative AI activity. |
| `ldap` | User authentications to LDAP, including LDAP Bind and Search events. |
| `mdm` | MDM command results. |
| `notifications` | Notification activity. |
| `object_storage` | Object storage activity. |
| `password_manager` | JumpCloud password manager activity. |
| `radius` | User authentications to RADIUS, used for Wi-Fi and VPNs. |
| `reports` | Report activity. |
| `software` | Application changes on macOS, Windows, and Linux devices. |
| `sso` | User authentications to SAML applications. |
| `systems` | User authentications to macOS, Windows, and Linux systems, including agent-related events. |

## Events

The JumpCloud events dataset provides events from JumpCloud Directory Insights events that have been received.

All JumpCloud Directory Insights events are available in the `jumpcloud.events` field group.

{{fields "events"}}

{{event "events"}}
