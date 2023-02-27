# JumpCloud

The JumpCloud integration allows you to monitor events related to the JumpCloud Directory as a Service via the Directory Insights API.

You can find out more about JumpCloud and JumpCloud Directory Insights [here](https://jumpcloud.com/platform/directory-insights)

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

![Example of Add JumpCloud Integration](./img/sample-add-integration.png)

## Events

The JumpCloud events dataset provides events from JumpCloud Directory Insights events that have been received.

All JumpCloud Directory Insights events are available in the `jumpcloud.events` field group.

{{fields "events"}}

{{event "events"}}
