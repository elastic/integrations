# Cisco Meraki Metrics Integration

This integration periodically fetches metrics from [Cisco Meraki](https://meraki.cisco.com/) networks. It fetches a wide range of metrics including device details and status, network performance measurements, and switch port information. The integration also collects metrics about wireless channel use and uplink performance.

These metrics help you understand how well your Meraki network is working and make it easier to monitor and manage your network setup.

## Compatibility

The integration uses the [Meraki Dashboard RESTFul APIs](https://github.com/meraki/dashboard-api-go/) library to collect metrics from Cisco Meraki networks.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Configuration

You need the following information from `Cisco Meraki` to configure this integration in Elastic:

- API Key
- Organization IDs
- API Base URL (optional)

You can find more information about the required settings for this integration in the [Meraki Dashboard API documentation](https://documentation.meraki.com/General_Administration/Other_Topics/Cisco_Meraki_Dashboard_API).

### Enabling the integration in Elastic

1. In Kibana go to **Management > Integrations**
2. In "Search for integrations" search bar type **Meraki**
3. Click on "Cisco Meraki metrics" integration from the search results.
4. Click on **Add Cisco Meraki metrics Integration** button to add the integration.

## Metrics

### Device Health

The `device_health` dataset provides metrics related to the health and status of Meraki devices. All Cisco Meraki specific fields are available in the `meraki` field group.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "device_health"}}

{{event "device_health"}}
