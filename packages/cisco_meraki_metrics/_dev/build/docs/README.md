# Cisco Meraki Metrics Integration

This integration periodically fetches metrics from [Cisco Meraki](https://meraki.cisco.com/) networks. It collects device details and status, network performance measurements, switch port information, wireless channel utilization, and uplink performance.

These metrics help you assess Meraki network health and simplify ongoing monitoring and management.

## Compatibility

The integration uses the [Meraki Dashboard RESTful APIs](https://github.com/meraki/dashboard-api-go/) library to collect metrics from Cisco Meraki networks.

## Requirements

You need Elasticsearch to store and search your data and Kibana to visualize and manage it. You can use our hosted Elasticsearch Service on Elastic Cloud (recommended) or self-manage the Elastic Stack on your own hardware.

## Configuration

To configure this integration in Elastic, you need the following information from Cisco Meraki:

- API Key
- Organization IDs
- API Base URL (optional)

For more details on these settings, refer to the [Meraki Dashboard API documentation](https://documentation.meraki.com/General_Administration/Other_Topics/Cisco_Meraki_Dashboard_API).

### Enabling the integration in Elastic

1. In Kibana, navigate to **Management > Integrations**
2. In the "Search for integrations" search bar, type **Meraki**
3. Click "Cisco Meraki Metrics" in the results
4. Click **Add Cisco Meraki Metrics Integration** to add the integration

## Metrics

### Device Health

The `device_health` dataset provides metrics related to the health and status of Meraki devices. All Cisco Meraki specific fields are available in the `meraki` field group.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "device_health"}}

{{event "device_health"}}
