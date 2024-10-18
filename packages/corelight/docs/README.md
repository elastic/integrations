# Corelight

[Corelight](https://corelight.com/) provides network detection and response (NDR) solutions that enhance visibility, threat detection, and incident response by leveraging open-source technologies like Zeek. Its platform integrates with existing security tools to deliver high-fidelity network data, helping organizations detect and respond to threats more effectively across both on-premises and cloud environments​.

This integration includes only the Corelight dashboards for Security Posture, Remote Activity Insights, Name Resolution Insights, and Secure Channel Insights.

## Prerequisites:

**Add ECS Mappings**: Start by adding the ECS (Elastic Common Schema) mappings from the [Corelight GitHub repository](https://github.com/corelight). You can find the required templates here: [Corelight ECS Templates](https://github.com/corelight/ecs-templates). These mappings will ensure that Corelight data is correctly formatted and aligned with Elastic's schema.

**Send Data from Corelight to Elastic**: Once the ECS mappings are in place, configure Corelight to send data directly to your Elastic environment.

**Note**: Use the default index (logs-*) name instead of a custom index.

## Setup

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations.
2. In "Search for integrations" search bar, type Corelight.
3. Click on the "Corelight" integration from the search results.
4. Go to Settings.
5. Click on the "Install Corelight assets".
6. Go to Assets to get list of dashboards.
