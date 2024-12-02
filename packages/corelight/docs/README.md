# Corelight

[Corelight](https://corelight.com/) provides network detection and response (NDR) solutions that enhance visibility, threat detection, and incident response by leveraging open-source technologies like Zeek. Its platform integrates with existing security tools to deliver high-fidelity network data, helping organizations detect and respond to threats more effectively across both on-premises and cloud environments​.

This integration includes only the Corelight dashboards mentioned below:
- Security Posture
- Remote Activity Insights
- Name Resolution Insights
- Secure Channel Insights

## Prerequisites:

**Add ECS Mappings**: Start by adding the ECS (Elastic Common Schema) mappings from the [Corelight GitHub organization](https://github.com/corelight). You can find the required templates here: [Corelight ECS Templates](https://github.com/corelight/ecs-templates). The script within the repository installs the necessary components, including index settings, index templates, ILM policies, and ingest pipelines etc. These components will ensure that Corelight data is correctly formatted and aligned with Elastic's schema.

**Send Data from Corelight to Elastic**: Once the ECS mappings are in place, configure Elasticsearch in the web interface under Sensor > Export > Export to Elastic. It will require below parameters:
- **Server:** The HTTP or HTTPS URL (including the port).
- **Prefix:** The Elasticsearch index, alias, and template prefix (e.g. logs-corelight-*).
- **Username:** The Username to authenticate to Elasticsearch.
- **Password:** The Password to authenticate to Elasticsearch.
- **Zeek logs to exclude:** Logs that you don't want to export to Elasticsearch. If blank, sensor will export all log types.
- **Elasticsearch log filter:** Logs to exclude using the Corelight Filtering Language.

**Note**: Use the index prefix name (logs-*) instead of a custom index prefix.

## Setup

### Enabling the integration in Elastic:

1. In Kibana navigate to Management > Integrations.
2. In "Search for integrations" top bar, search `Corelight`.
3. Select the "Corelight" integration from the search results.
4. Navigate to Settings.
5. Select the "Install Corelight assets".
6. Navigate to Assets to get list of dashboards.

> **Note:** This integration provides dashboards only. We recommend regularly checking and updating assets using the script from the Corelight repository. For any mapping or parsing issues, especially those not related to the dashboards, we recommend contacting Corelight, as they maintain those components.
