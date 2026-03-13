# ProjectDiscovery Cloud Integration for Elastic

## Overview

The ProjectDiscovery Cloud integration helps you centralize your external attack surface management (EASM) data by ingesting security findings directly into the Elastic Stack. This gives your security teams better visibility and analysis capabilities. You can monitor vulnerabilities, track remediation progress, and automate alerting within Kibana.

This integration facilitates:
- **Vulnerability management**: Ingests security vulnerabilities identified by ProjectDiscovery scans, enabling faster remediation and historical trend analysis. The `vulnerability_scan` data stream collects detailed findings and scan results.
- **Vulnerability changelog monitoring**: Tracks the status changes of vulnerabilities over time, such as new, resolved, or reintroduced issues. The `vulnerability_changelog` data stream collects logs about these changes to help you maintain an accurate view of your security posture.

### Compatibility

This integration is compatible with the ProjectDiscovery Cloud SaaS platform and requires a `Basic` subscription or higher.

You'll also need:
- Elastic Stack version `8.19.4` or `9.0.0` and higher.
- An Elastic Agent enrolled in Fleet with outbound internet connectivity to reach the vendor's API.

### How it works

This integration uses an Elastic Agent to collect data from the ProjectDiscovery Cloud API. It polls the API for security findings and vulnerability status changes, collecting the data in JSON format over HTTPS. The data is then parsed and mapped to the Elastic Common Schema (ECS) for analysis in your Elastic deployment.

## What data does this integration collect?

The ProjectDiscovery Cloud integration collects log data via API polling. It populates the following data streams:

*   **Vulnerability Scans (`vulnerability_scan`)**: Collects detailed security findings and scan results from the ProjectDiscovery Cloud platform. This includes data on identified vulnerabilities, severity levels (Critical, High, Medium, Low, Info), and scan lifecycle events.
*   **Vulnerability Changelogs (`vulnerability_changelog`)**: Collects logs about changes in vulnerability status, which helps you track remediation progress over time.

All data is collected in JSON format and mapped to the Elastic Common Schema (ECS) for consistency.

### Supported use cases

Integrating ProjectDiscovery Cloud logs with Elastic provides a powerful solution for enhancing your security posture. Key use cases include:

*   **Centralized vulnerability management**: Monitor and analyze vulnerability data from ProjectDiscovery Cloud directly within Elastic.
*   **Remediation tracking**: Use the vulnerability changelog data to monitor the progress and effectiveness of your remediation efforts.
*   **Incident enrichment**: Correlate vulnerability findings with other security and observability data sources in Elastic to accelerate incident investigation and response.

## What do I need to use this integration?

Before you can use this integration, you need:
- An active ProjectDiscovery Cloud account.
- An API key generated from your ProjectDiscovery Cloud account for authentication.
- An Elastic deployment running version 8.19.4 or higher. For more information, see our support matrix.
- An Elastic Agent installed on a host with outbound internet connectivity, able to reach `api.projectdiscovery.io` on port `443`.
- An agent policy to which you can add the ProjectDiscovery Cloud integration.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed on a host that can connect to the ProjectDiscovery Cloud API. For more details, check the Elastic Agent [installation instructions](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html). You can install only one Elastic Agent per host.

Elastic Agent is required to poll the ProjectDiscovery Cloud API and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Set up steps in ProjectDiscovery Cloud

Before you can configure the integration in Kibana, you need to retrieve an API key and your Team ID from the ProjectDiscovery Cloud dashboard.

1.  Log in to your ProjectDiscovery Cloud Dashboard.
2.  In the left-hand navigation sidebar, click the **Settings** gear icon and select **API Key**.
3.  If you don't have an API key, click the button to generate a new one. Copy the key immediately and store it in a safe place, as it will not be shown again.
4.  Navigate back to the **Settings** menu and select the **Team** tab.
5.  Locate the field labeled **Team ID** or **Workspace ID** and copy this value.
6.  Ensure that your discovery scans and monitors are active in ProjectDiscovery Cloud so that data is available for the integration to collect.
7.  Confirm that your network's firewall allows outbound traffic to the API endpoint: `https://api.projectdiscovery.io`.

### Set up steps in Kibana

Follow these steps to configure the integration in your Elastic deployment:

1.  In Kibana, navigate to **Management > Integrations**.
2.  In the search bar, enter "ProjectDiscovery Cloud" and select the integration.
3.  Click **Add ProjectDiscovery Cloud**.
4.  Configure the integration with the credentials you retrieved from ProjectDiscovery Cloud:
    *   **URL**: The base URL for the ProjectDiscovery Cloud API. This defaults to `https://api.projectdiscovery.io`.
    *   **API Key**: The secret API Key you generated.
    *   **Team ID**: The alphanumeric Team ID from your account settings.
5.  Under **Advanced Options**, you can configure the following optional settings:
    *   **Proxy URL**: If your environment requires a proxy for outbound connections, enter its URL in the format `http[s]://<user>:<password>@<server>:<port>`. Ensure special characters are URL-encoded.
    *   **SSL Configuration**: If you need custom SSL settings, provide the YAML configuration for `certificate_authorities`, `supported_protocols`, or `verification_mode`.
6.  Choose the agent policy where you want to add this configuration.
7.  Click **Save and continue**, then deploy the configuration to your Elastic Agents.

### Validation

To validate that the integration is working correctly, follow these steps:

1.  In Kibana, navigate to **Discover**.
2.  In the search bar, enter `data_stream.dataset: "projectdiscovery_cloud.vulnerability*"` and check for incoming documents.
3.  Verify that events are appearing with recent timestamps.
4.  Navigate to **Management > Fleet > Agents** to confirm that the agent running the integration is healthy.

## Troubleshooting

For help with generic Elastic Agent and ingest issues, see [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

### Common configuration issues

-   **No data is being collected**:
    *   Verify network connectivity from the Elastic Agent host to `https://api.projectdiscovery.io` on port 443. Use a command like `curl -v https://api.projectdiscovery.io` to test the connection.
    *   Ensure that no firewalls or network ACLs are blocking outbound traffic from the Elastic Agent to the ProjectDiscovery Cloud API.
    *   Check the Elastic Agent logs for connection errors or messages indicating an invalid API key.
-   **API authentication errors (401 Unauthorized)**:
    *   This error means your API key is invalid.
    *   Verify the API Key configured in the integration settings matches the one from your ProjectDiscovery Cloud dashboard.
    *   Ensure there are no leading or trailing spaces or hidden characters copied with the key.
    *   Generate a new key in the ProjectDiscovery Cloud dashboard if the issue persists.
-   **API authorization errors (403 Forbidden or 404 Not Found)**:
    *   This error often indicates that the `Team ID` is incorrect or that the API key does not have permission to access the specified team's data.
    *   Double-check the `Team ID` in the **Settings > Team** section of the ProjectDiscovery Cloud dashboard and update it in the integration settings.
-   **API rate limiting errors (429 Too Many Requests)**:
    *   If you see HTTP 429 errors in the Elastic Agent logs, the integration is polling the API too frequently.
    *   Increase the polling interval in the integration's data stream settings to stay within the vendor's API quotas.
-   **Proxy URL encoding issues**:
    *   If you use a proxy and your credentials contain special characters (like `@`, `:`, or `/`), they must be URL-encoded. An unencoded URL can cause parsing failures and connection errors.
-   **Delayed configuration updates**:
    *   After you save changes to the integration policy in Kibana, it may take a few minutes for the Elastic Agent to poll for and apply the new configuration. You can check the agent's status and last check-in time in **Fleet > Agents**.

### Vendor resources

-   [ProjectDiscovery Cloud Dashboard](https://cloud.projectdiscovery.io)
-   [ProjectDiscovery Cloud API Reference](https://docs.projectdiscovery.io/api-reference/introduction)
-   [ProjectDiscovery Cloud Integrations](https://docs.projectdiscovery.io/cloud/integrations)

## Performance and scaling

To ensure optimal performance in high-volume environments, consider the following recommendations:

*   **Monitor API rate limits**: The integration collects data by polling an HTTPS API endpoint. In environments with a large number of findings, you might encounter HTTP `429` (Too Many Requests) errors. If you see these errors, increase the polling interval to stay within the vendor's API quota. Also, ensure the Elastic Agent host has sufficient bandwidth.
*   **Filter data at the source**: Use the `Team ID` field in your configuration to retrieve only the data relevant to specific environments. Filtering at the source reduces processing overhead on the Elastic Agent and decreases the storage footprint in Elasticsearch.
*   **Scale your Elastic Agent**: For high-throughput environments with frequent, large-scale scans, deploy the integration on a dedicated Elastic Agent or increase the CPU and memory allocation for the agent. This ensures efficient processing without impacting other integrations on the same host.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### vulnerability_changelog

The `vulnerability_changelog` data stream collects events related to changes in discovered vulnerabilities from ProjectDiscovery Cloud.

#### vulnerability_changelog fields

{{ fields "vulnerability_changelog" }}

#### vulnerability_changelog sample event

{{ event "vulnerability_changelog" }}

### vulnerability_scan

The `vulnerability_scan` data stream collects the results from vulnerability scans performed by ProjectDiscovery Cloud.

#### vulnerability_scan fields

{{ fields "vulnerability_scan" }}

#### vulnerability_scan sample event

{{ event "vulnerability_scan" }}

### Inputs used

{{ inputDocs }}

### API usage

This integration uses the ProjectDiscovery Cloud API to collect data. The following resources provide more information about the API:

*   [ProjectDiscovery Cloud API Reference](https://docs.projectdiscovery.io/api-reference/introduction)
