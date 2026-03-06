# Service Info

## Common use cases

The ProjectDiscovery Cloud integration for Elastic provides a streamlined way to ingest security findings directly into the Elastic Stack. This integration allows security teams to centralize their external attack surface management (EASM) data for better visibility and analysis.

* **Vulnerability Management:** Monitor and track security vulnerabilities identified by ProjectDiscovery scans. This enables faster remediation through automated alerting and historical trend analysis within Kibana.
* **Vulnerability Changelog Monitoring:** Track the status changes of vulnerabilities over time (e.g., new, resolved, or reintroduced) to maintain an accurate view of your security posture evolution.

## Data types collected

This integration collects log data via API polling using the Common Expression Language (CEL) input. It populates the following data streams:

* **projectdiscovery.vulnerability_scan**: Collects detailed security findings and scan results from the ProjectDiscovery Cloud platform.
* **projectdiscovery.vulnerability_changelog**: Collects logs regarding changes in vulnerability status (diffs) to track remediation progress.

Specific types of data include:

* **Security Findings:** Detailed logs regarding identified vulnerabilities, including severity levels (Critical, High, Medium, Low, Info), templates used, and matching metadata.
* **Scan Status Events:** Data regarding the lifecycle of a scan, including start times, end times, and team-specific scoping information based on the **Team ID**.
* **Data Format:** All data is collected in JSON format via HTTPS API requests and mapped to the Elastic Common Schema (ECS) for consistency.

## Compatibility

This integration is compatible with the **ProjectDiscovery Cloud** SaaS platform. Requirements include:

* **Elastic Stack:** Version **8.19.4** or **9.0.0** and higher is required to support the CEL input and integration components.
* **Subscription:** A **Basic** subscription or higher is required.
* **Elastic Agent:** Requires an Elastic Agent enrolled in Fleet with outbound internet connectivity to reach the vendor API.

## Scaling and Performance

To ensure optimal performance in high-volume environments, consider the following:

* **Transport/Collection Considerations:** Data is collected via API polling over HTTPS using the Common Expression Language (CEL) input. For environments with a massive number of findings, ensure the Elastic Agent host has sufficient bandwidth and monitor for HTTP 429 (Too Many Requests) errors. If rate limits are encountered, increase the polling interval to stay within the vendor's API quota.
* **Data Volume Management:** Configure the integration using the **Team ID** field to retrieve only data pertinent to specific environments. Filtering data at the source via API parameters reduces the processing overhead on the Elastic Agent and decreases the storage footprint in Elasticsearch by avoiding the ingestion of irrelevant events.
* **Elastic Agent Scaling:** For high-throughput environments with frequent, large-scale scans (e.g., thousands of findings per hour), deploy the integration on a dedicated Elastic Agent or increase the CPU and memory allocation for the Agent. This ensures efficient JSON parsing and CEL evaluation without impacting other integrations on the same host.

# Set Up Instructions

## Elastic prerequisites

1. **Elastic Stack Version:** Verify that your Kibana and Elasticsearch instances are running version **8.19.4** or higher.
2. **Elastic Agent Deployment:** Ensure an Elastic Agent is installed on a host with outbound internet connectivity and is successfully enrolled in a Fleet policy.
3. **Connectivity Requirements:** Verify that the host running the Elastic Agent can reach `api.projectdiscovery.io` on port **443** (HTTPS).
4. **Policy Configuration:** Have a Fleet Agent Policy ready to which you can add the ProjectDiscovery Cloud integration.

## Vendor set up steps

1. **Log in to the Dashboard:** Access your account by logging in to the ProjectDiscovery Cloud Dashboard.
2. **Navigate to API Settings:** In the left-hand navigation sidebar, locate the **Settings** gear icon and select **API Key**.
3. **Generate API Key:** If an API key does not already exist, click the button to generate a new one. Copy the generated key immediately and store it securely, as it will not be shown again.
4. **Identify Team ID:** Navigate back to the **Settings** menu and select the **Team** tab, or visit the [Team Settings page](https://cloud.projectdiscovery.io/settings/team) directly.
5. **Copy Team ID:** Locate the field labeled **Team ID** or **Workspace ID**. Copy this unique alphanumeric string for use in the Kibana configuration.
6. **Configure Scans:** Ensure that your discovery scans and monitors are active in ProjectDiscovery Cloud so that there is data available for the API to provide to the Elastic Agent.
7. **Verify API Endpoint:** Confirm that your network's firewall allows traffic to the default base URL: `https://api.projectdiscovery.io`

## Kibana set up steps

1. In Kibana, navigate to **Management > Fleet > Integrations**.
2. Search for **ProjectDiscovery Cloud** in the search bar and click on the integration tile.
3. Click **Add ProjectDiscovery Cloud**.
4. Configure the integration settings using the variables from your vendor setup:
* **URL** (`url`): The base URL for the ProjectDiscovery Cloud API. This defaults to `https://api.projectdiscovery.io`
* **API Key** (`api_key`): Enter the secret API Key retrieved from your ProjectDiscovery Cloud settings.
* **Team ID** (`team_id`): Enter the alphanumeric Team ID required for scoped requests.
* **Proxy URL** (`proxy_url`): (Optional) Provide the URL to proxy connections if your environment requires it, in the format `http[s]://<user>:<password>@<server>:<port>`. Ensure special characters are URL-encoded.
* **SSL Configuration** (`ssl`): (Optional) Provide YAML configuration for **certificate_authorities**, **supported_protocols**, or **verification_mode** if custom SSL settings are needed for your network environment.


5. Choose the **Agent Policy** where you want to add this configuration.
6. Click **Save and Continue**, then click **Add agent integration** to deploy the configuration to your Elastic Agents.

# Troubleshooting

## Common Configuration Issues

* **Proxy URL Encoding**: If your proxy credentials include special characters (like @, :, or /) and are not URL-encoded, the Elastic Agent will fail to parse the Proxy URL, resulting in connection errors. Ensure all credentials in the URL string are properly encoded.
* **Team ID Mismatch**: Using an incorrect Team ID will result in 404 or 403 errors from the ProjectDiscovery API. Double-check the ID in the **Settings > Team** section of the ProjectDiscovery Cloud dashboard.
* **Network Egress Blocked**: If the Elastic Agent host cannot reach `https://api.projectdiscovery.io`, no data will be collected. Verify network connectivity using `curl -v https://api.projectdiscovery.io` from the host machine.
* **Policy Deployment Delay**: After clicking save in Kibana, it may take several minutes for the Elastic Agent to receive and apply the new policy. Check the Agent status in **Fleet > Agents** to ensure it is "Healthy".

## Ingestion Errors

* **CEL Evaluation Errors**: Check the Elastic Agent logs on the host for any errors related to the CEL input. This can occur if the API returns an unexpected data structure that the integration's expression language cannot parse.
* **Rate Limiting (429 Errors)**: If you see HTTP 429 errors in the agent logs, the polling interval is too frequent. Increase the interval in the integration settings to comply with ProjectDiscovery Cloud API quotas.
* **Field Mapping Issues**: Check the `error.message` field in Kibana for messages indicating that a field could not be mapped correctly to the Elastic Common Schema (ECS).

## API Authentication Errors

* **Unauthorized (401 Errors)**: This typically indicates the API Key is invalid or the header is not being passed correctly. Verify the API Key field in the Kibana UI does not contain extra spaces or hidden characters.
* **Forbidden (403 Errors)**: The API Key may be valid, but the user account associated with it may lack the permissions to view data for the specified Team ID.

## Vendor Resources

* [ProjectDiscovery Cloud Dashboard](https://cloud.projectdiscovery.io)
* [ProjectDiscovery Cloud API Reference](https://docs.projectdiscovery.io/api-reference/introduction)
* [ProjectDiscovery Cloud Integrations](https://docs.projectdiscovery.io/cloud/integrations)
* Refer to the [official vendor website](https://projectdiscovery.io) for additional resources.
