# Nextron Thor APT Scanner

[Nextron Thor APT Scanner](https://www.nextron-systems.com/thor/) is a powerful threat hunting and incident response tool that provides comprehensive scanning capabilities for detecting advanced persistent threats (APTs), malware, and security vulnerabilities across Windows systems. The Nextron Thor APT Scanner integration enables you to consume and analyze Thor Cloud scan results within Elastic Security, providing centralized visibility into threat detection findings and facilitating automated incident response workflows.

## Data streams

The Nextron Thor APT Scanner integration collects one type of data:

- **Thor Forwarding** - Scan results and findings from Thor Cloud API, including detected threats, malware signatures, suspicious files, and security events identified during system scans.

## Requirements

This integration supports Elastic Agent-based data collection.

### Elastic Agent

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

The minimum **kibana.version** required is **9.1.3**.

This integration has been tested against the **Nextron Thor Cloud API**.

## Setup

### Get the Thor Cloud API URL

1. Access your Nextron Thor Cloud dashboard.
2. Navigate to the API settings section.
3. Copy the **API Endpoint URL** (default: `https://thor-cloud.nextron-services.com/api`).

### Get the API Key

1. In the Thor Cloud dashboard, navigate to **General Settings** > **API Key**.
2. Click **Generate**.
4. Copy the generated API key. You won't be able to copy it after this stage.

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search top bar, type **Nextron Thor APT Scanner**.
3. Select the **Nextron Thor APT Scanner** integration and add it.
4. Configure the required integration parameters:
   - **API URL**: The Thor Cloud API endpoint URL
   - **API Key**: Your Thor Cloud API key
   - **Initial Interval**: How far back to pull scan logs (default: 24h)
   - **Interval**: Duration between API requests (default: 5m)
5. Save the integration.

**Note:**
- Scan data is fetched based on the configured initial interval and polling frequency.
- The integration supports batch processing with configurable batch sizes for optimal performance.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog or log file receiver and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Onboard / configure

To completely set up the Nextron Thor APT Scanner integration:

1. **Prepare Thor Cloud Access**
   - Log into your Nextron Thor Cloud dashboard
   - Generate an API key from General Settings > API Key
   - Note your API endpoint URL

2. **Install Elastic Agent**
   - Follow the [Elastic Agent installation guide](docs-content://reference/fleet/install-elastic-agents.md)
   - Ensure the agent is properly enrolled in Fleet

3. **Add the Integration**
   - Navigate to Kibana > Management > Integrations
   - Search for "Nextron Thor APT Scanner"
   - Click "Add Nextron Thor APT Scanner"

4. **Configure Integration Settings**
   - Enter your Thor Cloud API URL
   - Provide your API key
   - Set initial interval (recommended: 24h for first run)
   - Configure polling interval (recommended: 5m)
   - Adjust batch size if needed (default: 100)

5. **Deploy Configuration**
   - Review all settings
   - Save and deploy the integration
   - Monitor the agent logs for successful connection


## Exported fields
{{fields "thor_forwarding"}}

## Example Event

{{event "thor_forwarding"}}