# Google SecOps

[Google SecOps](https://cloud.google.com/chronicle/docs/secops/secops-overview) is a cloud-based service designed for enterprises to retain, analyze, and search large volumes of security and network telemetry. It normalizes, indexes, and correlates data to detect threats, investigate their scope and cause, and provide remediation through prebuilt integrations. The platform enables security analysts to examine aggregated security information, search across domains, and mitigate threats throughout their lifecycle.

The Google SecOps integration collects alerts using the [REST API](https://cloud.google.com/chronicle/docs/reference/detection-engine-api#listdetections).

## Compatibility

This module has been tested against the Google SecOps version **v2**.

## Data streams

This integration collects the following logs:

- **[Alerts](https://cloud.google.com/chronicle/docs/reference/detection-engine-api#response_fields_3)** - This method enables users to retrieve alerts from Google SecOps.

## Requirements

Elastic Agent must be installed. For more details and installation instructions, please refer to the [Elastic Agent Installation Guide](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

### Installing and managing an Elastic Agent:

There are several options for installing and managing Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

Please note, there are minimum requirements for running Elastic Agent. For more information, refer to the [Elastic Agent Minimum Requirements](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html#elastic-agent-installation-minimum-requirements).

## Setup

### To collect data from the Google SecOps API:

   - Create Google SecOps service account [Steps to create](https://developers.google.com/identity/protocols/oauth2/service-account#creatinganaccount).
   - Permissions required for Service Account: 
      - chronicle.rules.list
   - **Chronicle API** must be enabled.

This integration will make use of the following *oauth2 scope*:

- `https://www.googleapis.com/auth/chronicle-backstory`

Once Service Account credentials are downloaded as a JSON file, then the integration can be setup to collect data.

If installing in GCP-Cloud Environment, No need to provide any credentials and make sure the account linked with the VM has all the required IAM permissions. Steps to [Set up Application Default Credentials](https://cloud.google.com/docs/authentication/provide-credentials-adc).

### Enabling the integration in Elastic:

1. In Kibana navigate to Management > Integrations.
2. In "Search for integrations" top bar, search for `Google SecOps`.
3. Select the "Google SecOps" integration from the search results.
4. Select "Add Google SecOps" to add the integration.
5. Add all the required integration configuration parameters, including the URL, Credentials Type, and Credentials, to enable data collection.
6. Select "Save and continue" to save the integration.

**Note**: The default URL is `https://backstory.googleapis.com`, but this may vary depending on your region. Please refer to the [Documentation](https://cloud.google.com/chronicle/docs/reference/search-api#regional_endpoints) to find the correct URL for your region.

## Logs reference

### Alert

This is the `alert` dataset.

#### Example

{{event "alert"}}

{{fields "alert"}}
