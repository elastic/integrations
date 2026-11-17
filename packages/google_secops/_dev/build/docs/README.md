# Google SecOps

[Google SecOps](https://cloud.google.com/chronicle/docs/secops/secops-overview) is a cloud-based service designed for enterprises to retain, analyze, and search large volumes of security and network telemetry. It normalizes, indexes, and correlates data to detect threats. Investigate their scope and cause, and provide remediation through pre-built integrations. The platform enables security analysts to examine aggregated security information, search across domains, and mitigate threats throughout their lifecycle.

The Google SecOps integration collects alerts using the [Detection Engine API](https://cloud.google.com/chronicle/docs/reference/detection-engine-api#listdetections).

## Compatibility

This module has been tested against the Google SecOps version **v2**.

## Data streams

This integration collects the following logs:

- **[Alerts v2](https://cloud.google.com/chronicle/docs/reference/rest/v1alpha/projects.locations.instances.legacy/legacySearchDetections)** (`google_secops.alert_v2`) - Retrieves YARA-L rule detections using the Chronicle API `legacySearchDetections` method. **Use this data stream for new deployments.**
- **[Alerts](https://cloud.google.com/chronicle/docs/reference/detection-engine-api#response_fields_3)** (`google_secops.alert`) - **Deprecated.** Retrieves alerts using the Backstory Detection Engine API. Only existing Google SecOps Backstory users can access this API. New users should use **Alerts v2** instead.

## Requirements

### Elastic Managed enabled integration

Elastic Managed integrations are only supported on Elastic Cloud Serverless and Elastic Cloud Hosted deployments. An Elastic Managed integration lets you ingest data from a cloud source while avoiding the orchestration, management, and maintenance associated with standard ingest infrastructure. Elastic runs the collector for you, so you can focus on your data instead of the infrastructure that collects it.

For more information, refer to [Elastic Managed integrations](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations) and the [Elastic Managed integrations FAQ](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations-faq).

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Setup

### Collect data from the Google SecOps API

1. Create Google SecOps service account [Steps to create](https://developers.google.com/identity/protocols/oauth2/service-account#creatinganaccount).

**Chronicle API** must be enabled.

### Enable the Chronicle API

1. Log in to the  "https://console.cloud.google.com/"  using valid credentials.
2. Navigate to the **Chronicle API**.
3. Click **Enable**.

### Update the Permission of Service Account

1. Open GCP Console, and go to IAM.
2. In **View By Main Tab**, click **GRANT ACCESS**.
3. Add Service Account name in **New Principals**.
4. In **Assign Role**, select **Owner**.
5. Click **Save**.

This integration will make use of the following *oauth2 scope*:

- `https://www.googleapis.com/auth/chronicle-backstory`

Once Service Account credentials are downloaded as a JSON file, then the integration can be setup to collect data.
For more details, please refer [Google Chronicle Detection Engine API]( https://cloud.google.com/chronicle/docs/reference/detection-engine-api#getting_api_authentication_credentials).

If installing in GCP-Cloud environment, credentials are not necessary but make sure the account linked with the VM has all the required IAM permissions. Steps to [Set up Application Default Credentials](https://cloud.google.com/docs/authentication/provide-credentials-adc).

### Collect data for the Alerts v2 data stream

Enable the **Alerts v2** data stream to collect from the Chronicle API [`legacySearchDetections`](https://cloud.google.com/chronicle/docs/reference/rest/v1alpha/projects.locations.instances.legacy/legacySearchDetections) method. Documents ingest into the `google_secops.alert_v2` data stream.

1. Assign **Chronicle Viewer** (`roles/chronicle.viewer`) to the service account in IAM.
2. Configure OAuth scope `https://www.googleapis.com/auth/chronicle.readonly` (or another supported Chronicle scope). See [Chronicle API authentication](https://cloud.google.com/chronicle/docs/reference/authentication).
3. Note your regional Chronicle API URL, GCP project ID, location, and instance ID from Google SecOps. See [Chronicle API endpoints](https://cloud.google.com/chronicle/docs/reference/rest).

### Enabling the integration in Elastic:

1. In the top search bar in Kibana, search for **Integrations**.
2. In "Search for integrations" top bar, search for `Google SecOps`.
3. Select the "Google SecOps" integration from the search results.
4. Select "Add Google SecOps" to add the integration.
5. Add all the required integration configuration parameters to enable data collection:
   - For **Alerts v2**, enable the **Alerts v2** data stream and add the regional Chronicle API URL (for example, `https://us-chronicle.googleapis.com`), GCP project ID, location, instance ID, OAuth scope, Credentials Type, and Credentials.
   - For **Alerts** (deprecated; existing Backstory users only), set the URL to `https://backstory.googleapis.com` and add the Credentials Type and Credentials.
6. Select "Save and continue" to save the integration.

**Note**: The default URL is `https://us-chronicle.googleapis.com`, but this may vary depending on your region. Please refer to the [Documentation](https://cloud.google.com/chronicle/docs/reference/search-api#regional_endpoints) to find the correct URL for your region.

## Logs reference

### Alert

> **Deprecated:** The `alert` data stream uses the Backstory Detection Engine API and is only available to existing Google SecOps Backstory users. New users should use the [`alert_v2`](#alert-v2) data stream instead.

This is the `alert` dataset.

#### Example

{{event "alert"}}

{{fields "alert"}}

### Alert v2

This is the `alert_v2` dataset.

#### Example

{{event "alert_v2"}}

{{fields "alert_v2"}}
