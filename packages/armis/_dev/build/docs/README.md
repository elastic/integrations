# Armis

## Overview

[Armis](https://www.armis.com/) is an enterprise-class security platform designed to provide visibility and protection for managed, unmanaged, and IoT devices. It enables organizations to detect threats, manage vulnerabilities, and enforce security policies across their network.

Use this integration to collect and parse data from your Armis instance.

### Compatibility

This module has been tested against the Armis API version **v1**.

## What data does this integration collect?

The Armis integration collects three types of logs.

- **Devices**: Fetches the latest updates for all devices monitored by Armis.
- **Alerts**: Gathers alerts associated with all devices monitored by Armis.
- **Vulnerabilities**: Retrieves detected vulnerabilities and possible mitigation steps across all devices monitored by Armis.

**Note**:

1. The **vulnerability data stream** retrieves information by first fetching vulnerabilities and then identifying the devices where these vulnerabilities were detected, using a chained call between the vulnerability search and vulnerability match endpoints.

## What do I need to use this integration?

### Elastic Managed enabled integration

Elastic Managed integrations are only supported on Elastic Cloud Serverless and Elastic Cloud Hosted deployments. An Elastic Managed integration lets you ingest data from a cloud source while avoiding the orchestration, management, and maintenance associated with standard ingest infrastructure. Elastic runs the collector for you, so you can focus on your data instead of the infrastructure that collects it.

For more information, refer to [Elastic Managed integrations](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations) and the [Elastic Managed integrations FAQ](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations-faq).

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

## Setup

### Collect logs through REST API

1. Log in to your Armis portal.
2. Navigate to the **Settings** tab.
3. Select **Asset Management & Security**.
4. Go to **API Management** and generate a **Secret Key**.

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search bar, type **Armis**.
3. Select the **Armis** integration and add it.
4. Add all the required integration configuration parameters, including the URL, Secret Key to enable data collection.
5. Save the integration.

## Data retention

The `alert` and `device` data streams can hold repeated copies of the same records across polling intervals.

The package bounds the growth of these source data streams with a retention that depends on the deployment type:

| Data stream | Self-managed and Elastic Cloud Hosted (ILM policy) | Serverless (data stream lifecycle) |
|---|---|---|
| `logs-armis.alert-*` | `logs-armis.alert-default_policy`: roll over after 30d, delete 30d after rollover | delete 30d after ingestion |
| `logs-armis.device-*` | `logs-armis.device-default_policy`: roll over after 30d, delete 30d after rollover | delete 30d after ingestion |

On self-managed and Elastic Cloud Hosted deployments the ILM policy applies. The data stream lifecycle shipped with the package is not used there. ILM counts the delete age from the rollover of a backing index, so a document can remain for up to the rollover age plus the delete age. On Serverless, ILM is not available and the data stream lifecycle applies instead: documents are deleted the stated time after they are ingested. Where the package installs a transform, the transform's destination indices are not affected by either.

To keep data for a different period:

- Self-managed and Elastic Cloud Hosted: edit the ILM policy in Kibana under **Stack Management → Index Lifecycle Policies**, or with `PUT _ilm/policy/<policy name>`. A package upgrade reinstalls the package's ILM policies, so check your change after upgrading.
- Serverless: set the retention on the data stream, for example `PUT _data_stream/logs-armis.alert-default/_lifecycle` with the body `{"data_retention": "90d"}`. Replace `default` with your namespace.

## Limitations

In the **vulnerability data stream**, our filtering mechanism for the **vulnerability search API** relies specifically on the `lastDetected` field. This means that when a user takes action on a vulnerability and `lastDetected` updates, only then will the event for that vulnerability be retrieved. Initially, we assumed this field would always have a value and could be used as a cursor timestamp for fetching data between intervals. However, due to inconsistencies in the API response, we observed cases where `lastDetected` is `null`.

## Troubleshooting

- If you get the following errors in the **vulnerability data stream**, reduce the page size in your request.

  **Common errors:**
  - `502 Bad Gateway`
  - `414 Request-URI Too Large`

- If you encounter issues in the **alert data stream**, particularly during the initial data fetch, reduce the initial interval.

  **Example error:**
  - `The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.`

## Logs reference

### Alert

This is the `alert` dataset.

#### Example

An example event for `alert` looks as following:

{{event "alert"}}

#### Exported fields

{{fields "alert"}}

### Device

This is the `device` dataset.

#### Example

An example event for `device` looks as following:

{{event "device"}}

#### Exported fields

{{fields "device"}}

### Vulnerability

This is the `vulnerability` dataset.

#### Example

An example event for `vulnerability` looks as following:

{{event "vulnerability"}}

#### Exported fields

{{fields "vulnerability"}}
