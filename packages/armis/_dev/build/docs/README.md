# Armis

## Overview

[Armis](https://www.armis.com/) is an enterprise-class security platform designed to provide visibility and protection for managed, unmanaged, and IoT devices. It enables organizations to detect threats, manage vulnerabilities, and enforce security policies across their network.

Use this integration to collect and parse data from your Armis instance.

### Compatibility

This module has been tested against the Armis API version **v1**. Armis documents v1 as a supported API. v3 does not replace the device, alert, and vulnerability search calls this integration uses.

### How it works

The Elastic Agent uses the CEL input to poll the Armis API v1. Each data stream authenticates with `POST /api/v1/access_token/` using the secret key, then sends the access token in the `Authorization` header.

- **Devices** call `GET /api/v1/search/` with `in:devices`, ordered by `lastSeen`. The next poll starts from the latest `lastSeen` value.
- **Alerts** call `GET /api/v1/search/` with `in:alerts` and a `statusChangeTime` window.
- **Vulnerabilities** call `GET /api/v1/search/` with `in:vulnerabilities` and a `lastDetected` window, then `GET /api/v1/vulnerability-match/` for the devices where those vulnerabilities were detected.

Search requests follow `data.next` until the page is exhausted. Ingest pipelines map the response to ECS and keep the Armis fields under `armis.*`. The alert and device data streams also install a latest transform so the dashboards show the current record for each alert and device.

## What data does this integration collect?

The Armis integration collects three types of logs.

- **Devices**: Fetches the latest updates for all devices monitored by Armis.
- **Alerts**: Gathers alerts associated with all devices monitored by Armis.
- **Vulnerabilities**: Retrieves detected vulnerabilities and possible mitigation steps across all devices monitored by Armis.

**Note**:

1. The **vulnerability data stream** retrieves information by first fetching vulnerabilities and then identifying the devices where these vulnerabilities were detected, using a chained call between the vulnerability search and vulnerability match endpoints.

### Supported use cases

- Review the device inventory, including host identity, addresses, and operating system, on the Devices dashboard. Device documents set `host.id` and `host.name`, which Elastic Security can use to build host entities.
- Investigate Armis alerts. Alert documents set `event.kind` to `alert`.
- Review detected vulnerabilities and the devices they match, including the CVE identifier and severity, on the Vulnerabilities dashboard.

## What do I need to use this integration?

### Agent-based installation

Elastic Agent must be installed and enrolled in Fleet. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

You also need an Armis secret key from **Settings > Asset Management & Security > API Management**, and the base URL of the Armis API.

### Elastic Managed enabled integration

Elastic Managed integrations are only supported on Elastic Cloud Serverless and Elastic Cloud Hosted deployments. An Elastic Managed integration lets you ingest data from a cloud source while avoiding the orchestration, management, and maintenance associated with standard ingest infrastructure. Elastic runs the collector for you, so you can focus on your data instead of the infrastructure that collects it.

For more information, refer to [Elastic Managed integrations](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations) and the [Elastic Managed integrations FAQ](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations-faq).

## How do I deploy this integration?

Fleet-managed Elastic Agent and Elastic Managed (agentless) deployment are both supported. Standalone Elastic Agent is not required.

### Collect logs through REST API

1. Log in to your Armis portal.
2. Navigate to the **Settings** tab.
3. Select **Asset Management & Security**.
4. Go to **API Management** and generate a **Secret Key**.

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search bar, type **Armis**.
3. Select the **Armis** integration and add it.
4. Add all the required integration configuration parameters, including the URL and Secret Key, to enable data collection.
   - **URL**: Base URL of the Armis API.
   - **Secret Key**: Secret key generated in Armis.
   - **Interval**: Time between polls. The default is `5m` for each data stream.
   - **Initial Interval**: How far back the first poll looks. The default is `24h`.
   - **Page Size**: Number of records per search request. The default is `2000` for alerts and devices, and `89` for vulnerabilities. Vulnerability match requests place the returned ids on the query string, so that page size is smaller.
5. Save the integration.

### Validation

After the integration is saved, confirm that data is arriving:

1. In **Fleet**, confirm the Armis integration is healthy.
2. In **Discover**, open `logs-armis.device-*`, `logs-armis.alert-*`, and `logs-armis.vulnerability-*`. Documents appear after the first interval. The first collection looks back the Initial Interval.
3. Open the Armis **Devices**, **Alerts**, and **Vulnerabilities** dashboards. The Devices and Alerts dashboards read the latest-transform destination.
4. Record the Elasticsearch, Kibana, and Elastic Agent versions from **Stack Management > About** and the agent, and note whether each data stream returned documents.

## Data retention

The `alert` and `device` data streams can hold repeated copies of the same records across polling intervals.

The package bounds the growth of these source data streams with a retention that depends on the deployment type:

| Data stream | Self-managed and Elastic Cloud Hosted (ILM policy) | Serverless (data stream lifecycle) |
|---|---|---|
| `logs-armis.alert-*` | `logs-armis.alert-default_policy`: roll over after 30d, delete 30d after rollover | delete 30d after rollover |
| `logs-armis.device-*` | `logs-armis.device-default_policy`: roll over after 30d, delete 30d after rollover | delete 30d after rollover |

On self-managed and Elastic Cloud Hosted deployments the ILM policy applies. The data stream lifecycle shipped with the package is not used there. ILM counts the delete age from the rollover of a backing index, so a document can remain for up to the rollover age plus the delete age. On Serverless, ILM is not available and the data stream lifecycle applies instead. It also works per backing index: Elasticsearch [rolls the write index over automatically](https://www.elastic.co/docs/reference/elasticsearch/configuration-reference/data-stream-lifecycle-settings#cluster-lifecycle-default-rollover) on age, size, or document count, and [deletes a backing index once the retention has passed since it rolled over](https://www.elastic.co/docs/manage-data/lifecycle/data-stream#data-streams-lifecycle-how-it-works). A document therefore stays for the retention plus up to one rollover interval. The rollover age is derived from the retention and is an implementation detail that Elasticsearch may change. Where the package installs a transform, the transform's destination indices are not affected by either.

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

## Performance and scaling

Each data stream polls on its own interval. The default is 5 minutes. Alert and device searches request 2000 records per page. Vulnerability search requests 89 records per page, then requests the matching devices. One integration policy per Armis tenant is enough for all three streams.

If a request returns `502` or `414`, lower the page size. If the first alert collection fails because the initial window is too large, shorten the Initial Interval. Raise the interval when the tenant is large and the API cannot keep up with the default poll rate.

The alert and device latest transforms keep one current document per alert or device. Size the cluster for the source data streams plus those destination indices. Source retention is described in [Data retention](#data-retention).

## Reference

### Logs reference

#### Alert

This is the `alert` dataset.

##### Example

An example event for `alert` looks as following:

{{event "alert"}}

##### Exported fields

{{fields "alert"}}

#### Device

This is the `device` dataset.

##### Example

An example event for `device` looks as following:

{{event "device"}}

##### Exported fields

{{fields "device"}}

#### Vulnerability

This is the `vulnerability` dataset.

##### Example

An example event for `vulnerability` looks as following:

{{event "vulnerability"}}

##### Exported fields

{{fields "vulnerability"}}

### Inputs used in this integration

- [CEL input](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-cel.html): Polls the Armis API v1 and paginates each search response.

### APIs used to collect data

- `POST /api/v1/access_token/`: Exchanges the secret key for an access token.
- `GET /api/v1/search/`: Collects devices (`in:devices`), alerts (`in:alerts`), and vulnerabilities (`in:vulnerabilities`).
- `GET /api/v1/vulnerability-match/`: Collects the devices matched to the vulnerabilities returned by search.
