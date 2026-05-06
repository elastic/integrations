# Axonius Integration for Elastic

## Overview

[Axonius](https://www.axonius.com/) is a cybersecurity asset management platform that automatically collects data from hundreds of IT and security tools through adapters, merges that information, and builds a unified inventory of all assets including devices, users, SaaS apps, cloud instances, and more. By correlating data from multiple systems, Axonius helps organizations identify visibility gaps, missing security controls, risky configurations, and compliance issues. It lets you create powerful queries to answer any security or IT question and automate actions such as sending alerts, creating tickets, or enforcing policies.

This integration for Elastic allows you to collect assets and security events data using the Axonius API, then visualize the data in Kibana.

### Compatibility
The Axonius integration is compatible with product version **7.0**.

### How it works
This integration periodically queries the Axonius API to retrieve logs.

## What data does this integration collect?
This integration collects log messages of the following type:

- `Adapter`: Collect details of all adapters (endpoint: `/api/v2/adapters`).

- `User`: Collect details of all users (endpoint: `/api/v2/users`).

- `Gateway`: Collect details of all Gateway (endpoint: `/api/v2/gateway`).

- `Exposure`: Collect details of all exposure assets including:
    - vulnerability_instances (endpoint: `/api/v2/vulnerability_instances`)
    - vulnerabilities (endpoint: `/api/v2/vulnerabilities`)
    - vulnerabilities_repository (endpoint: `/api/v2/vulnerabilities_repository`)

- `Alert Findings`: Collect details of all alert findings and incident assets including:
    - alert_findings (endpoint: `/api/v2/alert_findings`)

- `Incidents`: Collect details of all incident assets including:
    - incidents (endpoint: `/api/v2/incidents`)

- `Storage`: Collect details of all storage assets including:
    - object_storages (endpoint: `/api/v2/object_storages`)
    - file_systems (endpoint: `/api/v2/file_systems`)
    - disks (endpoint: `/api/v2/disks`)

- `Ticket`: Collect details of all ticket assets including:
    - tickets (endpoint: `/api/v2/tickets`)
    - cases (endpoint: `/api/v2/cases`)

- `Network`: Collect details of all identity assets including:
    - networks (endpoint: `/api/v2/networks`)
    - load_balancers (endpoint: `/api/v2/load_balancers`)
    - network_services (endpoint: `/api/v2/network_services`)
    - network_devices (endpoint: `/api/v2/network_devices`)
    - firewalls (endpoint: `/api/v2/firewalls`)
    - nat_rules (endpoint: `/api/v2/nat_rules`)
    - network_routes (endpoint: `/api/v2/network_routes`)

- `Identity`: Collect details of all identity assets including:
    - users (endpoint: `/api/v2/users`)
    - groups (endpoint: `/api/v2/groups`)
    - security_roles (endpoint: `/api/v2/security_roles`)
    - organizational_units (endpoint: `/api/v2/organizational_units`)
    - accounts (endpoint: `/api/v2/accounts`)
    - certificates (endpoint: `/api/v2/certificates`)
    - permissions (endpoint: `/api/v2/permissions`)
    - latest_rules (endpoint: `/api/v2/latest_rules`)
    - profiles (endpoint: `/api/v2/profiles`)
    - job_titles (endpoint: `/api/v2/job_titles`)
    - access_review_campaign_instances (endpoint: `/api/v2/access_review_campaign_instances`)
    - access_review_approval_items (endpoint: `/api/v2/access_review_approval_items`)

### Supported use cases

Integrating the Axonius Identity Datastream with Elastic SIEM provides a unified view of users, groups, roles, organizational units, accounts, permissions, certificates, profiles, and access review activity. Metrics and breakdowns help teams quickly assess identity posture by highlighting active, inactive, suspended, and external users, as well as patterns across user types and departments.

Tables showing top email addresses and cloud providers add context into frequently used identities and their sources. These insights help security and IAM teams detect identity anomalies, validate account hygiene, and maintain strong visibility into access across the organization.

### Supported use cases

Integrating the Axonius Adapter, User, Gateway, Exposure, Alert, Incident, Storage, Ticket, and Network data streams with Elastic SIEM provides centralized, end-to-end visibility across data ingestion, identity posture, network configuration, vulnerability exposure, security events, storage assets, ticketing, and network activity. Together, these data streams help analysts understand how data flows into the platform, how it maps to users and access, how gateways and network assets operate, where risks and exposures exist, and how alerts evolve into incidents and tracked issues.

The dashboards surface insights into integration health, connection behavior, user roles, routing context, vulnerability severity, alert and incident trends, storage distribution, ticket activity, and network asset posture. Network-specific views highlight protocols, device states, exposure levels, and communication paths, while ticket insights provide context on priorities, statuses, and workload patterns. By correlating operational, identity, exposure, incident, storage, ticket, and network data in one place, security teams can detect anomalies, identify misconfigurations, prioritize remediation, and streamline investigations with comprehensive, end-to-end context across the environment.

## What do I need to use this integration?

### From Elastic

This integration installs [Elastic latest transforms](https://www.elastic.co/docs/explore-analyze/transforms/transform-overview#latest-transform-overview). For more details, check the [Transform](https://www.elastic.co/docs/explore-analyze/transforms/transform-setup) setup and requirements.

### From Axonius

To collect data through the Axonius APIs, you need to provide the **URL**, **API Key** and **API Secret**. Authentication is handled using the **API Key** and **API Secret**, which serves as the required credential.

#### Retrieve URL, API Token and API Secret:

1. Log in to the **Axonius** instance.
2. Your instance URL is your Base **URL**.
3. Navigate to **User Settings > API Key**.
4. Generate an **API Key**.
5. If you do not see the API Key tab in your user settings, follow these steps:
    1.  Go to **System Settings** > **User and Role Management** > **Service Accounts**.
    2. Create a Service Account, and then generate an **API Key**.
6. Copy both values including **API Key and Secret Key** and store them securely for use in the Integration configuration.

**Note:**
To generate or reset an API key, your role must be **Admin**, and you must have **API Access** permissions, which include **API Access Enabled** and **Reset API Key**.

## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog or log file receiver and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Agentless deployment

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. Agentless deployments provide a means to ingest data while avoiding the orchestration, management, and maintenance needs associated with standard ingest infrastructure. Using an agentless deployment makes manual agent deployment unnecessary, allowing you to focus on your data instead of the agent that collects it.

For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html)

### Configure

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **Axonius**.
3. Select the **Axonius** integration from the search results.
4. Select **Add Axonius** to add the integration.
5. Enable and configure only the collection methods which you will use.

    * To **Collect logs from Axonius API**, you'll need to:

        - Configure **URL**, **API Key** and **API Secret**.
        - Adjust the integration configuration parameters if required, including the Interval, HTTP Client Timeout etc. to enable data collection.

6. Select **Save and continue** to save the integration.

### Validation

#### Dashboard populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **Axonius**, and verify the dashboard information is populated.

#### Transforms healthy

1. In the top search bar in Kibana, search for **Transforms**.
2. Select the **Data / Transforms** from the search results.
3. In the search bar, type **Axonius**.
4. All transforms from the search results should indicate **Healthy** under the **Health** column.

An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created for each data stream, to provide a view of the most recent, active Axonius data. Use the relevant destination alias from the table below to access the latest data, whether for use in dashboards, rules, or elsewhere.
Destinations indices are aliased to `logs-axonius_latest.<data_stream_name>`.

| Source Data stream                 | Destination Index Pattern                        | Destination Alias                       |
|:-----------------------------------|:-------------------------------------------------|-----------------------------------------|
| `logs-axonius.adapter-*`           | `logs-axonius_latest.dest_adapter-*`             | `logs-axonius_latest.adapter`           |
| `logs-axonius.alert_finding-*`     | `logs-axonius_latest.dest_alert_finding-*`       | `logs-axonius_latest.alert_finding`     |
| `logs-axonius.exposure-*`          | `logs-axonius_latest.dest_exposure-*`            | `logs-axonius_latest.exposure`          |
| `logs-axonius.gateway-*`           | `logs-axonius_latest.dest_gateway-*`             | `logs-axonius_latest.gateway`           |
| `logs-axonius.incident-*`          | `logs-axonius_latest.dest_incident-*`            | `logs-axonius_latest.incident`          |
| `logs-axonius.user-*`              | `logs-axonius_latest.dest_user-*`                | `logs-axonius_latest.user`              |
| `logs-axonius.storage-*`           | `logs-axonius_latest.dest_storage-*`             | `logs-axonius_latest.storage`           |
| `logs-axonius.ticket-*`            | `logs-axonius_latest.dest_ticket-*`              | `logs-axonius_latest.ticket`            |
| `logs-axonius.network-*`           | `logs-axonius_latest.dest_network-*`             | `logs-axonius_latest.network`           |
| `logs-axonius.identity-*`          | `logs-axonius_latest.dest_identity-*`            | `logs-axonius_latest.identity`          |


**Note:** Assets deleted from Axonius may reappear in a future discovery cycle if they are still present in connected data sources and get re-detected. Because the exact duration for which a deleted asset may remain dormant before being rediscovered is unknown, the transform retention period is set to **90 days** to reduce the risk of data loss for such assets. This means deleted assets will continue to appear in dashboards for up to 90 days after deletion.
The network and identity destination indices are a content-based deduplicated view, not an entity-level latest-state view like the other data streams (for example `user` and `gateway`), which rely on a unique entity identifier and reflect the latest state of each entity.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Adapter

The `adapter` data stream provides adapter logs from axonius.

#### adapter fields

{{ fields "adapter" }}

{{ event "adapter" }}

### User

The `user` data stream provides user events from axonius.

#### user fields

{{ fields "user" }}

{{ event "user" }}

### Gateway

The `gateway` data stream provides gateway events from axonius.

#### gateway fields

{{ fields "gateway" }}

{{ event "gateway" }}

### Exposure

The `exposure` data stream provides exposure logs from axonius.

#### exposure fields

{{ fields "exposure" }}

{{event "exposure"}}

### Alert Finding

The `alert_finding` data stream provides alert findings asset logs from axonius.

#### alert_finding fields

{{ fields "alert_finding" }}

{{event "alert_finding"}}

### Incident

The `incident` data stream provides incident asset logs from axonius.

#### incident fields

{{ fields "incident" }}

{{event "incident"}}

### Storage

The `storage` data stream provides storage asset logs from axonius.

#### storage fields

{{ fields "storage" }}

{{event "storage"}}

### Ticket

The `ticket` data stream provides ticket asset logs from axonius.

#### ticket fields

{{ fields "ticket" }}

{{event "ticket"}}

### Network

The `network` data stream provides network events from axonius.

#### network fields

{{ fields "network" }}

{{ event "network" }}

### Identity

The `identity` data stream provides identity asset logs from axonius.

#### identity fields

{{ fields "identity" }}

{{event "identity"}}

### Inputs used
{{/* All inputs used by this package will be automatically listed here. */}}
{{ inputDocs }}

### API usage

These APIs are used with this integration:

* Adapter (endpoint: `/api/v2/adapters`)
* User (endpoint: `/api/v2/users`)
* Gateway (endpoint: `/api/v2/gateway`)
* Exposure:
    * vulnerability_instances (endpoint: `/api/v2/vulnerability_instances`)
    * vulnerabilities (endpoint: `/api/v2/vulnerabilities`)
    * vulnerabilities_repository (endpoint: `/api/v2/vulnerabilities_repository`)
* Alert Findings:
    * alert_findings (endpoint: `/api/v2/alert_findings`)
* Incidents:
    * incidents (endpoint: `/api/v2/incidents`)
* Storage:
    * object_storages (endpoint: `/api/v2/object_storages`)
    * file_systems (endpoint: `/api/v2/file_systems`)
    * disks (endpoint: `/api/v2/disks`)
* Ticket:
    * tickets (endpoint: `/api/v2/tickets`)
    * cases (endpoint: `/api/v2/cases`)
* Network
    * networks (endpoint: `/api/v2/networks`)
    * load_balancers (endpoint: `/api/v2/load_balancers`)
    * network_services (endpoint: `/api/v2/network_services`)
    * network_devices (endpoint: `/api/v2/network_devices`)
    * firewalls (endpoint: `/api/v2/firewalls`)
    * nat_rules (endpoint: `/api/v2/nat_rules`)
    * network_routes (endpoint: `/api/v2/network_routes`)
* Identity:
    * users (endpoint: `/api/v2/users`)
    * groups (endpoint: `/api/v2/groups`)
    * security_roles (endpoint: `/api/v2/security_roles`)
    * organizational_units (endpoint: `/api/v2/organizational_units`)
    * accounts (endpoint: `/api/v2/accounts`)
    * certificates (endpoint: `/api/v2/certificates`)
    * permissions (endpoint: `/api/v2/permissions`)
    * latest_rules (endpoint: `/api/v2/latest_rules`)
    * profiles (endpoint: `/api/v2/profiles`)
    * job_titles (endpoint: `/api/v2/job_titles`)
    * access_review_campaign_instances (endpoint: `/api/v2/access_review_campaign_instances`)
    * access_review_approval_items (endpoint: `/api/v2/access_review_approval_items`)

### ILM Policy

To facilitate adapter, user, gateway and assets data including exposures, alert findings, incidents, storage and ticket, network and identity source data stream-backed indices `.ds-logs-axonius.adapter-*`, `.ds-logs-axonius.user-*`, `.ds-logs-axonius.gateway-*`, `.ds-logs-axonius.exposure-*`, `.ds-logs-axonius.alert_finding-*`, `.ds-logs-axonius.incident-*`, `.ds-logs-axonius.storage-*`, `.ds-logs-axonius.ticket-*`, `.ds-logs-axonius.network-*` and `.ds-logs-axonius.identity-*` respectively are allowed to contain duplicates from each polling interval. ILM policies `logs-axonius.adapter-default_policy`, `logs-axonius.user-default_policy`, `logs-axonius.gateway-default_policy`, `logs-axonius.exposure-default_policy`,  `logs-axonius.alert_finding-default_policy`, `logs-axonius.incident-default_policy`, `logs-axonius.storage-default_policy`, `logs-axonius.ticket-default_policy`, `logs-axonius.network-default_policy` and `logs-axonius.identity-default_policy` are added to these source indices, so it doesn't lead to unbounded growth. This means that in these source indices data will be deleted after `30 days` from ingested date.
