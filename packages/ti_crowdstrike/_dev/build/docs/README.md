# CrowdStrike Falcon Intelligence

CrowdStrike Falcon Intelligence is a threat intelligence product that provides advanced cybersecurity insights to organizations. Leveraging machine learning and behavioural analytics, Falcon Intelligence delivers real-time threat data, enabling proactive threat detection and response. With a focus on actionable intelligence, it empowers businesses to stay ahead of cyber adversaries and enhance their overall security posture. This [CrowdStrike Falcon Intelligence](https://www.crowdstrike.com/en-us/) integration enables you to consume and analyze CrowdStrike Falcon Intelligence data within Elastic Security, including Intel Indicator and IOCs, providing you with visibility and context for your cloud environments within Elastic Security.

## Data streams

The CrowdStrike Falcon Intelligence integration collects two types of data: IOC and Intel Indicator.

Both the endpoints are related to the threat intelligence. Intel Indicators provide information about a hash, particularly related to malware and threat types, while IOC provides information about the detection of an IPv4 address, including severity, platforms, and global application status.

Reference for CrowdStrike Falcon Intelligence APIs - https://falcon.crowdstrike.com/documentation/page/a2a7fc0e/crowdstrike-oauth2-based-apis. -> Go to the Accessing CrowdStrike API specification and find the API reference link for your cloud environment region.

NOTE: Your Base URL depends on your cloud environment region.
For example, the US-2 cloud environment will have the base URL as https://falcon.us-2.crowdstrike.com.

## Compatibility

This module has been tested against the **CrowdStrike Falcon Intelligence API Version v1**.

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

### Permissions

This integration includes assets such as latest transform which requires users installing the integration to have `kibana_system` built-in role. Follow the [documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/built-in-roles.html) for information on `kibana_system` built-in role.

## Setup

To collect data from CrowdStrike Falcon Intelligence, the following parameters from your CrowdStrike Falcon Intelligence instance are required:

1. Client ID
2. Client Secret
3. Token url
4. API Endpoint url
5. Required scopes for each data stream :

    | Data Stream   | Scope                 |
    | ------------- | --------------------- |
    | Intel         | read:intel            |
    | IOC           | read:iocs             |
    |               | read:ioc-management   |

Follow the [documentation](https://www.crowdstrike.com/blog/tech-center/consume-ioc-and-threat-feeds/) for enabling the scopes from the CrowdStrike console.

User should either have `admin` role or `Detection Exception Manager` role to access IOCs endpoint. Follow the [documentation](https://falcon.crowdstrike.com/documentation/page/f20650df/default-roles-reference) for managing user roles and permissions.

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search top bar, type **CrowdStrike Falcon Intelligence**.
3. Select the **CrowdStrike Falcon Intelligence** integration and add it.
4. Add all the required integration configuration parameters, such as Client ID, Client Secret, URL, and Token URL. For all data streams, these parameters must be provided in order to retrieve logs.
5. Save the integration.

## IoCs expiration

The ingested IOCs expire after a certain duration. A separate [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created for Intel and IOC datasets to facilitate only active Indicators and IOCs, respectively, being available to the end users. Since we want to retain only valuable information and avoid duplicated data, the CrowdStrike Falcon Intelligence Elastic integration forces the intel indicators to rotate into a custom index called: `logs-ti_crowdstrike_latest.dest_intel` and forces the IOC logs to rotate into a custom index called: `logs-ti_crowdstrike_latest.dest_ioc`.
**Please, refer to this index in order to set alerts and so on.**

### Transform permissions

The latest transforms for both Intel and IOC datasets require users to have `kibana_system` role as noted in [permissions](https://www.elastic.co/docs/current/integrations/ti_crowdstrike#permissions).

### Handling Orphaned IOCs

IOC expiration is set default to false in CrowdStrike console but user can set the expiration duration in using the admin console. Some CrowdStrike IOCs may never expire and will continue to stay in the latest destination index. To avoid any false positives from such orphaned IOCs, users are allowed to configure `IOC Expiration Duration` parameter for both the dataset Intel and IOC, respectively, while setting up the integration. This parameter deletes all data inside the destination index `logs-ti_crowdstrike_latest.intel` and `logs-ti_crowdstrike_latest.ioc` after this specified duration is reached. Users must pull entire feed instead of incremental feed when this expiration happens so that the IOCs get reset.

### How it works

This is possible thanks to a transform rule installed along with the integration. The transform rule parses the data stream content that is pulled from CrowdStrike Falcon Intelligence and only adds new intel indicators.

Both the data stream and the latest index have applied expiration through ILM and a retention policy in the transform respectively.

## Logs reference

### Intel

This is the `Intel` dataset.

#### Example

{{event "intel"}}

{{fields "intel"}}

### IOC

This is the `IOC` dataset.

#### Example

{{event "ioc"}}

{{fields "ioc"}}
