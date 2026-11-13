# Tenable.sc

The Tenable Security Center integration collects and parses data from the [Tenable Security Center](https://docs.tenable.com/tenablesc/Content/Welcome.htm) APIs.

## Elastic Managed enabled integration

Elastic Managed integrations are only supported on Elastic Cloud Serverless and Elastic Cloud Hosted deployments. An Elastic Managed integration lets you ingest data from a cloud source while avoiding the orchestration, management, and maintenance associated with standard ingest infrastructure. Elastic runs the collector for you, so you can focus on your data instead of the infrastructure that collects it.

For more information, refer to [Elastic Managed integrations](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations) and the [Elastic Managed integrations FAQ](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations-faq).

## Compatibility

This module has been tested against `Tenable.sc version 5.23` and `Tenable.sc version 6.4.0`.

## Requirements

In order to ingest data from the Tenable.sc you must have the **Access key** and **Secret Key**.

Enable API keys to allow users to perform API key authentication. 

See Tenable's documentation for more information on: 

* [Enabling API Key Authentication](https://docs.tenable.com/tenablesc/Content/EnableAPIKeys.htm) 
* [Generating API keys]( https://docs.tenable.com/tenablesc/Content/GenerateAPIKey.htm)

>  Note: The default value is the recommended value for a batch size by Tenable. It can be found under _Advanced Options_ and can be configured as per requirements. A very large value might not work as intended depending on the API and instance limitations.

## Breaking Changes

### Support for Elastic Vulnerability Findings page

Version `3.0.0` of the Tenable Security Center integration adds support for the [Elastic Cloud Security workflow](https://www.elastic.co/docs/solutions/security/cloud/ingest-third-party-cloud-security-data#_ingest_third_party_security_posture_and_vulnerability_data). Vulnerabilities collected from Tenable Security Center are shown on the Elastic [Vulnerability Findings page](https://www.elastic.co/docs/solutions/security/cloud/findings-page-3) and in the vulnerability insights of the Alert and Entity details flyouts for the affected host.

This update adds an [Elastic Latest Transform](https://www.elastic.co/docs/explore-analyze/transforms/transform-overview#latest-transform-overview) which copies the latest vulnerability findings from source indices matching the pattern `logs-tenable_sc.vulnerability-*` into new destination indices matching the pattern `security_solution-tenable_sc.vulnerability_latest-*`. The Elastic Vulnerability Findings page displays vulnerabilities based on the destination indices. The transform keeps the latest copy of each vulnerability finding per asset, and removes findings that were last seen more than 90 days ago.

For existing users of the Tenable Security Center integration, before upgrading to `3.0.0`, ensure the following requirements are met:

1. Users need [Elastic Security solution](https://www.elastic.co/docs/solutions/security) which has requirements documented [here](https://www.elastic.co/docs/solutions/security/get-started/elastic-security-requirements).
2. To use transforms, users must have:
   - at least one [transform node](https://www.elastic.co/docs/deploy-manage/distributed-architecture/clusters-nodes-shards/node-roles#transform-node-role),
   - management features visible in the Kibana space, and
   - security privileges that:
     - grant use of transforms, and
     - grant access to source and destination indices
   For more details on Transform Setup, refer to the link [here](https://www.elastic.co/docs/explore-analyze/transforms/transform-setup)
3. Because the latest copy of vulnerabilities is now indexed in two places, that is, in both source and destination indices, users must anticipate storage requirements accordingly.

The vulnerability data stream collects vulnerabilities incrementally, requesting only vulnerabilities that were last seen after the previous poll. **Initial Interval** only applies to the first poll of a new integration. To populate the Vulnerability Findings page with vulnerabilities that were last seen before the integration was added, set **Initial Interval** to `2160h` (90 days) when adding the integration. Changing **Initial Interval** on an existing integration has no effect, because collection continues from the last poll. To populate the page for an existing integration after the upgrade, remove the integration and add it again with **Initial Interval** set to `2160h`. Vulnerabilities that were already collected may be indexed again in the source indices, but the latest index keeps one copy of each vulnerability.

Informational vulnerabilities are collected, but are not shown on the Vulnerability Findings page.

Vulnerabilities that Tenable Security Center moves out of its cumulative database, for example after they are mitigated, are no longer collected. Until collection of mitigated vulnerabilities is added, a mitigated vulnerability is still shown as open on the Vulnerability Findings page until it was last seen more than 90 days ago.

## Logs

### Asset

This is the `asset` dataset.

Asset documents use a stable `tenable_sc.asset.custom_hash` (computed in the asset ingest pipeline from the export field values named in the Tenable export property `uniqueness`, stored as `tenable_sc.asset.uniqueness`) and an ingest `_id` derived from that identity, mutable scan state (scores, severity counts, MAC address, policy, plugin set, and scan timestamps), and the collection day. The asset input requests only assets whose Tenable `lastSeen` time falls after the previous poll, so an asset is indexed again only when Tenable reports it again. Repeat reports on the same day with unchanged state deduplicate on `_id`. A change in scan state indexes a new document. A later Tenable report on a new collection day also indexes a new document, even if the scan state has not changed. The package installs a [latest transform](https://www.elastic.co/docs/explore-analyze/transforms/transform-overview#latest-transform-overview) that copies the newest document per asset into `logs-tenable_sc_latest.asset`, keyed on `tenable_sc.asset.custom_hash` and `data_stream.namespace`. The latest index removes a document when its `@timestamp` is older than 90 days, so assets that Tenable has not reported for 90 days drop out of `logs-tenable_sc_latest.asset`.

Upgrading to version `2.6.0` or later installs and starts this transform. Clusters need a [transform node](https://www.elastic.co/docs/deploy-manage/distributed-architecture/clusters-nodes-shards/node-roles#transform-node-role), transform privileges, and access to source and destination indices. Asset data is stored in both the source data stream and the latest destination index; plan storage accordingly. See [Transform setup](https://www.elastic.co/docs/explore-analyze/transforms/transform-setup) for details.

{{event "asset"}}

{{fields "asset"}}

### Plugin

This is the `plugin` dataset.

{{event "plugin"}}

{{fields "plugin"}}

### Vulnerability

This is the `vulnerability` dataset.

{{event "vulnerability"}}

{{fields "vulnerability"}}