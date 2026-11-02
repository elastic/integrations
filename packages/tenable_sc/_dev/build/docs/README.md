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