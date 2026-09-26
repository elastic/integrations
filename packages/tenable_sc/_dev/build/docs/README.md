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