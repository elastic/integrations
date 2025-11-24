# Tenable.sc

The Tenable Security Center integration collects and parses data from the [Tenable Security Center](https://docs.tenable.com/tenablesc/Content/Welcome.htm) APIs.

## Agentless Enabled Integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).
Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

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