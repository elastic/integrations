# Tenable Vulnerability Management

## Overview

The [Tenable Vulnerability Management](https://www.tenable.com/products/tenable-io) integration allows users to monitor asset, audit, plugin, scan and vulnerability activity. It provides the industry's most comprehensive vulnerability coverage with the ability to predict which security issues to remediate first. Tenable Vulnerability Management is the user's complete end-to-end vulnerability management solution.

Use the Tenable Vulnerability Management integration to collects and parses data from the REST APIs. Then visualize that data in Kibana.

## Data streams

The Tenable Vulnerability Management integration collects logs for five types of events: Asset, Audit, Plugin, Scan, and Vulnerability.

**Asset** is used to get details related to assets that belong to the user's organization. See more details in the API documentation [here](https://developer.tenable.com/reference/exports-assets-request-export).

**Audit** is used to obtain details about when each activity occurred, the actions taken, the individuals involved, and other relevant information. See more details in the API documentation [here](https://developer.tenable.com/reference/audit-log-events).

**Plugin** is used to get detailed plugin information. See more details in the API documentation [here](https://developer.tenable.com/reference/io-plugins-list).

**Vulnerability** is used to retrieve all vulnerabilities on each asset, including the vulnerability state. See more details in the API documentation [here](https://developer.tenable.com/reference/exports-vulns-request-export).

**Scan** is used to retrieve details about existing scans, including scan statuses, assigned targets, and more. See more details in the API documentation [here](https://developer.tenable.com/reference/scans-list).

## Compatibility

This module has been tested against `Tenable Vulnerability Management release` [December 6, 2022](https://docs.tenable.com/releasenotes/Content/tenableio/tenableio202212.htm).

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

**Notes:**
  - In this integration, export and plugin endpoints of vulnerability management are used to fetch data.
  - The default value is the recommended value for a batch size by Tenable. Using a smaller batch size can improve performance. A very large value might not work as intended depending on the API and instance limitations.
  - If any long-running export jobs are stuck in the "PROCESSING" state and reach the user-provided timeout, the export job will be terminated, allowing for the initiation of a new export job after the specified interval.

## Agentless enabled integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

## Setup

### Collect data from the Tenable Vulnerability Management REST APIs

1. Create a valid user account with appropriate permissions on Tenable Vulnerability Management.
2. Generate the API keys for the account to access all Tenable Vulnerability Management APIs.

**Note:**
  - For the Tenable Vulnerability Management asset and vulnerability API, **ADMINISTRATOR [64]** and **Can View** access control is required in  created user's access key and secret key.
  - For the Tenable Vulnerability Management plugin, **BASIC [16]** user permissions are required in created user's access key and secret key.
  - For the Tenable Vulnerability Management audit, **ADMINISTRATOR [64]** user permissions are required in created user's access key and secret key.
  - For more details related to permissions, refer to the link [here](https://developer.tenable.com/docs/permissions).

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search top bar, type **Tenable Vulnerability Management**.
3. Select the **Tenable Vulnerability Management** integration and add it.
4. Add all the required integration configuration parameters according to the enabled input type.
5. Save the integration.

## Logs reference

### asset

This is the `asset` dataset.

#### Example

{{event "asset"}}

{{fields "asset"}}

### audit

This is the `audit` dataset.

#### Example

{{event "audit"}}

{{fields "audit"}}

### plugin

This is the `plugin` dataset.

#### Example

{{event "plugin"}}

{{fields "plugin"}}

### vulnerability

This is the `vulnerability` dataset.

#### Example

{{event "vulnerability"}}

{{fields "vulnerability"}}

### scan

This is the `scan` dataset.

#### Example

{{event "scan"}}

{{fields "scan"}}
