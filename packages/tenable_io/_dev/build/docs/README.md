# Tenable Vulnerability Management

## Overview

The [Tenable Vulnerability Management](https://www.tenable.com/products/tenable-io) integration allows users to monitor asset, plugin, scan and vulnerability activity. It provides the industry's most comprehensive vulnerability coverage with the ability to predict which security issues to remediate first. Tenable Vulnerability Management is the user's complete end-to-end vulnerability management solution.

Use the Tenable Vulnerability Management integration to collects and parses data from the REST APIs. Then visualize that data in Kibana.

## Data streams

The Tenable Vulnerability Management integration collects logs for four types of events: Asset, Plugin, Scan, and Vulnerability.

**Asset** is used to get details related to assets that belong to the user's organization. See more details in the API documentation [here](https://developer.tenable.com/reference/exports-assets-request-export).

**Plugin** is used to get detailed plugin information. See more details in the API documentation [here](https://developer.tenable.com/reference/io-plugins-list).

**Vulnerability** is used to retrieve all vulnerabilities on each asset, including the vulnerability state. See more details in the API documentation [here](https://developer.tenable.com/reference/exports-vulns-request-export).

**Scan** is used to retrieve details about existing scans, including scan statuses, assigned targets, and more. See more details in the API documentation [here](https://developer.tenable.com/reference/scans-list).

## Compatibility

This module has been tested against `Tenable Vulnerability Management release` [December 6, 2022](https://docs.tenable.com/releasenotes/Content/tenableio/tenableio202212.htm).

## Requirements

- Elastic Agent must be installed.
- You can install only one Elastic Agent per host.
- Elastic Agent is required to stream data through the REST API and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

The minimum **kibana.version** required is **8.12.0**.

**Note:**
  - In this integration, export and plugin endpoints of vulnerability management are used to fetch data.
  - The default value is the recommended value for a batch size by Tenable. Using a smaller batch size can improve performance. A very large value might not work as intended depending on the API and instance limitations.
  - If any long-running export jobs are stuck in the "PROCESSING" state and reach the user-provided timeout, the export job will be terminated, allowing for the initiation of a new export job after the specified interval.

## Setup

### To collect data from the Tenable Vulnerability Management REST APIs, follow the below steps:

  1. Create a valid user account with appropriate permissions on Tenable Vulnerability Management.
  2. Generate the API keys for the account to access all Tenable Vulnerability Management APIs.

**Note:**
  - For the Tenable Vulnerability Management asset and vulnerability API, **ADMINISTRATOR [64]** and **Can View** access control is required in  created user's access key and secret key.
  - For the Tenable Vulnerability Management plugin, **BASIC [16]** user permissions are required in created user's access key and secret key.
  - For more details related to permissions, refer to the link [here](https://developer.tenable.com/docs/permissions).

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations
2. In "Search for integrations" search bar, type Tenable Vulnerability Management.
3. Click on the "Tenable Vulnerability Management" integration from the search results.
4. Click on the "Add Tenable Vulnerability Management" button to add the integration.
5. Add all the required integration configuration parameters according to the enabled input type.
6. Click on "Save and Continue" to save the integration.

## Logs reference

### asset

This is the `asset` dataset.

#### Example

{{event "asset"}}

{{fields "asset"}}

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
