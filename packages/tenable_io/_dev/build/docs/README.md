# Tenable.io

## Overview

The [Tenable.io](https://www.tenable.com/products/tenable-io) integration allows users to monitor asset, plugin, and vulnerability activity. It provides the industry's most comprehensive vulnerability coverage with the ability to predict which security issues to remediate first. Tenable.io is the user's complete end-to-end vulnerability management solution.

Use the Tenable.io integration to collects and parses data from the REST APIs. Then visualize that data in Kibana.

## Data streams

The Tenable.io integration collects logs for three types of events: Asset, Plugin, and Vulnerability.

**Asset** is used to get details related to assets that belong to the user's organization. See more details in the API documentation [here](https://developer.tenable.com/reference/exports-assets-request-export).

**Plugin** is used to get detailed plugin information. See more details in the API documentation [here](https://developer.tenable.com/reference/io-plugins-list).

**Vulnerability** is used to retrieve all vulnerabilities on each asset, including the vulnerability state. See more details in the API documentation [here](https://developer.tenable.com/reference/exports-vulns-request-export).

**Scanners** is used to retrieve the current state of scanners, including licensing and activity. See more details in the API documentation [here](https://developer.tenable.com/reference/scanners-list).

## Compatibility

This module has been tested against `Tenable.io release` [December 6, 2022](https://docs.tenable.com/releasenotes/Content/tenableio/tenableio202212.htm).

## Requirements

Elasticsearch is needed to store and search data, and Kibana is needed for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your hardware.

**Note:**
  - In this integration, export and plugin endpoints of vulnerability management are used to fetch data.
  - The default value is the recommended value for a batch size by Tenable. Using a smaller batch size can improve performance. A very large value might not work as intended depending on the API and instance limitations.
  - If you have a large amount of data and are having trouble with data ingestion in the integration package, you can try to increase the `Max Retries` and `Min Wait Time` parameter.

## Setup

### To collect data from the Tenable.io REST APIs, follow the below steps:

  1. Create a valid user account with appropriate permissions on Tenable.io.
  2. Generate the API keys for the account to access all Tenable.io APIs.

**Note:**
  - For the Tenable.io asset and vulnerability API, **ADMINISTRATOR [64]** and **Can View** access control is required in  created user's access key and secret key.
  - For the Tenable.io plugin, **BASIC [16]** user permissions are required in created user's access key and secret key.
  - For more details related to permissions, refer to the link [here](https://developer.tenable.com/docs/permissions).

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

### scanner

This is the `scanner` dataset.

#### Example

{{event "scanner"}}

{{fields "scanner"}}
