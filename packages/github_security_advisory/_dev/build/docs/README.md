# GitHub Security Advisory integration

## Overview

The [GitHub Security Advisory](https://github.com/advisories) integration allows you to extract data from the GitHub Security Advisory database. 

Use the GitHub Security Advisory integration to extract reviewed, unreviewed or malware security advisories. Then visualize that data in Kibana, create alerts to notify you on some specifics conditions.

For example, if you wanted to be notified for a new security advisory with a CVSS score higher than 9.0, you could set up an alert. 

## Datastreams

This integration collects the following logs:

- **[Security Advisories](https://docs.github.com/en/rest/security-advisories/global-advisories?apiVersion=2022-11-28)** - Retrieves security advisories from the GitHub REST API. 

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Each data stream collects different kinds of logs data, which may require dedicated permissions to be fetched and may vary across operating systems. Details on the permissions needed for each data stream are available in the Logs reference.

## Setup

Before sending logs to Elastic from your Miniflux application (self-hosted or SaaS), you must create a GitHub Personall Access Token (PAT) by following [GitHub's documentation](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)

After you've configured your device, you can set up the Elastic integration.

## Logs

### Vulnerability

This is the `vulnerability` dataset.

{{event "vulnerability"}}

{{fields "vulnerability"}}

