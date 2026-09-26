# Miniflux integration

## Overview

The [Miniflux](https://miniflux.app/) integration allows you to extract data from Miniflux. Miniflux is an RSS feed reader.

Use the Miniflux integration to extract RSS feed content. Then visualize that data in Kibana, create alerts to notify you if something goes wrong.

For example, if you wanted to be notified for a new feed entry you could set up an alert. 

## Elastic Managed enabled integration

Elastic Managed integrations are only supported on Elastic Cloud Serverless and Elastic Cloud Hosted deployments. An Elastic Managed integration lets you ingest data from a cloud source while avoiding the orchestration, management, and maintenance associated with standard ingest infrastructure. Elastic runs the collector for you, so you can focus on your data instead of the infrastructure that collects it.

For more information, refer to [Elastic Managed integrations](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations) and the [Elastic Managed integrations FAQ](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations-faq).

## Datastreams

This integration collects the following logs:

- **[Entries](https://miniflux.app/docs/api.html#endpoint-get-entries)** - Retrieves feed entries from the Miniflux application.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Each data stream collects different kinds of logs data, which may require dedicated permissions to be fetched and may vary across operating systems. Details on the permissions needed for each data stream are available in the Logs reference.

## Setup

Before sending logs to Elastic from your Miniflux application (self-hosted or SaaS), you must create a Miniflux API key by following [Miniflux's documentation](https://miniflux.app/docs/api.html#authentication)

After you've configured your device, you can set up the Elastic integration.

## Logs

### Feed Entry

This is the `feed_entry` dataset.

{{event "feed_entry"}}

{{fields "feed_entry"}}

