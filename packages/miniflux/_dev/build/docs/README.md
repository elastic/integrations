# Miniflux integration

## Overview

The Miniflux integration allows you to extract data from Miniflux. Miniflux is an RSS feed reader.

Use the Miniflux integration to extract RSS feed content. Then visualize that data in Kibana, create alerts to notify you if something goes wrong.

For example, if you wanted to be notified for a new feed entry you could set up an alert. 

## Datastreams

The Minifux integration collects one type of data streams: logs.

**Logs** help you extract feed entries from Miniflux API.
Log data streams collected by the Miniflux integration include feed_entry. See more details in the Logs reference.

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

