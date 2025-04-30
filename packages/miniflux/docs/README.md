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

<!-- ## Troubleshooting (optional)

Provide information about special cases and exceptions that aren’t necessary for getting started or won’t be applicable to all users. Check the [troubleshooting guidelines](https://www.elastic.co/guide/en/integrations-developer/current/documentation-guidelines.html#idg-docs-guidelines-troubleshooting) for more information. -->

<!-- ## Reference

Provide detailed information about the log or metric types we support within the integration. Check the [reference guidelines](https://www.elastic.co/guide/en/integrations-developer/current/documentation-guidelines.html#idg-docs-guidelines-reference) for more information. -->

## Logs

### Feed Entry

This is the `feed_entry` dataset.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| miniflux.author | Author of the feed entry | keyword |
| miniflux.changed_at |  | date |
| miniflux.comments_url |  | keyword |
| miniflux.content |  | keyword |
| miniflux.created_at |  | date |
| miniflux.enclosures |  | keyword |
| miniflux.feed.allow_self_signed_certificates |  | boolean |
| miniflux.feed.apprise_service_urls |  | boolean |
| miniflux.feed.blocklist_rules |  | keyword |
| miniflux.feed.category.hide_globally |  | boolean |
| miniflux.feed.category.id |  | long |
| miniflux.feed.category.title |  | keyword |
| miniflux.feed.category.user_id |  | long |
| miniflux.feed.checked_at |  | date |
| miniflux.feed.cookie |  | keyword |
| miniflux.feed.crawler |  | boolean |
| miniflux.feed.description |  | keyword |
| miniflux.feed.disable_http2 |  | boolean |
| miniflux.feed.disabled |  | boolean |
| miniflux.feed.etag_header |  | keyword |
| miniflux.feed.feed_url |  | keyword |
| miniflux.feed.fetch_via_proxy |  | boolean |
| miniflux.feed.hide_globally |  | boolean |
| miniflux.feed.icon.external_icon_id |  | keyword |
| miniflux.feed.icon.feed_id |  | long |
| miniflux.feed.icon.icon_id |  | long |
| miniflux.feed.id |  | long |
| miniflux.feed.ignore_http_cache |  | boolean |
| miniflux.feed.keeplist_rules |  | keyword |
| miniflux.feed.last_modified_header |  | keyword |
| miniflux.feed.next_check_at |  | date |
| miniflux.feed.no_media_player |  | boolean |
| miniflux.feed.ntfy_enabled |  | boolean |
| miniflux.feed.ntfy_priority |  | integer |
| miniflux.feed.ntfy_topic |  | keyword |
| miniflux.feed.parsing_error_count |  | integer |
| miniflux.feed.parsing_error_message |  | keyword |
| miniflux.feed.password |  | keyword |
| miniflux.feed.proxy_url |  | keyword |
| miniflux.feed.pushover_enabled |  | boolean |
| miniflux.feed.pushover_priority |  | integer |
| miniflux.feed.rewrite_rules |  | keyword |
| miniflux.feed.scraper_rules |  | keyword |
| miniflux.feed.site_url |  | keyword |
| miniflux.feed.title |  | keyword |
| miniflux.feed.urlrewrite_rules |  | keyword |
| miniflux.feed.user_agent |  | keyword |
| miniflux.feed.user_id |  | long |
| miniflux.feed.username |  | keyword |
| miniflux.feed.webhook_url |  | keyword |
| miniflux.feed_id |  | long |
| miniflux.hash |  | keyword |
| miniflux.id |  | long |
| miniflux.published_at |  | date |
| miniflux.reading_time |  | integer |
| miniflux.share_code |  | keyword |
| miniflux.starred |  | boolean |
| miniflux.status |  | keyword |
| miniflux.tags |  | keyword |
| miniflux.title |  | keyword |
| miniflux.url |  | keyword |
| miniflux.user_id |  | long |


