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

An example event for `feed_entry` looks as following:

```json
{
    "@timestamp": "2025-05-05T22:15:10.510Z",
    "agent": {
        "ephemeral_id": "36c14525-764a-45b6-a98a-a5a715feef13",
        "id": "68cff31f-e9c8-4b25-a95f-3790734acbd9",
        "name": "elastic-agent-12943",
        "type": "filebeat",
        "version": "8.18.0"
    },
    "data_stream": {
        "dataset": "miniflux.feed_entry",
        "namespace": "26056",
        "type": "logs"
    },
    "ecs": {
        "version": "8.16.0"
    },
    "elastic_agent": {
        "id": "68cff31f-e9c8-4b25-a95f-3790734acbd9",
        "snapshot": false,
        "version": "8.18.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "vulnerability"
        ],
        "dataset": "miniflux.feed_entry",
        "ingested": "2025-05-05T22:15:12Z",
        "kind": "alert",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "miniflux": {
        "author": "",
        "changed_at": "2023-09-02T20:30:13.118Z",
        "comments_url": "",
        "content": "<p></p>\n\n<h1>Exploit for Code Injection in Vmware Spring Framework CVE-2022-22965</h1>\n<p>2023-09-02 | CVSS 7.5 </p>\n\n\n\n\n\nCopy\nDownload\nSource\n<a href=\"#share-url\">Share</a>\n\n<pre><code>## https://sploitus.com/exploit?id=5C9561BE-D9BB-58D0-8E51-09DDD257BC72\n# Spring4Shell: CVE-2022-22965 RCE\n\n## Java Spring framework RCE vulnerability\nThese vulnerabilities affects a component &#34;Spring Core&#34; —  the heart of the framework \n\n**Current conditions for vulnerability:-**\n\n- JDK 9+\n- A vulnerable version of the Spring Framework (&lt;5.2 | 5.2.0-19 | 5.3.0-17)\n- Apache Tomcat as a server for the Spring application, packaged as a WAR\n- A dependency on the spring-webmvc and/or spring-webflux components of the Spring Framework\n\n## The exploit\n\n```python\nuser@attacker:~$ ./exploit.py --help\nusage: exploit.py [-h] [-f FILENAME] [-p PASSWORD] [-d DIRECTORY] url\n\nSpring4Shell RCE Proof of Concept\n\npositional arguments:\n  url                   Target URL\n\noptional arguments:\n  -h, --help            show this help message and exit\n  -f FILENAME, --filename FILENAME\n                        Name of the file to upload (Default tomcatwar.jsp)\n  -p PASSWORD, --password PASSWORD\n                        Password to protect the shell with (Default: thm)\n  -d DIRECTORY, --directory DIRECTORY\n                        The upload path for the file (Default: ROOT)\n```\n\n```python\nuser@attacker:~$ ./exploit.py http://MACHINE_IP/\nShell Uploaded Successfully!\n\n\n# OUTPUT= Your shell can be found at: http://MACHINE_IP/tomcatwar.jsp?pwd=thm&amp;cmd=whoami\n```</code> </pre>\n\n",
        "created_at": "2023-09-02T20:17:02.689Z",
        "enclosures": [],
        "feed": {
            "allow_self_signed_certificates": false,
            "apprise_service_urls": "",
            "blocklist_rules": "",
            "category": {
                "hide_globally": false,
                "id": 25000,
                "title": "2-Production",
                "user_id": 4426
            },
            "checked_at": "2025-05-02T12:25:58.524Z",
            "cookie": "",
            "crawler": true,
            "description": "",
            "disable_http2": false,
            "disabled": false,
            "etag_header": "",
            "feed_url": "https://sploitus.com/rss",
            "fetch_via_proxy": false,
            "hide_globally": false,
            "icon": {
                "external_icon_id": "dadd95d716e12dbdc58fabdd0f38f48e8d7eab88",
                "feed_id": 355593,
                "icon_id": 60476
            },
            "id": 355593,
            "ignore_http_cache": false,
            "keeplist_rules": "",
            "last_modified_header": "",
            "next_check_at": "0001-01-01T00:00:00.000Z",
            "no_media_player": false,
            "ntfy_enabled": false,
            "ntfy_priority": 0,
            "ntfy_topic": "",
            "parsing_error_count": 0,
            "parsing_error_message": "",
            "password": "",
            "proxy_url": "",
            "pushover_enabled": false,
            "pushover_priority": 0,
            "rewrite_rules": "",
            "scraper_rules": "",
            "site_url": "https://sploitus.com/rss",
            "title": "Sploitus.com Exploits RSS Feed",
            "urlrewrite_rules": "",
            "user_agent": "",
            "user_id": 4426,
            "username": "",
            "webhook_url": ""
        },
        "feed_id": 355593,
        "hash": "fab2dc0ad7ba85e40595d197da245cb2602ce93c6a2c2deca340ce909c9a4a13",
        "id": 83721716,
        "published_at": "2023-09-02T10:41:05.000Z",
        "reading_time": 1,
        "share_code": "",
        "starred": true,
        "status": "read",
        "tags": [],
        "title": "Exploit for Code Injection in Vmware Spring Framework exploit",
        "url": "https://sploitus.com/exploit?id=5C9561BE-D9BB-58D0-8E51-09DDD257BC72&utm_source=rss&utm_medium=rss",
        "user_id": 4426
    },
    "tags": [
        "forwarded"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
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
| miniflux.feed_entry_split |  | keyword |
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


