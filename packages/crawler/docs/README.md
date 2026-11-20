# Elastic Web Crawler

The Elastic Web Crawler integration runs the [Elastic Open Web Crawler](https://github.com/elastic/crawler) as an Elastic-managed (agentless) integration. It discovers pages starting from the configured domains, extracts their content and indexes it into an Elasticsearch index that you can search with your own applications.

This integration is a technical preview.

## Requirements

- An Elasticsearch deployment or Serverless project where agentless integrations are available.
- An index to write the crawled documents to. The crawler creates it when it does not exist.

## Configuration

| Setting | Description |
|---|---|
| Index name | The Elasticsearch index that receives the crawled documents. |
| Elasticsearch API key | API key the crawler uses to write to the index. Kibana creates a key scoped to the index when it sets up an Elastic managed crawler; the credentials of the agent's Elasticsearch output do not grant access to arbitrary indices. |
| Domains | The websites to crawl. Each domain can define seed URLs, sitemap URLs, crawl rules, extraction rules and authentication, using the same format as the crawler configuration file. |
| Crawl schedule | A cron expression that starts a crawl periodically. Without a schedule, crawls are started on demand from Kibana. |
| Maximum crawl depth | How many links deep the crawler follows from the seed URLs. |
| Advanced settings | Any other crawler setting, for example content size limits or thread counts. |

Example `Domains` value:

```yaml
- url: https://www.elastic.co
  seed_urls:
    - https://www.elastic.co/search-labs
  crawl_rules:
    - policy: deny
      type: begins
      pattern: /blog/archive
```

See the [crawler configuration reference](https://github.com/elastic/crawler/blob/main/docs/CONFIG.md) for all settings and the [Elastic Agent documentation](https://github.com/elastic/crawler/blob/main/docs/features/ELASTIC_AGENT.md) for how the crawler runs under Elastic Agent.

## Documents

Crawled pages are indexed with the crawler's document schema (`title`, `body`, `url`, `links`, `headings`, `meta_description`, `meta_keywords`, `last_crawled_at` and fields added by extraction rules). Documents that are no longer found during a crawl are removed from the index when *Purge outdated documents* is enabled.
