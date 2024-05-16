# GitLab

The GitLab integration collects logs from the GitLab logs directory.

## Compatibility

This module has been tested against the GitLab 

## Data streams

The GitLab integration collects data for the following events:

| Event Type                    |
|-------------------------------|
| Api                           |
| Application                   |
| Audit                         |
| Auth                          |
| CI Resource Groups            |
| Database Load Balancing       |
| Elasticsearch                 |
| Exceptions                    |
| Features                      |
| Geo                           |
| Git                           |
| Gitaly                        |
| Graphql                       |
| Importer                      |
| Integrations                  |
| Pages                         |
| Performance Bar               |
| Production                    |
| Puma                          |
| Service Measurement           |
| Shell                         |
| Sidekiq                       |
| Update Mirror Service         |
| Web Hooks                     |
| Workhorse                     |
| Zoekt                         |

**NOTE**:

1. The following logs are not ingested with this integration instead you should use its relevant integration

  - [NGINX](https://docs.elastic.co/integrations/nginx)
  - [PostgreSQL](https://docs.elastic.co/integrations/postgresql)
  - [Redis](https://docs.elastic.co/integrations/redis)
  - [Prometheus](https://docs.elastic.co/integrations/prometheus)
  - [Mattermost](https://docs.elastic.co/integrations/mattermost)

## Setup

Install Elastic Agent on the host where GitLab is running

If you deployed GitLab using a Linux package the logs will be located in `/var/log/gitlab` which is the default location. Otherwise, on self-compiled installations the logs will be located at `/home/git/gitlab/log`.

Refer to the [GitLab documentation](https://docs.gitlab.com/ee/administration/logs/) on the location of logs.

## Logs Reference

### api

This is the `api` dataset that helps you see requests made directly to the API.

#### Example

{{event "api" }}

{{fields "api" }}

### application

This is the `application` dataset which helps you discover event happening in your instance such as user and project creation or deletion.

#### Example

{{event "application" }}

{{fields "application" }}

### audit

This is the `audit` dataset .

#### Example

{{event "audit" }}

{{fields "audit" }}

### auth

This is the `auth` dataset.

#### Example

{{event "auth" }}

{{fields "auth" }}

### ci_resource_groups

This is the `ci_resource_groups` dataset.

#### Example

{{event "ci_resource_groups" }}

{{fields "ci_resource_groups" }}

### database_load_balancing

This is the `database_load_balancing` dataset.

#### Example

{{event "database_load_balancing" }}

{{fields "database_load_balancing" }}

### elasticsearch

This is the `elasticsearch` dataset.

#### Example

{{event "elasticsearch" }}

{{fields "elasticsearch" }}

### exceptions

This is the `exceptions` dataset.

#### Example

{{event "exceptions" }}

{{fields "exceptions" }}

### features

This is the `features` dataset.

#### Example

{{event "features" }}

{{fields "features" }}

### geo

This is the `geo` dataset.

#### Example

{{event "geo" }}

{{fields "geo" }}

### git

This is the `git` dataset.

#### Example

{{event "git" }}

{{fields "git" }}

### gitaly

This is the `gitaly` dataset.

#### Example

{{event "gitaly" }}

{{fields "gitaly" }}

### graphql

This is the `graphql` dataset.

#### Example

{{event "graphql" }}

{{fields "graphql" }}

### importer

This is the `importer` dataset.

#### Example

{{event "importer" }}

{{fields "importer" }}

### integrations

This is the `integrations` dataset.

#### Example

{{event "integrations" }}

{{fields "integrations" }}

### pages

This is the `pages` dataset.

#### Example

{{event "pages" }}

{{fields "pages" }}

### performance_bar

This is the `performance_bar` dataset.

#### Example

{{event "performance_bar" }}

{{fields "performance_bar" }}

### production

This is the `production` dataset.

#### Example

{{event "production" }}

{{fields "production" }}

### puma

This is the `puma` dataset.

#### Example

{{event "puma" }}

{{fields "puma" }}

### service_measurement

This is the `service_measurement` dataset.

#### Example

{{event "service_measurement" }}

{{fields "service_measurement" }}

### shell

This is the `shell` dataset.

#### Example

{{event "shell" }}

{{fields "shell" }}

### sidekiq

This is the `sidekiq` dataset.

#### Example

{{event "sidekiq" }}

{{fields "sidekiq" }}

### update_mirror_service

This is the `update_mirror_service` dataset.

#### Example

{{event "update_mirror_service" }}

{{fields "update_mirror_service" }}

### web_hooks

This is the `web_hooks` dataset.

#### Example

{{event "web_hooks" }}

{{fields "web_hooks" }}

### workhorse

This is the `workhorse` dataset.

#### Example

{{event "workhorse" }}

{{fields "workhorse" }}

### zoekt

This is the `zoekt` dataset.

#### Example

{{event "zoekt" }}

{{fields "zoekt" }}

