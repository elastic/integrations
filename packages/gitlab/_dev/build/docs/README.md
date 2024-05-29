# GitLab Integration

This integration is for ingesting logs from [GitLab](https://about.gitlab.com/).

- `api`: Collect logs for HTTP requests made to the Gitlab API

- `production`: Collect logs for Rails controller requests received from GitLab.

See the GitLab [Log system docs](https://docs.gitlab.com/ee/administration/logs/) for more information.

## Compatibility

The Gitlab module has been developed with and tested against the [community edition](https://gitlab.com/rluna-gitlab/gitlab-ce) version 16.8.5-ce.0. 

## Setup

Refer to the GitLab documentation for the specific filepath(s) for your instance type. Both are provided as default in the configuration setup, but only one will be needed for use. See [API](https://docs.gitlab.com/ee/administration/logs/#api_jsonlog) and [Production](https://docs.gitlab.com/ee/administration/logs/#production_jsonlog) for details. 

## Logs

### api

Collect logs for HTTP requests made to the GitLab API. Check out the [GitLab API log docs](https://docs.gitlab.com/ee/administration/logs/#api_jsonlog) for more information.

{{fields "api"}}

{{event "api"}}

### production

Collect logs for Rails controller requests received from GitLab. Check out the [Gitlab production log docs](https://docs.gitlab.com/ee/administration/logs/#production_jsonlog) for more information.

{{fields "production"}}

{{event "production"}}