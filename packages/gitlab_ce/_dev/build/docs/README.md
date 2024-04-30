# gitlab_ce Integration

This integration is for ingesting logs from [Gitlab Community Edition](https://gitlab.com/rluna-gitlab/gitlab-ce).

- `api`: Collect logs for HTTP requests made to the Gitlab API

- `production`: Collect logs for Rails controller requests received from GitLab.

See [Link to docs](https://docs.gitlab.com/ee/administration/logs/) for more information.

## Compatibility

The Gitlab Community Edition module is currently tested on Linux and Mac with the community edition, version 16.8.5-ce.0.

## Logs

### api

Collect logs for HTTP requests made to the Gitlab API. Check out the [Gitlab api log docs](https://docs.gitlab.com/ee/administration/logs/#api_jsonlog) for more information.

{{fields "api"}}

{{event "api"}}

### production

Collect logs for Rails controller requests received from GitLab. Check out the [Gitlab production log docs](https://docs.gitlab.com/ee/administration/logs/#production_jsonlog) for more information.

{{fields "production"}}

{{event "production"}}