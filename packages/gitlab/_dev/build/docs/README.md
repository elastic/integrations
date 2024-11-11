# GitLab Integration

This integration is for ingesting logs from [GitLab](https://about.gitlab.com/).

- **api**: Collect logs for HTTP requests made to the GitLab API

- **application**: Collect logs for events in GitLab like user creation or project deletion.

- **audit**: Collect logs for changes to group or project settings and memberships.

- **auth**: Collect logs for protected paths abusive requests or requests over the Rate Limit.

- **pages**: Collect logs for Pages.

- **production**: Collect logs for Rails controller requests received from GitLab.

- **sidekiq**: Collect logs from [sidekiq](https://sidekiq.org/) for jobs background jobs that take a long time.

See the GitLab [Log system docs](https://docs.gitlab.com/ee/administration/logs/) for more information.

## Compatibility

The GitLab module has been developed with and tested against the [community edition](https://gitlab.com/rluna-gitlab/gitlab-ce) version 16.8.5-ce.0. 

## Requirements

Elastic Agent must be installed. For more details and installation instructions, please refer to the [Elastic Agent Installation Guide](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

### Installing and managing an Elastic Agent:

There are several options for installing and managing Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

Please note, there are minimum requirements for running Elastic Agent. For more information, refer to the  [Elastic Agent Minimum Requirements](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html#elastic-agent-installation-minimum-requirements).


## Setup

Refer to the [GitLab documentation](https://docs.gitlab.com/ee/administration/logs/) for the specific filepath(s) for your instance type. Both are provided as default in the configuration setup, but only one will be needed for use.

## Logs

### api

Collect logs for HTTP requests made to the GitLab API. Check out the [GitLab API log docs](https://docs.gitlab.com/ee/administration/logs/#api_jsonlog) for more information.

{{fields "api"}}

{{event "api"}}

### application

Collect logs for events happening in GitLab like user creation or project deletion. Check out the [GitLab Application log docs](https://docs.gitlab.com/ee/administration/logs/#application_jsonlog) for more information.

{{fields "application"}}

{{event "application"}}

### audit

Collect logs for changes to group or project settings and memberships. Check out the [GitLab Audit log docs](https://docs.gitlab.com/ee/administration/logs/#audit_jsonlog) for more information.

{{fields "audit"}}

{{event "audit"}}

### auth

Collect logs for abusive protect paths requests or requests over the Rate Limit. Check out the [GitLab Auth log docs](https://docs.gitlab.com/ee/administration/logs/#auth_jsonlog) for more information.

{{fields "auth"}}

{{event "auth"}}

### pages

Collect logs for Pages. Check out the [GitLab Pages log docs](https://docs.gitlab.com/ee/administration/logs/#pages-logs) for more information.

{{fields "pages"}}

{{event "pages"}}

### production

Collect logs for Rails controller requests received from GitLab. Check out the [GitLab production log docs](https://docs.gitlab.com/ee/administration/logs/#production_jsonlog) for more information.

{{fields "production"}}

{{event "production"}}

### sidekiq

Collect logs from sidekiq for jobs background jobs that take a long time. Check out the [GitLab sidekiq log docs](https://docs.gitlab.com/ee/administration/logs/#sidekiq-logs) for more information.

{{fields "sidekiq"}}

{{event "sidekiq"}}
