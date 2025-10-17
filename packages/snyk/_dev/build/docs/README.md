# Snyk Integration

<!--
Keep the API docs version in sync with the version used in the agent
configuration in cel.yml.hbs for both REST API data streams.

This is hard-coded in to the state construction instead of being configurable,
since new versions may break our ingest pipeline.
-->
This integration is for ingesting data from the [Snyk](https://snyk.io/) API. The integration allows collection of audit logging information and vulnerability issues via the Snyk [REST API](https://apidocs.snyk.io/?version=2024-04-29#overview).

## Agentless Enabled Integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

## REST API

- `issues`: Collects all found issues for the related organizations and projects.
- `audit_logs`: Collects audit logging from Snyk, this can be actions like users, permissions, groups, api access and more.

To configure access to the Snyk REST Audit Log API you will have to obtain an API access token from [your Snyk account dashboard](https://app.snyk.io/account) as described in the [Snyk Documentation](https://docs.snyk.io/snyk-api/authentication-for-api).


## Audit Logs

{{event "audit_logs"}}

{{fields "audit_logs"}}

## Issues

{{event "issues"}}

{{fields "issues"}}
