# Atlassian Bitbucket Integration

The Bitbucket integration collects audit logs from the audit log files or the [audit API](https://developer.atlassian.com/server/bitbucket/reference/rest-api/). 

For more information on auditing in Bitbucket and how it can be configured, see [View and configure the audit log](https://confluence.atlassian.com/bitbucketserver/view-and-configure-the-audit-log-776640417.html) on Atlassian's website.

## Elastic Managed enabled integration

Elastic Managed integrations are only supported on Elastic Cloud Serverless and Elastic Cloud Hosted deployments. An Elastic Managed integration lets you ingest data from a cloud source while avoiding the orchestration, management, and maintenance associated with standard ingest infrastructure. Elastic runs the collector for you, so you can focus on your data instead of the infrastructure that collects it.

For more information, refer to [Elastic Managed integrations](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations) and the [Elastic Managed integrations FAQ](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations-faq).

## Logs

### Audit

The Bitbucket integration collects audit logs from the audit log files or the audit API from self hosted Bitbucket Data Center. It has been tested with Bitbucket 7.18.1 but is expected to work with newer versions.  This has not been tested with Bitbucket Cloud and is not expected to work.

{{fields "audit"}}

{{event "audit"}}