# Snyk Integration

This integration is for ingesting data from the [Snyk](https://snyk.io/) API.

- `vulnerabilities`: Collects all found vulnerabilities for the related organizations and projects
- `audit`: Collects audit logging from Snyk, this can be actions like users, permissions, groups, api access and more.

To configure access to the Snyk Audit Log API you will have to generate an API access token as described in the [Snyk Documentation](https://snyk.docs.apiary.io/#introduction/authorization)


## Audit Logs

{{event "audit_logs"}}

{{fields "audit_logs"}}

## Audit (Legacy)

{{event "audit"}}

{{fields "audit"}}

## Vulnerabilities

{{event "vulnerabilities"}}

{{fields "vulnerabilities"}}

