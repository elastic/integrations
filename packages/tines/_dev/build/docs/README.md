# Tines Integration

Tines makes data, including logs, related to use and configuration of a Tines tenant available via a REST API.

This integration can be used to collect:
1. [audit logs](https://www.tines.com/api/audit-logs)
2. [time saved reports](https://www.tines.com/api/reporting/time_saved)

The Tines API documentation is available via [this page](https://www.tines.com/api/welcome).

## Compatibility

The package collects "audit log" events and "time saved" reports from the Tines API.

At present the only API version available, and hence the version assumed to be polled by this integration, is v1.

The audit logs list endpoint is [documented here](https://www.tines.com/api/audit-logs/list).

The time saved reporting endpoint is [documented here](https://www.tines.com/api/reporting/time_saved).

## Configuration

### Find your Tines tenant URL

This is available within the Tines web interface via the URL bar, e.g. https://your-tenant-1234.tines.com

**NOTE**: the trailing domain may be tines.io for your particular tenant.

### Create a Tines user API key

Refer to [this documentation](https://www.tines.com/api/authentication) from Tines regarding how to create an API key.

The API key can be either a Personal or Tenant API key.

### Enabling the integration in Elastic

1. In Kibana go to **Management > Integrations**
2. In "Search for integrations" search bar type **Tines**
3. Click on "Tines" integration from the search results.
4. Click on **Add Tines** button to add the Tines integration.
5. Modify the Tines Tenant URL as appropriate
6. Insert your Tines API user email address
7. Insert the Tines API key created associated with the API user email address

![Example Integration Configuration](../img/tines-integration-configuration.png)

## Dashboards

There are two dashboards immediately available as part of the integration.

The Tines Audit Logs summary dashboard,

![Tines Audit Logs](../img/tines-audit-logs-dashboard.png)

And the Tines Time Saved dashboard,

![Tines Time Saved](../img/tines-time-saved-dashboard.png)

## Data Stream

### audit_logs

All fields ingested to this data stream are stored under `tines.audit_log` as each audit_log event is stored individually.

{{fields "audit_logs"}}

{{event "audit_logs"}}

### time_saved

All fields ingested to this data stream are stored under `tines.time_saved` as each time saved report event is stored individually.

{{fields "time_saved"}}

{{event "time_saved"}}
