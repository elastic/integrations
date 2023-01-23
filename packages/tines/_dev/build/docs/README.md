# Tines Integration

Tines makes data, including logs, related to use and configuration of a Tines tenant available via a REST API.

This integration can be used to collect:
1. [audit logs](https://www.tines.com/api/audit-logs)

The Tines API documentation is available via [this page](https://www.tines.com/api/welcome).

## Compatibility

The package collects "audit log" events from the Tines API.

At present the only API version available, and hence the version assumed to be polled by this integration, is v1.

The only API endpoint utilised is currently the [audit logs list endpoint](https://www.tines.com/api/audit-logs/list).

## Configuration

### Find your Tines tenant URL

This is available within the Tines web interface via the URL bar, e.g. https://your-tenant-1234.tines.com

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

![Example Integration Configuration](./img/tines-integration-configuration.png)

## Dashboards

There is one audit log summary dashboard available as part of the integration.

![Tines Audit Logs](./img/tines-audit-logs-dashboard.png)

## Data Stream

### audit_logs

All fields ingested to this data stream are stored under `tines.audit_log` as each audit_log event is stored individually.

{{fields "audit_logs"}}

{{event "audit_logs"}}
