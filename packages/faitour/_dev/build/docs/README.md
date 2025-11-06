# Faitour

This integration is for [Faitour](https://github.com/MakoWish/Faitour) honeypot event logs. The package processes messages from Faitour honeypot logs to allow visibility and alerting to observed activity on your network.

## Data streams

The Faitour integration collects the following event types:

- **events**

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).


### Enabling the integration in Elastic:

1. In Kibana navigate to Management > Integrations.
2. In "Search for integrations" top bar, search for `Faitour`.
3. Select the "Faitour" integration from the search results.
4. Select "Add Faitour" to add the integration.
5. Add all the required integration configuration parameters.
6. Select "Save and continue" to save the integration.

## Logs

### Faitour Honeypot

The `honeypot` dataset collects the Faitour honeypot logs.

{{event "honeypot"}}

{{fields "honeypot"}}

### Faitour Application

The `application` dataset collects the Faitour application logs.

{{event "application"}}

{{fields "application"}}
