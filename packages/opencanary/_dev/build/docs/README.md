# OpenCanary

This integration is for [Thinkst OpenCanary](https://github.com/thinkst/opencanary) honeypot event logs. The package processes messages from OpenCanary honeypot logs.

## Data streams

The OpenCanary integration collects the following event types:

`events`: Collects the OpenCanary logs.

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search top bar, type **OpenCanary**.
3. Select the **OpenCanary** integration and add it.
4. Add all the required integration configuration parameters.
5. Save the integration.

## Logs

### OpenCanary

The `events` dataset collects the OpenCanary logs.

{{event "events"}}

{{fields "events"}}
