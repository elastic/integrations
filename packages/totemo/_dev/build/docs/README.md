# Kiteworks Totemomail

## Overview

The Kiteworks Totemomail integration collects and parses Tracelogs from [Kiteworks Totemomail](https://pleasantpasswords.com/).

### Compatibility

This module has been tested against `Kiteworks Totemomail Version #TODO: Find out the version`. It should however work with all versions if the logging is setup correctly.

### How it works

The integration collects log data from Kiteworks Totemomail via syslog over TCP/UDP. It parses the log4j formatted logs and extracts relevant fields for analysis in Elastic Observability.

## What data does this integration collect?

The Totemo integration collects the following event types: `log`.

## What do I need to use this integration?

- Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).
- Because Totemo has a flexible logging output it is important to have the log4j forwarder setup in the same way on all systems, otherwise the log extraction will fail.

### log4j forwarder configuration

```
%-5p <%d{ISO8601}> [%t] [%-30c{1}] %X{mailID} %m %n
```

## How do I deploy this integration?

### Onboard and configure

1. Enable the integration with TCP/UDP input.
2. Login to your Totemo Mail Appliance and navigate to:
   - Settings
   - Logging + Tracking
     - audit.adminSyslogHost = Elastic Agent Hostname
     - auditadminSyslogPort = Integration Port
     - audit.adminSyslogProtocol = TCP or UDP
     - totemo.log4j2.appender.syslog.layout.pattern = ``%-5p <%d{ISO8601}> [%t] [%-30c{1}] %X{mailID} %m %n``

3. In Kibana navigate to **Management** > **Integrations**.
4. In the search top bar, type **Totemomail**.
5. Select the **Kiteworks Totemomail** integration and add it.
6. Add all the required integration configuration parameters.
7. Save the integration.

### Validation

After deployment, verify that logs are being collected by checking the Discover view in Kibana for the `totemo-*` index pattern.

## Troubleshooting

Common issues and their solutions:

- **Logs not appearing**: Verify that the log4j pattern matches exactly and that the syslog host/port are correctly configured in both Totemo and Elastic Agent.
- **Field extraction failures**: Ensure the log format is consistent across all Totemo instances.

## Performance and scaling

This integration is designed to handle typical email gateway log volumes. For high-volume deployments, consider:

- Increasing the Elastic Agent resource allocation
- Adjusting the batch size in the integration configuration
- Using multiple Elastic Agents for load balancing

## Reference

### Logs reference

This is the `log` dataset.

{{event "log"}}

{{fields "log"}}
