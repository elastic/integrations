# Kiteworks Totemomail

The Kiteworks Totemomail integration collects and parses Tracelogs
from [Kiteworks Totemomail](https://pleasantpasswords.com/).

## Data streams

The Totemo integration collects the following event types: `log`.

## Compatibility

This module has been tested against `Kiteworks Totemomail Version #TODO: Find out the version`.  
It should however work with all versions if the logging is setup correctly

## Requirements

Elastic Agent must be installed. For more details, check the Elastic
Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).
Since Totemo has a very flexible logging output it is important to have the log4j forwarder setup like this:

```
%-5p <%d{ISO8601}> [%t] [%-30c{1}] %X{mailID} %m %n
```

## Setup
### Syslog over Network
1. Enable the integration with TCP/UDP input.
1. Login to your Totemo Mail Appliance and navigate to:
* Settings
  * Logging + Tracking
    * audit.adminSyslogHost = Elastic Agent Hostname
    * auditadminSyslogPort = Integration Port
    * audit.adminSyslogProtocol = TCP or UDP
    * totemo.log4j2.appender.syslog.layout.pattern = ``%-5p <%d{ISO8601}> [%t] [%-30c{1}] %X{mailID} %m %n``

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search top bar, type **Totemomail**.
3. Select the **Kiteworks Totemomail** integration and add it.
4. Add all the required integration configuration parameters.
5. Save the integration.

## Logs

This is the `log` dataset.

{{event "log"}}

{{fields "log"}}
