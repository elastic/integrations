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

An example event for `log` looks as following:

```json
{
    "@timestamp": "2025-01-23T09:49:10.000+05:00",
    "agent": {
        "ephemeral_id": "e3830e56-f9b7-4278-b2cc-6c0041b3204b",
        "id": "92657501-44cd-4942-ab49-19404cc15d88",
        "name": "elastic-agent-47754",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "client": {
        "ip": "192.168.1.2"
    },
    "data_stream": {
        "dataset": "pps.log",
        "namespace": "63231",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "92657501-44cd-4942-ab49-19404cc15d88",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2025-01-23T09:49:10.000+05:00",
        "dataset": "pps.log",
        "ingested": "2025-05-30T11:05:38Z",
        "kind": "event",
        "original": "<134>Jan 23 09:49:10 SRV-PPS-001 Pleasant Password Server:192.168.1.2 - user@name.test -  - Success - Syslog Settings Changed - User <user@name.test> Syslogging setting updated  changing the host from <localhost> to <127.0.0.1> changing the port fr\t127.0.0.1\t23/01 09:49:10.894\t",
        "outcome": "success",
        "timezone": "+0500"
    },
    "host": {
        "hostname": "SRV-PPS-001"
    },
    "input": {
        "type": "udp"
    },
    "log": {
        "source": {
            "address": "192.168.255.3:58871"
        },
        "syslog": {
            "priority": 134
        }
    },
    "message": "Syslog Settings Changed - User <user@name.test> Syslogging setting updated  changing the host from <localhost> to <127.0.0.1> changing the port fr\t127.0.0.1\t23/01 09:49:10.894\t",
    "tags": [
        "preserve_original_event",
        "forwarded",
        "pps-log"
    ],
    "user": {
        "domain": "name.test",
        "email": "user@name.test",
        "name": "user"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.ip |  | ip |
| client.port |  | long |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Log source address | keyword |
| server.ip |  | ip |
| server.port |  | long |

