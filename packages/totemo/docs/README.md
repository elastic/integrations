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

An example event for `log` looks as following:

```json
{
    "@timestamp": "2025-12-01T12:03:33.260Z",
    "agent": {
        "ephemeral_id": "0208c96a-67dc-4667-af3b-8bd5205121f7",
        "id": "e02472c2-5cc9-407f-a322-ab838af9fc7a",
        "name": "elastic-agent-24138",
        "type": "filebeat",
        "version": "9.0.0"
    },
    "client": {
        "address": "client.contoso.com",
        "domain": "client.contoso.com",
        "ip": "1.128.0.1"
    },
    "data_stream": {
        "dataset": "totemo.log",
        "namespace": "83285",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "e02472c2-5cc9-407f-a322-ab838af9fc7a",
        "snapshot": false,
        "version": "9.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2025-12-01T12:03:33.260Z",
        "dataset": "totemo.log",
        "ingested": "2026-02-12T13:48:34Z",
        "kind": "event",
        "original": "INFO  <2025-12-01T17:03:33,260> [default Worker #9] [MailServer                    ]  Connection from client.contoso.com (1.128.0.1)",
        "timezone": "+0500"
    },
    "input": {
        "type": "udp"
    },
    "log": {
        "level": "info",
        "origin": {
            "function": "MailServer"
        },
        "source": {
            "address": "172.21.0.3:35704"
        }
    },
    "message": "Connection from client.contoso.com (1.128.0.1)",
    "tags": [
        "preserve_original_event",
        "forwarded",
        "totemo-log"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp, crucial for tracking when the email activity occurred. | date |
| client.domain | Domain name of the client. | keyword |
| client.ip | IP address of the client involved in the email transaction. | ip |
| client.port | Port number used by the client during the email transaction. | integer |
| data_stream.dataset | Data stream dataset, helping in categorizing the logs for easier management and analysis. | constant_keyword |
| data_stream.namespace | Data stream namespace, useful for organizing and querying logs. | constant_keyword |
| data_stream.type | Data stream type, indicating whether the log pertains to transport or mailbox activities. | constant_keyword |
| email.from.address | Sender's email address. | keyword |
| email.local_id | Unique identifier for the email within the local system. | keyword |
| email.message_id | Unique message ID assigned to the email, useful for tracking and referencing specific emails. | keyword |
| email.subject | Subject line of the email. | keyword |
| email.to.address | Recipient's email address. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.origin.function | Function or process that originated the log entry. | keyword |
| log.source.address | Log source address, specifying the server or system generating the log. | keyword |
| server.domain | Domain name of the server. | keyword |
| server.ip | IP address of the server involved in the email transaction. | ip |
| server.port | Port number used by the server during the email transaction. | integer |
| x509.serial_number | Serial number of an X.509 certificate, used in secure email transactions. | keyword |
| x509.subject.common_name | Common name of the subject in an X.509 certificate, often used to identify the entity associated with the certificate. | keyword |

