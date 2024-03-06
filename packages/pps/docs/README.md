# Pleasant Password Server

The Pleasant Password Server integration collects and parses DNS, DHCP, and Audit data collected from [Pleasant Password Server](https://pleasantpasswords.com/) via TCP/UDP or logfile.

## Setup steps
1. Enable the integration with TCP/UDP input.
2. Log in to the PPS WebUI.
3. Configure the PPS to send messages to a Syslog server using the following steps. 
    1. From the Menu go to Logging -> Syslog Configuration
    2. Set the Syslog Configuration to Enabled
    3. Set Hostname to the Hostname of your Fleet Agent or Load Balancer
    4. Set the Correct Port used in the Integration Configuration
    5. Set UDP or TCP
    6. Optionally set the Facility

## Compatibility

This module has been tested against `Pleasant Password Server Version 7.11.44.0 `.  
It should however work with all versions.

## Log samples
Below are the samples logs of the respective category:

## Audit Logs:
```
<134>Jan 23 09:49:10 SRV-PPS-001 Pleasant Password Server:192.168.1.2 - user@name.test -  - Success - Syslog Settings Changed - User <user@name.test> Syslogging setting updated  changing the host from <localhost> to <127.0.0.1> changing the port fr	127.0.0.1	23/01 09:49:10.894	
<134>Jan 23 11:32:57 SRV-PPS-001 Pleasant Password Server:192.168.1.2 - user@name.test -  - Success - Password Fetched - User <user@name.test> fetched the password for <TOP/SECRET/PASSWORD> - test	127.0.0.1	23/01 11:32:57.857	
<134>Jan 23 12:20:07 SRV-PPS-001 Pleasant Password Server:0.0.0.0 - Backup Restore Service -  - Success - Backup Occurred - User <Backup Restore Service> backing up database to <C:\ProgramData\Pleasant Solutions\Password Server\Backups\Backup	127.0.0.1	23/01 12:20:07.802	
<134>Jan 23 12:37:37 SRV-PPS-001 Pleasant Password Server:192.168.1.1 - user@name.test -  - Success - Session Log On - User <user@name.test> logged on	127.0.0.1	23/01 12:37:37.346
<134>Jan 23 12:38:07 SRV-PPS-001 Pleasant Password Server:192.168.1.1 - user@name.test -  - Success - Entry Updated - User <user@name.test> updated entry <TOP/SECRET/PASSWORD> changing the password	127.0.0.1	23/01 12:38:07.629	
<134>Jan 23 13:43:47 SRV-PPS-001 Pleasant Password Server:192.168.1.3 - user@name.test -  - Success - Identity Verified - User <user@name.test> verified via ApplicationBasicOAuth	127.0.0.1	23/01 13:43:47.422	
<134>Jan 23 13:47:25 SRV-PPS-001 Pleasant Password Server:192.168.1.3 - user@name.test -  - Error - Identity Not Verified - User <user@name.test> failed to verify themselves	127.0.0.1	23/01 13:47:25.593	
<134>Jan 23 13:47:25 SRV-PPS-001 Pleasant Password Server:192.168.1.3 - user@name.test -  - Error - Sign-in Failed - User <user@name.test> sign-in denied	127.0.0.1	23/01 13:47:25.641	
<134>Jan 23 14:05:54 SRV-PPS-001 Pleasant Password Server:192.168.1.3 - user@name.test -  - Success - Entry Created - User <user@name.test> created entry <TOP/SECRET/PASSWORD> as a duplicate	127.0.0.1	23/01 14:05:54.404	
<134>Jan 23 14:05:54 SRV-PPS-001 Pleasant Password Server:192.168.1.3 - user@name.test -  - Success - Entry Duplicated - User <user@name.test> duplicated entry <TOP/SECRET/PASSWORD>	127.0.0.1	23/01 14:05:54.450	
```

## Logs

This is the `log` dataset.

An example event for `log` looks as following:

```json
{
    "@timestamp": "2024-01-23T09:49:10.000+05:00",
    "agent": {
        "ephemeral_id": "4839a553-f2b3-4b50-8473-50087ad56a7c",
        "id": "fb476fe0-ec94-4731-9642-3d09807f2a87",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0"
    },
    "client": {
        "ip": "192.168.1.2"
    },
    "data_stream": {
        "dataset": "pps.log",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "fb476fe0-ec94-4731-9642-3d09807f2a87",
        "snapshot": false,
        "version": "8.0.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2024-01-23T09:49:10.000+05:00",
        "dataset": "pps.log",
        "ingested": "2024-01-23T22:18:43Z",
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
            "address": "172.24.0.7:44613"
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
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| input.type | Input type | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.offset | Log offset | long |
| log.source.address | Log source address | keyword |
| log.syslog.priority | Syslog numeric priority of the event, if available. According to RFCs 5424 and 3164, the priority is 8 \* facility + severity. This number is therefore expected to contain a value between 0 and 191. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.email | User email address. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |

