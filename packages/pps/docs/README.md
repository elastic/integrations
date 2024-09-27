# Pleasant Password Server

The Pleasant Password Server integration collects and parses DNS, DHCP, and Audit data collected from [Pleasant Password Server](https://pleasantpasswords.com/) via TCP/UDP or logfile.

## Data streams

The PPS integration collects the following event types:

- **log**

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


## Requirements

Elastic Agent must be installed. For more details and installation instructions, please refer to the [Elastic Agent Installation Guide](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

### Installing and managing an Elastic Agent:

There are several options for installing and managing Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

Please note, there are minimum requirements for running Elastic Agent. For more information, refer to the  [Elastic Agent Minimum Requirements](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html#elastic-agent-installation-minimum-requirements).


### Enabling the integration in Elastic:

1. In Kibana navigate to Management > Integrations.
2. In "Search for integrations" top bar, search for `Pleasant Password Server` or `PPS`.
3. Select the "Pleasant Password Server" integration from the search results.
4. Select "Add Pleasant Password Server" to add the integration.
5. Add all the required integration configuration parameters.
6. Select "Save and continue" to save the integration.

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
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Log source address | keyword |

