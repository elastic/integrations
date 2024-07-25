# Palo Alto Prisma Access

## Overview

[Palo Alto Prisma Access](https://www.paloaltonetworks.com/sase/access) is a Secure Access Service Edge (SASE) platform that enables organizations to provide protected connectivity to their network and applications for branches, retail locations, and remote users. It's designed to ensure secure access to the cloud, SaaS, and internet for users, regardless of their location. Prisma Access uses a cloud-delivered infrastructure to connect users to applications, delivering both network security and a seamless user experience.

Use the Palo Alto Prisma Access integration to collect and parse data from the Syslog server. Then visualize that data in Kibana.

## Compatibility

This module has been tested against the latest Palo Alto Prisma Access version **5.0**.

## Data streams

The Palo Alto Prisma Access integration collects 16 types of event types:

**[Authentication](https://docs.paloaltonetworks.com/strata-logging-service/log-reference/network-logs/network-authentication-log)** - Auth logs contain information about authentication events seen by the next-generation firewall.

**[DNS Security](https://docs.paloaltonetworks.com/strata-logging-service/log-reference/network-logs/network-dns-security-log)** - DNS Security logs contain information that the DNS Security service collects, such as server response and request information based on your firewall security policy rules, associated action, and the DNS query details when performing domain lookups.

**[Decryption](https://docs.paloaltonetworks.com/strata-logging-service/log-reference/network-logs/network-decryption-log)** - By default, decryption logs display entries for unsuccessful TLS handshakes.

**[File](https://docs.paloaltonetworks.com/strata-logging-service/log-reference/network-logs/network-file-log)** - File logs represents a file transfer across the network.

**[GlobalProtect](https://docs.paloaltonetworks.com/strata-logging-service/log-reference/network-logs/network-globalprotect-log)** - GlobalProtect logs identify network traffic between a GlobalProtect portal or gateway, and GlobalProtect apps.

**[HIP Match](https://docs.paloaltonetworks.com/strata-logging-service/log-reference/network-logs/network-hip-match-log)** - HIP Match logs capture information about the security status of the endpoints accessing a network (such as whether they have disk encryption enabled).

**[IPtag](https://docs.paloaltonetworks.com/strata-logging-service/log-reference/network-logs/network-iptag-log)** - IPtag logs display how and when a source IP address is registered or unregistered with the next-generation firewall, and what tag the firewall applied to the address.

**[SCTP](https://docs.paloaltonetworks.com/strata-logging-service/log-reference/network-logs/network-sctp-log)** - SCTP logs are written at the end of every SCTP network session, as well as optionally at the start of every such session.

**[Threat](https://docs.paloaltonetworks.com/strata-logging-service/log-reference/network-logs/network-threat-log)** - Threat logs contain entries for when network traffic matches one of the security profiles attached to a next-generation firewall security rule.

**[Traffic](https://docs.paloaltonetworks.com/strata-logging-service/log-reference/network-logs/network-traffic-log)** - Traffic logs contain entries for the end of each network session, as well as (optionally) the start of a network session.

**[Tunnel](https://docs.paloaltonetworks.com/strata-logging-service/log-reference/network-logs/network-tunnel-log)** - Tunnel logs are written whenever a next-generation firewall is handling GTP traffic.

**[URL](https://docs.paloaltonetworks.com/strata-logging-service/log-reference/network-logs/network-url-log)** - URL logs are written by next-generation firewalls whenever network traffic matches a URL Filtering Profile attached to one or more security rules.

**[UserID](https://docs.paloaltonetworks.com/strata-logging-service/log-reference/network-logs/network-userid-log)** - User-ID logs are generated whenever a user authentication event occurs using a resource to which the firewall has visibility.

**[System](https://docs.paloaltonetworks.com/strata-logging-service/log-reference/common-logs/common-system-log)** - System logs are used to record system events that occur within the writing entity.

**[Configuration](https://docs.paloaltonetworks.com/strata-logging-service/log-reference/common-logs/common-configuration-log)** - Configuration logs are used to record changes made to the writing entity.

**[GlobalProtect App Troubleshooting](https://docs.paloaltonetworks.com/strata-logging-service/log-reference/endpoint-logs/endpoint-globalprotect-app-troubleshooting-log)** - GlobalProtect App troubleshooting logs contain information about the GlobalProtect client and its host to help app users resolve issues.

**NOTE**: The Palo Alto Prisma Access integration collects logs for different events, but we have combined all of those in one data stream named `event`.

## Requirements

- Elastic Agent must be installed.
- You can install only one Elastic Agent per host.
- Elastic Agent is required to stream data through the Syslog server and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

## Setup

For step-by-step instructions on how to forward logs to syslog server from your Palo Alto Prisma Access instance, see the
[Forward Logs to a Syslog Server](https://docs.paloaltonetworks.com/strata-logging-service/administration/forward-logs/forward-logs-to-syslog-server) guide.

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations.
2. In "Search for integrations" search bar, type Palo Alto Prisma Access.
3. Click on the "Palo Alto Prisma Access" integration from the search results.
4. Click on the "Add Palo Alto Prisma Access" button to add the integration.
5. Add all the required integration configuration parameters according to the enabled input type.
6. Click on "Save and continue" to save the integration.

## Logs Reference

### Event

This is the `Event` dataset.

#### Example

{{event "event"}}

{{fields "event"}}