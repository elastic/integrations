# Trendmicro Integration

## Overview

Trend Micro Deep Security provides advanced server security for physical, virtual, and cloud servers. It protects enterprise applications and data from breaches and business disruptions without requiring emergency patching. The Trend Micro Deep Security integration collects and parses data received from [Deep Security](https://www.trendmicro.com/en_gb/business/products/hybrid-cloud/deep-security.html) via syslog server.

## Data Streams

This integration supports **deep_security** data stream. See more details from Deep Security logging documentation [here](https://help.deepsecurity.trendmicro.com/20_0/on-premise/events.html).

## Requirements

Elastic Agent is required to ingest data from Deep Security. For more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

## Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

The minimum **kibana.version** required is **8.11.0**.

This integration has been tested against Deep Security 20. Please note if you have a Trend Micro Vision One XDR license, we recommend using the [Vision One](https://docs.elastic.co/integrations/trend_micro_vision_one) integration to ingest Deep Security events. For steps on how to configure Deep Security events with Vision One, please see [here](https://help.deepsecurity.trendmicro.com/aws/xdr.html).

## Setup

Follow the [setup guide](https://help.deepsecurity.trendmicro.com/20_0/on-premise/event-syslog.html) to forward deep security events to a syslog server.

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations
2. In "Search for integrations" search bar, type Trend Micro.
3. Click on the "Trend Micro" integration from the search results.
4. Click on the "Add Trend Micro" button to add the integration.
5. Add all the required integration configuration parameters according to the enabled input type.
6. Click on "Save and Continue" to save the integration.

## Logs

### Deep Security Logs

Deep Security logs collect the trendmicro deep security logs.

{{event "deep_security"}}

{{fields "deep_security"}}
