# Trendmicro Integration

## Overview

Trend Micro Deep Security provides advanced server security for physical, virtual, and cloud servers. It protects enterprise applications and data from breaches and business disruptions without requiring emergency patching. The Trend Micro Deep Security integration collects and parses data received from [Deep Security](https://www.trendmicro.com/en_gb/business/products/hybrid-cloud/deep-security.html) via syslog server.

## Data Streams

This integration supports **deep_security** data stream. For more details, check the [Deep Security logging documentation](https://help.deepsecurity.trendmicro.com/20_0/on-premise/events.html).

## Compatibility

This integration has been tested against Deep Security 20. If you have a Trend Micro Vision One XDR license, we recommend using the [Vision One](https://docs.elastic.co/integrations/trend_micro_vision_one) integration to ingest Deep Security events. For more information on how to configure Deep Security events with Vision One, check the [Deep Security documentation](https://help.deepsecurity.trendmicro.com/aws/xdr.html).

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

The minimum **kibana.version** required is **8.11.0**.

## Setup

Follow the Deep Security [setup guide](https://help.deepsecurity.trendmicro.com/20_0/on-premise/event-syslog.html) to forward Deep Security events to a syslog server.

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search top bar, type **Trend Micro**.
3. Select the **Trend Micro** integration and add it.
4. Add all the required integration configuration parameters according to the enabled input type.
5. Save the integration.

## Logs

### Deep Security Logs

Deep Security logs collect the trendmicro deep security logs.

{{event "deep_security"}}

{{fields "deep_security"}}
