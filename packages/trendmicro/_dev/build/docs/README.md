# Trendmicro Integration

## Overview

Trend Micro Deep Security provides advanced server security for physical, virtual, and cloud servers. It protects enterprise applications and data from breaches and business disruptions without requiring emergency patching. The Trend Micro Deep Security integration collects and parses data received from [Deep Security](https://www.trendmicro.com/en_gb/business/products/hybrid-cloud/deep-security.html) via a log file.

## Data Streams

This integration collects **deep_security** data streams.See more details from Deep Security logging documentation [here](https://help.deepsecurity.trendmicro.com/aws/events.html).

## Requirements

Elastic Agent is required to ingest data from Deep Security log files. This integration has been tested against Deep Security v12 LTS. Please note is you have a Trend Micro Vision One XDR license, we recommend using the [Vision One](https://docs.elastic.co/integrations/trend_micro_vision_one) integration to ingest Deep Security events. For steps on how to configure Deep Security events with Vision One, please see [here](https://help.deepsecurity.trendmicro.com/aws/xdr.html).

## Logs

### Deep Security Logs

Deep Security logs collect the trendmicro deep security logs.

{{fields "deep_security"}}
