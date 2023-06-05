# Vectra Detect Integration

The [Vectra Detect](https://www.vectra.ai/) integration allows you to monitor logs sent in the syslog format.
Vectra Detect provides the fastest and most efficient way to prioritize and stop attacks across cloud, data center, applications and workloads as well as user & IoT devices and accounts. Vectra uses artificial intelligence to automate real-time cyberattack detection and response – from network users and IoT devices to data centers and the cloud. All internal traffic is continuously monitored to detect hidden attacks in progress. Detected threats are instantly correlated with host devices that are under attack and unique context shows where attackers are and what they are doing. Threats that pose the biggest risk to an organization are automatically scored and prioritized based on their severity and certainty, which enables security operations teams to quickly focus their time and resources on preventing and mitigating loss.

Vectra Detect integration can be used in two different input modes:
- TCP mode: Vectra Detect sends logs to an Elastic Agent-hosted TCP port.
- UDP mode: Vectra Detect sends logs to an Elastic Agent-hosted UDP port.

## Data streams

The Vectra Detect integration collects logs for the following events:

  | Vectra Detect          |
  | -----------------------|
  | Account Detection      |
  | Account Lockdown       |
  | Account Scoring        |
  | Alert                  |
  | Audit                  |
  | Campaign               |
  | Health                 |
  | Host Detection         |
  | Host Lockdown          |
  | Host Scoring           |

**NOTE**: The Vectra Detect integration collects logs for different events, but we have combined all of those in one data stream named `log`.

## Compatibility

This integration has been tested against Vectra Detect **7.4**. Versions above this are expected to work but have not been tested.

## Requirements

You need Elasticsearch to store and search your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended or self-manage the Elastic Stack on your hardware.

## Setup

Please follow [Vectra Platform Getting Started Guide](https://content.vectra.ai/hubfs/downloadable-assets/Vectra-Platform-Getting-Started-Guide.pdf) to install and setup the Vectra AI platform.
To configure the syslog, follow [Vectra Syslog Guide](https://support.vectra.ai/s/article/KB-VS-1233).
Syslog messages can be sent in 3 formats to the remote syslog server: standard syslog, CEF, or JSON. Consider sending JSON format as we are supporting only the JSON format.

## Log Reference

The `log` data stream collects Vectra Detect logs.

{{event "log"}}

{{fields "log"}}
