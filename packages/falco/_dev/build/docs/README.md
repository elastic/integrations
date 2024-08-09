# Falco Integration
This integration allows for the shipping of [Falco](https://falco.org/) alerts to Elastic for observability and organizational awareness. Alerts can then be analyzed by using either the dashboard included with the integration or via the creation of a custom dashboard within Kibana.

## Data Streams
The Falco integration collects one type of data stream: logs.

**Logs** The Logs data stream collected by the Falco integration is comprised of Falco Alerts. See more details about Falco Alerts in [Falco's Outputs Documentation](https://falco.org/docs/outputs/). A complete list of potential fields used by this integration can be found in the [Logs reference](#logs-reference)

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Falco must be configured to output alerts to a supported output channel as defined in [Setup](#setup). The system will only receive fields output by Falco's rules. If a rule does not include a desired field the rule must be edited in Falco to add the field.

This integration is compatible with Falco version 0.37 and above, and should not be expected to perform successfully in lower versions. 

## Setup

For step-by-step instructions on how to set up an integration, see the {{ url "getting-started-observability" "Getting started" }} guide.

In order to capture alerts from Falco you **must** configure Falco to output Alerts as JSON to one of the supported channels: [Logfile](#logfile-input) or [TCP Syslog](#tcp-syslog-input).

**Required:** To configure Falco to output JSON, set the config properties `json_output=true` and `json_include_output_property=true` in Falco's config. See the examples in Falco's [Output Channels documentation](https://falco.org/docs/outputs/channels/#http-output).

### Logfile Input

The logfile input reads data from one or more Falco log files using the Elastic Agent. Use this input when the Elastic Agent will be deployed to the same machine as Falco or when Falco's log files are available via a mounted filesystem.

To use this input Falco must be configured to output alerts to a log file. See Falco's [File Output](https://falco.org/docs/outputs/channels/#file-output) documentation for details.

### TCP Syslog Input

The TCP Syslog input allows the Elastic Agent to receive Falco Alerts via remote syslog. Use this input when you want to send data via [Falco Sidekick](https://github.com/falcosecurity/falcosidekick).

To use this input you will need to deploy the Elastic Agent *first* and then configure and deploy Falco Sidekick to send Alerts to the Agent via Syslog. See [Syslog Output](https://github.com/falcosecurity/falcosidekick/blob/master/docs/outputs/syslog.md) and [Connecting Falco to Sidekick](https://github.com/falcosecurity/falcosidekick?tab=readme-ov-file#connect-falco) for more details.

## Logs Reference

### alerts

Falco alerts can contain a multitude of various fields pertaining to the type of activity on the host machine.

{{ fields "alerts" }}

{{ event "alerts" }}
