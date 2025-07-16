# Ubiquiti UniFi

This integration is for [Ubiquiti UniFi](https://ui.com) equipment event logs. The package processes events collected from Ubiquiti Unifi devices.

## Data Streams

The Ubiquiti UniFi integration collects the following event types:

- **logs**, Logs produced via UDP syslog from a Unifi controller, application or device.

This includes CEF logs, iptables firewall logs, and other Unix/Linux style syslog messages that may be produced.

You can use Elastic Agent to read files of logs if you already have a syslog aggregation system that is already collecting UniFi syslog output. Or alternatively you can configure your UniFi systems to log directly to a UDP listener on an Elastic Agent.

- **webhooks**, Events produced by Unifi Alarm Manager as webhooks, aka. HTTP POST's with a JSON body.

The Ubiquiti UniFi Alarm Manager and webhook based alarms are very new features and the content currently included in the body of a webhook is highly variable in terms of quality and field completeness.

## Related Integrations

**NOTE**: Ubiquiti UniFi now supports NetFlow based traffic logging. If network flow visibility is desired you can and should utilise the existing Elastic [Netflow](https://www.elastic.co/docs/reference/integrations/netflow) integration using NetFlow Version 9 to collect flow records from your Ubiquiti UniFi equipment. Refer to [https://community.ui.com/releases](https://community.ui.com/releases) for further documentation regarding NetFlow support and configuration instructions.

**NOTE**: Ubiquiti UniFi produces iptables "style" firewall logs with a slightly different format to the firewall logs previously produced by other Ubiquiti systems. You do not need to, and should not, install or utilise existing Ubiquiti support within the [iptables](https://www.elastic.co/docs/reference/integrations/iptables) integration as it will not work for firewall logs produced by UniFi systems. You should utilise this integration to collect Ubiquiti UniFi firewall logs independently of other non-UniFi Ubiquiti equipment.

**NOTE**: Ubiquiti UniFi components produce iptables style firewall logs, *some* CEF format logs for configuration activity and events on UniFi consoles and within applications, as well as some common *nix style logs. While at times these are sent with a syslog prefix at other times they are not sent with a syslog prefix. At present not all CEF logs produced by UniFi components are conformant to the Common Event Format (CEF) specification. You do not need to, and should not, attempt to utilise the existing Elastic [CEF](https://www.elastic.co/docs/reference/integrations/cef) integration to process Ubiquiti UniFi logs in any way. This Ubiquiti UniFi integration includes Elastic Agent beat level content fixes for the format problems that are often produced by Ubiquiti UniFi components at present.

## Requirements

For `logs` based event collection Elastic Agent *MUST* be utilised due to the pre-processing and filtering that occurs at the agent level. For example CEF parsing is completed by the Elastic Agent, as this is the only component that natively supports CEF parsing, when logs are first received from the network or read from file. A number of content fixes are applied. 

If `logs` are received/aggregated or otherwise handled by something else and delivered to Elasticsearch for indexing, without passing thru an Elastic Agent, you should replicate the Elastic Agent behaviour, including content fixes, CEF parsing, as well as appropriate tagging.

`webhooks` events from the Ubiquiti UniFi Alarm Manager feature/s require no special Elastic Agent based pre-processing and can be delivered to Elasticsearch for indexing via any method that is suitable for your environment; provided you tag the events appropriately.

For more details and installation instructions, please refer to the [Elastic Agent Installation Guide](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

Your Ubiquiti UniFi infrastructure should consist of:
- Ubiquiti UniFi OS `4.0.0` or higher, if running a Ubquiti Unifi Cloud Gateway or similar appliance.
- Ubiquiti UniFi Applications, e.g. Network, `9.0.0` or higher, either on a Ubquiti Unifi Cloud Gateway or self hosted.

Refer to [https://community.ui.com/releases](https://community.ui.com/releases) for current release information, upgrade instructions and further documentation.

**NOTE**: This integration has been tested with Ubiquiti UniFi Cloud Gateways only, self-hosted versions of UniFi applications should work but have not been tested.

**NOTE**: This integration has only been tested with Ubiquiti UniFi Network and Protect applications at this time.

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
2. In "Search for integrations" top bar, search for `Ubiquiti UniFi`.
3. Select the "Ubiquiti UniFinary" integration from the search results.
4. Select "Add Ubiquiti UniFi" to add the integration.
5. Add all the required integration configuration parameters.
6. Select "Save and continue" to save the integration.

## Logs

### Ubiquiti UniFi Logs

The `logs` dataset collects Ubiquiti Unifi logs sent via syslog.

{{event "logs"}}

{{fields "logs"}}

### Ubiquiti UniFi Webhooks

The `webhooks` dataset collects Ubiquiti Unifi events producted by Alarm Manager configurations which send alarms as HTTP POST requests with a JSON body.

{{event "webhooks"}}

{{fields "webhooks"}}