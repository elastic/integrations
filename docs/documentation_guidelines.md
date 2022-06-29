# Documentation guidelines

The goal of each integration doc is to:

* Help the reader see the benefits the integration offers and how Elastic can help with their use case.
* Inform the reader of any requirements including system compatibility, supported versions of third-party products, permissions needed, and more.
* Provide a comprehensive list of collected fields and the data and metric types for each. The reader can reference this information while evaluating the integration, interpreting collected data, or troubleshooting issues.
* Set the reader up for a successful installation and setup by connecting them with any other resources they'll need.

Each integration doc should contain several sections, and you should use consistent headings
to make it easier for a single user to evaluate and use multiple integrations.
Sections include:

* [Overview](#overview)
* [Data streams](#data-streams)
* [Requirements](#requirements)
* [Setup](#setup)
* (Optional) [Troubleshooting](#troubleshooting)
* [Reference](#reference)

## Overview

The overview section explains what the integration is, defines the third-party product that is providing data,
establishes its relationship to the larger ecosystem of Elastic products, and helps the reader understand
how it can be used to solve a tangible problem.

The overview should answer the following questions:

* What is the integration?
* What is the third-party product that is providing data?
* What can you do with it?
  * General description
  * Basic example

**Template**

Use this template language as a starting point, replacing `<placeholder text>` with details about the integration:

```md
The <name> integration allows you to monitor <service>. <service> is <definition>.

Use the <name> integration to <function>. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference <data stream type> when troubleshooting an issue.

For example, if you wanted to <use case> you could <action>. Then you can <visualize|alert|troubleshoot> by <action>.
```

**Example**

>The AWS CloudFront integration allows you to monitor your [AWS CloudFront](https://aws.amazon.com/cloudfront/) usage.
>AWS CloudFront is a content delivery network (CDN) service.
>
>Use the AWS CloudFront integration to collect and parse logs related to content delivery.
Then visualize that data in Kibana, create alerts to notify you if something goes wrong,
and reference logs when troubleshooting an issue.
>
>For example, you could use the data from this integration to know when there are more than some number of failed requests for a single piece of content in a given time period. You could also use the data to troubleshoot the underlying issue by looking at additional context in the logs like the number of unique users (by IP address) who experienced the issue, the source of the request, and more.

## Data streams

The data streams section provides a high-level overview of the kind of data that is collected by the integration.
This is helpful since it can be difficult to quickly derive an understanding from just the reference sections (since they're so long).

The data streams section should include:

* A list of the types of data streams collected by the integration
* A summary of each type of data stream included and a link to the relevant reference section:
  * Logs
  * Metrics
* (Optional) Notes

**Template**

Use this template language as a starting point, replacing `<placeholder text>` with details about the integration:

```md
## Data streams

The <name> integration collects two types of data streams: logs and metrics.

**Logs** help you keep a record of events happening in <service>.
Log data streams collected by the <name> integration include <select data streams>, and more. See more details in the [Logs](#logs-reference).

**Metrics** give you insight into the state of <service>.
Metric data streams collected by the <name> integration include <select data streams> and more. See more details in the [Metrics](#metrics-reference).

<!-- etc. -->

<!-- Optional notes -->
```

**Example**

>The System integration collects two types of data: logs and metrics.
>
>**Logs** help you keep a record of events that happen on your machine.
>Log data streams collected by the System integration include application, system, and security events on
>machines running Windows or auth and syslog events on machines running macOS or Linux.
>See more details in the [Logs reference](#logs-reference).
>
>**Metrics** give you insight into the state of the machine.
>Metric data streams collected by the System integration include CPU usage, load statistics, memory usage,
>information on network behavior, and more.
>See more details in the [Metrics reference](#metrics-reference).
>
>You can enable and disable individual data streams. If _all_ data streams are disabled and the System integration
is still enabled, Fleet uses the default data streams.

## Requirements

The requirements section helps the reader be confident up front that the integration will work with their systems.

* Elastic prerequisites (for example, a self-managed or cloud deployment)
* System compatibility
* Supported versions of third-party products
* Permissions needed
* Anything else that could block a user from successfully using the integration

**Template**

Use this template language as a starting point, including any other requirements for the integration:

```md
## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

<!-- Other requirements -->
```

**Example**

>You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
>You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.
>
>Each data stream collects different kinds of metric data, which may require dedicated permissions
>to be fetched and may vary across operating systems.
>Details on the permissions needed for each data stream are available in the [Metrics reference](#metrics-reference).

See a much more detailed example in [`packages/aws/_dev/build/docs/README.md`](../packages/aws/_dev/build/docs/README.md#requirements).

## Setup

The setup section points the reader to the Getting started guide for generic step-by-step instructions.

It should also include any additional setup instructions beyond what's included in the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide,
which may include updating the configuration of a third-party service.
For example, for the Cisco ASA integration, users need to configure their Cisco device following the
[steps found in the Cisco documentation](https://documentation.meraki.com/General_Administration/Monitoring_and_Reporting/Syslog_Server_Overview_and_Configuration#Configuring_a_Syslog_Server).

Note: When possible, use links to point to third-party documentation for configuring non-Elastic products
since workflows may change without notice.

**Template**

Use this template language as a starting point, including any other setup instructions for the integration:

```md
## Setup

<!-- Any prerequisite instructions -->

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

<!-- Additional set up instructions -->
```

**Example**

>Before sending logs to Elastic from your Cisco device, you must configure your device according to 
>[Cisco's documentation on configuring a syslog server](https://documentation.meraki.com/General_Administration/Monitoring_and_Reporting/Syslog_Server_Overview_and_Configuration#Configuring_a_Syslog_Server).
>
>After you've configured your device, you can set up the Elastic integration.
>For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Troubleshooting

The troubleshooting section is optional.
It should contain information about special cases and exceptions that isn't necessary for getting started or won't be applicable to all users.

**Template**

There is no standard format for the troubleshooting section.

**Example**

>Note that certain data streams may access `/proc` to gather process information,
>and the resulting `ptrace_may_access()` call by the kernel to check for
>permissions can be blocked by
>[AppArmor and other LSM software](https://gitlab.com/apparmor/apparmor/wikis/TechnicalDoc_Proc_and_ptrace), even though the System module doesn't use `ptrace` directly.
>
>In addition, when running inside a container the proc filesystem directory of the host
>should be set using `system.hostfs` setting to `/hostfs`.

## Reference

Readers might use the reference section while evaluating the integration, interpreting collected data, or troubleshooting issues.

There can be any number of reference sections (for example, `## Metrics reference`, `## Logs reference`).
And each reference section can contain one or more subsections, one for each individual data stream (for example, `### Access Logs` and `### Error logs`).

Each reference section should contain detailed information about:

* A list of the log or metric types we support within the integration and a link to the relevant third-party docs.
* (Optional) An example event in JSON format.
* Exported fields for logs, metrics, and events with actual types (for example, `counters`, `gauges`, `histograms` vs. `longs` and `doubles`). Fields should be generated using the instructions in [Fine-tune the integration](./fine_tune_integration.md).
* ML Modules jobs.

**Template**

```md
<!-- Repeat for both Logs and Metrics if applicable -->
## <Logs|Metrics> reference

<!-- Repeat for each data stream of the current type -->
### <Data stream name>

The `<data stream name>` data stream provides events from <source> of the following types: <list types>.

<!-- Optional -->
<!-- #### Example -->
<!-- An example event for `<data stream name>` looks as following: -->
<!-- <code block with example> -->

#### Exported fields

<insert table>
```

**Example**

>## Logs reference
>
>### PAN-OS
>
>The `panos` data stream provides events from Palo Alto Networks device of the following types: [GlobalProtect](https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/globalprotect-log-fields), [HIP Match](https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/hip-match-log-fields), [Threat](https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/threat-log-fields), [Traffic](https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/traffic-log-fields) and [User-ID](https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/user-id-log-fields).
>
>#### Example
>
>An example event for `panos` looks as following:
>
>(code block)
>
>#### Exported fields
>
>(table of fields)
