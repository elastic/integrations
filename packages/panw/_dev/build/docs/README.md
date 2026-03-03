# Palo Alto Network Integration for Elastic

## Overview

The Palo Alto Network Integration for Elastic enables collection of logs from Palo Alto Networks' PAN-OS firewalls. This integration facilitates real-time visibility into network
activity, threat detection and security operations.

### Compatibility

This integration is compatible with PAN-OS versions 10.2, 11.1 and 11.2.

Support for specific log types varies by PAN-OS version. GlobalProtect logs are supported starting with PAN-OS version 9.1.3. User-ID logs are supported for PAN-OS version 8.1 and
above, while Tunnel Inspection logs are supported for version 9.1 and later.

This integration can receive logs from syslog via TCP or UDP, or read from log files.

## What data does this integration collect?

The Palo Alto Network integration collects log messages of the following types:

* [GlobalProtect](https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/globalprotect-log-fields.html)
* [HIP Match](https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/hip-match-log-fields.html)
* [Threat](https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/threat-log-fields.html)
* [Traffic](https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/traffic-log-fields.html)
* [User-ID](https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/user-id-log-fields.html)
* [Authentication](https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/authentication-log-fields)
* [Config](https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/config-log-fields)
* [Correlated Events](https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/correlated-events-log-fields)
* [Decryption](https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/decryption-log-fields)
* [GTP](https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/gtp-log-fields)
* [IP-Tag](https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/ip-tag-log-fields)
* [SCTP](https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/sctp-log-fields)
* [System](https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/system-log-fields)
* [Tunnel Inspection](https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/tunnel-inspection-log-fields).

### Supported use cases

Integrating Palo Alto Networks (PANW) with the Elastic Stack creates a powerful solution for transforming raw firewall logs into actionable intelligence, dramatically enhancing
security and operational visibility. This synergy enables advanced use cases including real-time threat detection and hunting through Elastic SIEM, deep network traffic analysis
with intuitive Kibana dashboards, and automated incident response by connecting with Cortex XSOAR. By centralizing and analyzing PANW data, organizations can strengthen their
security posture, optimize network performance, and build a solid data foundation for implementing a Zero Trust architecture.

## What do I need to use this integration?

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog or log file receiver and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

## How do I deploy this integration?

### Collect logs via syslog

To configure syslog monitoring, follow the steps described in the [Configure Syslog Monitoring](https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/monitoring/use-syslog-for-monitoring/configure-syslog-monitoring) documentation.

### Collect logs via log file

To configure log file monitoring, follow the steps described in the [Configure Log Forwarding](https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/monitoring/configure-log-forwarding) documentation.

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search bar, type **Palo Alto Next-Gen Firewall**.
3. Select the **Palo Alto Next-Gen Firewall** integration and add it.
4. If needed, install Elastic Agent on the systems which receive syslog messages or log files.
5. Enable and configure only the collection methods which you will use.

    * **To collect logs via syslog over TCP**, you'll need to configure the syslog server host and port details.

    * **To collect logs via syslog over UDP**, you'll need to configure the syslog server host and port details.

    * **To collect logs via log file**, configure the file path patterns which will be monitored, in the Paths field.

6. Press **Save Integration** to begin collecting logs.

### Validate log collection

1. In Kibana, navigate to **Dashboards**.
2. In the search bar, type **Logs PANW**.
3. Select a dashboard overview for the data type you are collecting, and verify the dashboard information is populated.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

If events are truncated, increase `max_message_size` option for TCP and UDP input type. You can find it under Advanced Options and configure it as per requirements.
The default value of `max_message_size` is set to 50KiB.

If the TCP input is used, it is recommended that PAN-OS is configured to send syslog messages using the IETF (RFC 5424) format. In addition, RFC 6587 framing (Octet Counting) will
be enabled by default on the TCP input.

To verify the configuration before and after the change (fields `before-change-detail` and `after-change-detail`) in the [config-log](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/config-log-fields), use the following [custom log format in the syslog server profile](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/custom-logevent-format):
  ``1,$receive_time,$serial,$type,$subtype,2561,$time_generated,$host,$vsys,$cmd,$admin,$client,$result,$path,$before-change-detail,$after-change-detail,$seqno,$actionflags,$dg_hier_level_1,$dg_hier_level_2,$dg_hier_level_3,$dg_hier_level_4,$vsys_name,$device_name,$dg_id,$comment,0,$high_res_timestamp``

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### ECS field reference

{{fields "panos"}}

### Example event

{{event "panos"}}

### Inputs

These inputs can be used in this integration:

* [tcp](https://www.elastic.co/docs/reference/integrations/tcp)
* [udp](https://www.elastic.co/docs/reference/integrations/udp)
* [logfile](https://www.elastic.co/docs/reference/integrations/filestream)
