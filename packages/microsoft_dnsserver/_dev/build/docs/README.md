# Microsoft DNS Server Audit and Analytical logs

The Elastic integration for DNS Server logs is designed to facilitate the collection, aggregation, and analysis of DNS logs from both Audit and Analytical categories. By capturing detailed DNS event data, this integration enables organizations to enhance their visibility into DNS transactions, detect potential security threats, and optimize their network performance. Leveraging the powerful capabilities of Elastic Stack, this integration provides real-time insights and analytics, empowering IT and security teams to quickly respond to incidents and maintain robust network infrastructure integrity.

## Data streams

The Microsoft DNS Server integration collects two type of data: audit and analytical.

**Analytical** events represent the bulk of DNS events, an analytic event is logged each time the server sends or receives DNS information.

**Audit** events enable change tracking on the DNS server. An audit event is logged each time server, zone, or resource record settings are changed. This includes operational events such as dynamic updates, zone transfers, and DNSSEC zone signing and unsigning.

## Requirements

- Elastic Agent must be installed.
- You can install only one Elastic Agent per host.

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

This integration is supported in every Windows versions supported by [`Filebeat`](https://www.elastic.co/support/matrix), starting from Windows 10 and Windows Server 2016.

The minimum **kibana.version** required is **8.13.0**.

## Configuration
 
DNS analytical events are not enabled by default. To enable it, you can follow the [guide to enable DNS diagnostics logging](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn800669(v=ws.11)#to-enable-dns-diagnostic-logging) of Microsoft's documentation.

**Note:**  DNS logging and diagnostics feature in Windows is designed to have a very low impact on performance. However, according to the [Audit and analytic event logging section](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn800669(v=ws.11)#audit-and-analytic-event-logging) of the docs, typically will only affect DNS server performance at very high DNS query rates. For example, a DNS server running on modern hardware that is receiving 100,000 queries per second (QPS) can experience a performance degradation of 5% when analytic logs are enabled.

## Usage

**DNS Analytical** events are collected through [Event Tracing for Windows (ETW)](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-etw.html), a mechanism that allows real-time logging and capturing of Windows system events. This collection can be done either by initiating a new ETW session to gather logs directly from the DNS Server provider or by reading pre-existing logs from a .etl (Event Trace Log) file.

This integration provides a native filtering mechanism called `Match All Keyword`. This filter uses a 64-bit bitmask to specify which events to capture based on their defined keywords. Each keyword corresponds to a specific type of event detailed in the DNS Server provider's manifest.

To view these keywords and understand what types of events can be traced, you can run the following command in a command prompt: `logman query providers "Microsoft-Windows-DNSServer"`. Here is an example of the output:

```text
PS> logman query providers "Microsoft-Windows-DNSServer"

Provider                                 GUID
-------------------------------------------------------------------------------
Microsoft-Windows-DNSServer              {EB79061A-A566-4698-9119-3ED2807060E7}

Value               Keyword              Description
-------------------------------------------------------------------------------
0x0000000000000001  QUERY_RECEIVED
0x0000000000000002  RESPONSE_SUCCESS
0x0000000000000004  RESPONSE_FAILURE
0x0000000000000008  IGNORED_QUERY
0x0000000000000010  RECURSE_QUERY_OUT
0x0000000000000020  RECURSE_RESPONSE_IN
0x0000000000000040  RECURSE_QUERY_DROP
0x0000000000000080  DYN_UPDATE_RECV
0x0000000000000100  DYN_UPDATE_RESPONSE
0x0000000000000200  IXFR_REQ_OUT
0x0000000000000400  IXFR_REQ_RECV
0x0000000000000800  IXFR_RESP_OUT
0x0000000000001000  IXFR_RESP_RECV
0x0000000000002000  AXFR_REQ_OUT
0x0000000000004000  AXFR_REQ_RECV
0x0000000000008000  AXFR_RESP_OUT
0x0000000000010000  AXFR_RESP_RECV
0x0000000000020000  XFR_NOTIFY_IN
0x0000000000040000  XFR_NOTIFY_OUT
0x0000000000080000  AUDIT_ZONES
0x0000000000100000  AUDIT_REC_ADMIN
0x0000000000200000  AUDIT_ZONESCOPE
0x0000000000400000  AUDIT_ZONE_SIGN
0x0000000000800000  AUDIT_ROLLOVER
0x0000000001000000  AUDIT_FORWARDER
0x0000000002000000  AUDIT_REC_DYN_UPDATE
0x0000000004000000  AUDIT_ROOTHINTS
0x0000000008000000  AUDIT_SERVER_CONFIG
0x0000000010000000  AUDIT_RECURSIONSCOPE
0x0000000020000000  AUDIT_EXPORT_IMPORT
0x0000000040000000  AUDIT_REC_SCAVENGER
0x0000000080000000  AUDIT_CACHE
0x0000000100000000  AUDIT_TRUST_ANCHOR
0x0000000200000000  XFR_NOTIFY_ACK_IN
0x0000000400000000  DYN_UPDATE_FORWARD
0x0000000800000000  INTERNAL_LOOKUP_CNAME
0x0000001000000000  INTERNAL_LOOKUP_ADDITIONAL
0x0000002000000000  AUDIT_SERVER_ADMIN
0x0000004000000000  AUDIT_SERVER
0x0000008000000000  DYN_UPDATE_RESPONSE_IN
0x0000010000000000  XFR_NOTIFY_ACK_OUT
0x0000020000000000  AUDIT_POLICY
0x0000040000000000  RRL_TO_BE_DROPPED_RESPONSE
0x0000080000000000  RRL_TO_BE_TRUNCATED_RESPONSE
0x0000100000000000  RRL_TO_BE_LEAKED_RESPONSE
0x0000200000000000  AUDIT_RRL
0x0000400000000000  AUDIT_TENANT
0x0000800000000000  RECURSE_ALIAS_FAILURE
0x8000000000000000  Microsoft-Windows-DNSServer/Analytical Microsoft-Windows-DNS-Server/Analytical
0x4000000000000000  Microsoft-Windows-DNSServer/Audit Microsoft-Windows-DNS-Server/Audit

Value               Level                Description
-------------------------------------------------------------------------------
0x02                win:Error            Error
0x03                win:Warning          Warning
0x04                win:Informational    Information

PID                 Image
-------------------------------------------------------------------------------
0x00000354          C:\Windows\System32\dns.exe
0x00000354          C:\Windows\System32\dns.exe


The command completed successfully.
```

The output lists various event types with corresponding keywords, allowing you to select which events to monitor. For example, if you want to track recursive queries, you would look for keywords like `RECURSE_QUERY_OUT`, `RECURSE_RESPONSE_IN`, and `RECURSE_QUERY_DROP`. To set up filtering for these specific events, you would calculate the sum of their bitmask values. The result for this particular case would be `0x8000000000000070` (notice that it includes `0x8000000000000000` to match Analytical events as well).

On the other hand, **Audit** events are exposed through Microsoft-Windows-DNS-Server/Audit event log channel.

## Logs reference

### Analytical

{{ fields "analytical" }}

### Audit

{{ fields "audit" }}
