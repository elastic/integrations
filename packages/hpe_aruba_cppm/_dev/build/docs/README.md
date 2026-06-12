{{- generatedHeader }}
{{/*
This template can be used as a starting point for writing documentation for your new integration. For each section, fill in the details
described in the comments.

Find more detailed documentation guidelines in https://www.elastic.co/docs/extend/integrations/documentation-guidelines
*/}}
# HPE Aruba ClearPass Policy Manager (CPPM) Integration for Elastic

## Overview
{{/* Complete this section with a short summary of what data this integration collects and what use cases it enables */}}
The HPE Aruba ClearPass Policy Manager (CPPM) integration collects structured syslog events from ClearPass Policy Manager and normalizes them into ECS.
This integration facilitates monitoring network access control activity, reviewing authentication and accounting outcomes, and correlating user and device access activity with other telemetry in Elastic.

### Compatibility
{{/* Complete this section with information on what 3rd party software or hardware versions this integration is compatible with */}}
This integration is compatible with HPE Aruba ClearPass Policy Manager syslog events. It is designed to work with the structured syslog format emitted by ClearPass, which may require specific configuration on the ClearPass side.

### How it works
{{/* Add a high level overview on how this integration works. For example, does it collect data from API calls or recieving data from a network or file.*/}}
Elastic Agent listens for ClearPass syslog messages over TCP or UDP. ClearPass forwards structured syslog events to the Agent, and the ingest pipelines parse the syslog header plus the ClearPass structured-data blocks before routing authentication and accounting events into dedicated normalization pipelines.

## What data does this integration collect?
{{/* Complete this section with information on what types of data the integration collects, and link to reference documentation if available */}}
The HPE Aruba ClearPass Policy Manager integration collects log messages of the following types:
* Authentication and access decision events.
* RADIUS accounting and session update events.
* ClearPass service, role, enforcement profile, and diagnostic context associated with those events.

### Supported use cases
{{/* Add details on the use cases that can be enabled by using this integration. Explain why a user would want to install and use this integration. */}}
This integration helps investigate failed 802.1X, EAP, PAP, and MAC authentication attempts, audit policy enforcement decisions, track endpoint and user identities involved in network access requests, and correlate ClearPass activity with network, identity, and security data already stored in Elastic.

## What do I need to use this integration?
{{/* List any vendor-specific prerequisites needed before starting to install the integration. */}}
You need an HPE Aruba ClearPass Policy Manager deployment that can forward syslog events to Elastic Agent, network connectivity between ClearPass or an intermediate syslog relay and the Agent listener, and an Elastic deployment with Fleet and Elastic Agent available.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog or log file receiver and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

{{/* If agentless is available for this integration, we'll want to include that here as well.
### Agentless deployment

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. Agentless deployments provide a means to ingest data while avoiding the orchestration, management, and maintenance needs associated with standard ingest infrastructure. Using an agentless deployment makes manual agent deployment unnecessary, allowing you to focus on your data instead of the agent that collects it.

For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html)
*/}}

### Onboard / configure
{{/* List the steps that will need to be followed in order to completely set up a working integration.
For integrations that support multiple input types, be sure to add steps for all inputs.
*/}}
1. In Fleet, add the HPE Aruba ClearPass Policy Manager integration to an Elastic Agent policy.
2. Choose either the TCP or UDP input and configure the listener host and port that ClearPass will send syslog messages to.

#### ClearPass configuration

In ClearPass Policy Manager, [configure a syslog target](https://arubanetworking.hpe.com/techdocs/ClearPass/6.12/PolicyManager/Content/CPPM_UserGuide/Admin/syslogTargets.html) that points to the Elastic Agent listener

1. Go to **Administration > External servers > Syslog targets**.
2. Click the **Add** link. The Add Syslog Target dialog opens:
3. Add the following details:
   - **Description**: enter a description for the syslog target.
   - **Host Address**: enter the IP address of the Elastic Agent listener.
   - **Transport protocol**: select either TCP or UDP, depending on which input you configured in Fleet.
   - **Port**: enter the port number of the Elastic Agent listener.

After creating the syslog target, you need to [configure syslog export](https://arubanetworking.hpe.com/techdocs/ClearPass/6.12/PolicyManager/Content/CPPM_UserGuide/Admin/syslogExportFilters_add_syslog_filter_general.htm) so session events are forwarded to the Elastic Agent listener.

1. Go to **Administration > External servers > Syslog export filters**.
2. Click **Add**.
3. In the **Add Syslog Filters** window that appears, in the **General** tab, complete the following fields:
   - **Name**: enter the syslog export filter name of your choice.
   - **Export template**: select the `Session Logs` export template.
   - **Export event format type**: select `RFC5424`.
   - **Syslog servers**: select the Elastic Agent listener.
4. In the **Export template** list, when you select the **Session** export templates, the **Filter and columns** tab is enabled. Complete the following steps (see [Aruba ClearPass documentation for more details on export templates and field groups](https://arubanetworking.hpe.com/techdocs/ClearPass/6.12/PolicyManager/Content/CPPM_UserGuide/Admin/syslogExportFilters_add_syslog_filter_filterandcolumns.htm)):
   - Click the **Filter and columns** tab.
   - **Data filter**: verify that the default value `All requests` is selected.
   - **Selected columns**: verify that all fields in this list are compatible with the fields parsed by this integration. You can add or remove fields from this list, but be aware that removing fields may result in missing data in Elastic and adding unsupported fields may cause parsing errors. The fields parsed by this integration are listed in the Reference section inside this document `ClearPass field reference compatibility`.
   - Click the **Summary** tab.
   - Click **Save**.

### Validation
{{/* How can the user test whether the integration is working? Including example commands or test files if applicable */}}
Generate a known authentication or accounting event in ClearPass, then verify in Discover or Logs that documents arrive in the `logs-aruba_cppm.session-*` data stream. Confirm that fields such as `event.action`, `event.outcome`, `user.name`, `source.mac`, and `service.name` are populated, and enable `Preserve original event` when you need to compare the parsed fields with the raw syslog line.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).
{{/*
Add any vendor specific troubleshooting here.

Are there common issues or “gotchas” for deploying this integration? If so, how can they be resolved?
If applicable, links to the third-party software’s troubleshooting documentation.
*/}}
If events do not parse as expected, first confirm that ClearPass is sending the structured syslog format expected by this package and that any intermediate syslog relay is not rewriting the message body. When troubleshooting parsing issues, enable `Preserve original event` so you can inspect the full raw event in `event.original`.

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.
{{/* Add any vendor specific scaling information here */}}
For higher event volumes, prefer TCP over UDP when delivery guarantees are important, deploy Elastic Agent close to the syslog source or relay, and use an intermediate syslog tier if ClearPass needs to fan out events to multiple downstream consumers.

## Reference
{{/* Repeat for each data stream of the current type
### {Data stream name}

The `{data stream name}` data stream provides events from {source} of the following types: {list types}.

For each data_stream_name, include an optional summary of the datastream, the exported fields reference table and the sample event.

The fields template function will be replaced by a generated list of all fields from the `fields/` directory of the data stream when building the integration.

#### {data stream name} fields

To include a generated list of fields from the `fields/` directory, uncomment and use:
{{ fields "data_stream_name" }}

The event template function will be replace by a sample event, taken from `sample_event.json`, when building this integration.

To include a sample event from `sample_event.json`, uncomment and use:
{{ event "data_stream_name" }}

*/}}

### Session logs

The `session` data stream provides ClearPass authentication and accounting syslog events, including user and device identity data, policy outcomes, service names, role assignments, and diagnostic details.

#### ClearPass field reference compatibility
The following lists commonly used fields from ClearPass structured syslog messages that are parsed and mapped to ECS by this integration.

- `Auth.Enforcement-Profiles`
- `Auth.Host-IP-Address`
- `Auth.Host-MAC-Address`
- `Auth.Login-Status`
- `Auth.NAS-IP-Address`
- `Auth.Protocol`
- `Auth.Roles`
- `Auth.Service`
- `Auth.Source`
- `Auth.System-Posture-Token`
- `Auth.Username`
- `Common.Alerts`
- `Common.Enforcement-Profiles`
- `Common.Error-Code`
- `Common.Host-MAC-Address`
- `Common.NAS-IP-Address`
- `Common.Request-Timestamp`
- `Common.Roles`
- `Common.Service`
- `Common.System-Posture-Token`
- `Common.Username`
- `CppmAlert.Alerts`
- `CppmConfigAudit.Action`
- `CppmConfigAudit.Category`
- `CppmConfigAudit.Name`
- `CppmConfigAudit.Updated-At`
- `CppmConfigAudit.Updated-By`
- `CppmErrorCode.Error-Code-Details`
- `CppmNode.CPPM-Node`
- `CppmSystemEvent.Action`
- `CppmSystemEvent.Category`
- `CppmSystemEvent.Level`
- `CppmSystemEvent.Source`
- `CppmSystemEvent.Timestamp`
- `Endpoint.Added-At`
- `Endpoint.Antispyware-APT`
- `Endpoint.Antispyware-Input`
- `Endpoint.Antispyware-Output`
- `Endpoint.Antivirus-APT`
- `Endpoint.Antivirus-Input`
- `Endpoint.Antivirus-Output`
- `Endpoint.Conflict`
- `Endpoint.Device-Category`
- `Endpoint.Device-Family`
- `Endpoint.Device-Name`
- `Endpoint.DiskEncryption-APT`
- `Endpoint.DiskEncryption-Input`
- `Endpoint.DiskEncryption-Output`
- `Endpoint.Firewall-APT`
- `Endpoint.Firewall-Input`
- `Endpoint.Firewall-Output`
- `Endpoint.Hostname`
- `Endpoint.IP-Address`
- `Endpoint.MAC-Address`
- `Endpoint.MAC-Vendor`
- `Endpoint.Posture-Healthy`
- `Endpoint.Posture-Unhealthy`
- `Endpoint.Status`
- `Endpoint.System-Agent-Type`
- `Endpoint.System-Agent-Version`
- `Endpoint.System-Client-OS`
- `Endpoint.System-Posture-Token`
- `Endpoint.Updated-At`
- `Endpoint.Usermame`
- `Endpoint.Username`
- `Guest.Created-At`
- `Guest.Enabled`
- `Guest.Expires-At`
- `Guest.MAC-Address`
- `Guest.Role-Name`
- `Guest.Starts-At`
- `Guest.Username`
- `Guest.Visitor-Company`
- `Guest.Visitor-Name`
- `OnboardCert.Issuer`
- `OnboardCert.Mac-Address`
- `OnboardCert.Revoked-At`
- `OnboardCert.Subject`
- `OnboardCert.Username`
- `OnboardCert.Valid-From`
- `OnboardCert.Valid-To`
- `OnboardEnrollment.Added-At`
- `OnboardEnrollment.Device-Name`
- `OnboardEnrollment.Device-Product`
- `OnboardEnrollment.Device-Version`
- `OnboardEnrollment.MAC-Address`
- `OnboardEnrollment.Updated-At`
- `OnboardEnrollment.Username`
- `OnboardOCSP.Remote-Address`
- `OnboardOCSP.Response-Status-Name`
- `OnboardOCSP.Timestamp`
- `RADIUS.Acct-Calling-Station-Id`
- `RADIUS.Acct-Framed-IP-Address`
- `RADIUS.Acct-Input.Octets`
- `RADIUS.Acct-Input-Pkts`
- `RADIUS.Acct-NAS-IP-Address`
- `RADIUS.Acct-NAS-Port`
- `RADIUS.Acct-NAS-Port-Type`
- `RADIUS.Acct-Output-Octets`
- `RADIUS.Acct-Output-Pkts`
- `RADIUS.Acct-Service-Name`
- `RADIUS.Acct-Session-Id`
- `RADIUS.Acct-Session-Time`
- `RADIUS.Acct-Timestamp`
- `RADIUS.Acct-Username`
- `RADIUS.Auth-Method`
- `RADIUS.Auth-Source`
- `Radius.Calling-Station-Id`
- `Radius.Duration`
- `Radius.End-Time`
- `Radius.Framed-IP-Address`
- `Radius.Input-bytes`
- `Radius.NAS-IP-Address`
- `Radius.Output-bytes`
- `Radius.Start-Time`
- `Radius.Username`
- `tacacs.Acct-Flags`
- `tacacs.Auth-Source`
- `tacacs.Enforcement-Profiles`
- `tacacs.NAS-IP-Address`
- `tacacs.Privilege.Level`
- `tacacs.Privilege-Level`
- `tacacs.Remote-Address`
- `tacacs.Request-Type`
- `tacacs.Roles`
- `tacacs.Service`
- `tacacs.Username`
- `WEBAUTH.Host-IP-Address`

#### Session log fields

{{ fields "session" }}

### Inputs used
{{/* All inputs used by this package will be automatically listed here. */}}
{{ inputDocs }}