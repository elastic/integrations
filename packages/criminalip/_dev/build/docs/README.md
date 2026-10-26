{{- generatedHeader }}

Copyright (c) 2026 AI Spera Inc. Licensed under the [Apache License, Version 2.0](../LICENSE.txt). See [NOTICE.txt](../NOTICE.txt) for attribution.

The code license does not grant Criminal IP or AI Spera trademark rights beyond section 6 of that license. The separately distributed Cortex analyzer and third-party dependencies retain their own applicable licenses.

Maintained by [Jang Sihoo (@0xhoo)](https://github.com/0xhoo), AI Spera Inc. This is a community-supported integration; it does not imply Elastic support or official publication approval.

## AI assistance notice

OpenAI Codex was used to assist with code generation, refactoring, and debugging. Maintainers remain responsible for reviewing changes, validating behavior, and deciding what is released.

![Criminal IP](../img/criminalip-wordmark.png)

Use Criminal IP TI Feed indicators to detect matching IPs in ECS-normalized firewall events and investigate the observed communications in Elastic Security. TheHive/Cortex reports and configured IP Report lookups are separate optional investigation paths.

## Before you start

**Primary workflow — firewall TI detection:** prepare firewall logs with common ECS fields, a running collector, a key with Criminal IP TI Feed access, and permissions to install/enable the indicator match rule. Use vendor-specific parsers; this package does not automatically identify arbitrary raw firewall formats on one listener.

Start with **[Logs Criminal IP] Firewall, Threat Intelligence, and Cortex Overview**. Read the traffic, TI alert and optional Cortex sections separately. Installing assets alone does not start collection or enable the rule.

**Optional standalone lookups:** IP Report needs a running Elastic Agent, an IP Report API key and explicitly configured public IPs, but no firewall or Cortex. Use **[Logs Criminal IP] IP Intelligence Overview** for that path. It is not automatic network monitoring; every periodic lookup consumes API usage.

| Feature | What you need | Required connection |
| --- | --- | --- |
| Firewall visibility | Elastic Agent and a supported firewall configured to forward logs | Firewall to the Agent's TCP or UDP listener |
| TI match alerts | Firewall logs, Elastic Agent, a key with Criminal IP TI Feed access, and the installed/enabled indicator match rule | Agent to the TI Feed endpoint; firewall to its collector |
| Optional Cortex analysis | TheHive, Cortex, the custom Criminal IP analyzer, an IP Report API key, an Elasticsearch endpoint, and an Elasticsearch write API key | TheHive to Cortex; analyzer to Criminal IP and Elasticsearch |
| Optional configured IP Report lookups | Elastic Agent, a Criminal IP key with IP Report access, and explicitly configured public IPs | Agent to the Criminal IP API |

For every feature, prepare an Elastic deployment that meets the package's Kibana requirement, `^9.5.3`, with Elastic Security available. Your Kibana user needs permission to install the package and read the relevant data. Agent management and detection rule management require their corresponding permissions.

For Cortex, TheHive also needs a Cortex API key with analyzer execution permissions in the correct organization. This key is separate from the Criminal IP key and Elasticsearch key.

Obtain the Criminal IP keys and API access through your organization's Criminal IP account. IP Report and TI Feed access can require different entitlements; confirm access to the feature you selected before configuring collection.

Installing the integration provides dashboard and rule assets. Each feature still requires its own connection settings and data source. Cortex writes directly to Elasticsearch and does not require Elastic Agent or the indicator match rule.

## What information you receive

| Source | Available information | Where to view it |
| --- | --- | --- |
| Firewall events | Event time, source/destination IPs and ports, protocol, raw action, session state, and vendor/product when available | Firewall dashboard panels and Discover |
| TI Feed | IP indicators, provider, reason, confidence, score, and first/last seen values when supplied | Discover: `logs-criminalip.ti_feed-*` |
| Indicator match alerts | Firewall events matching a feed indicator, match evidence, and alert workflow status | Elastic Security Alerts and TI dashboard panels |
| Optional Cortex analysis | Analysis time, IP, classification, summary, inbound/outbound risk, hostname, organization, and ASN when available | Cortex dashboard panels and `criminalip-cortex-results*` in Discover |
| Optional IP Report | Investigated IP, inbound/outbound scores, and available VPN, Tor, proxy, scanner, dark web, hosting, and cloud flags | IP Intelligence Overview and Discover: `logs-criminalip.ip_report-*` |

IP Report collection and Cortex analysis are separate paths. An IP queried by the Agent does not automatically appear in the Cortex panels.

## How this helps

- Compare supported firewall vendors using common ECS fields.
- Identify frequently observed source IPs and review allowed, denied, and session events.
- Prioritize events matching Criminal IP indicators and inspect their actual match evidence.
- Investigate a public IP from TheHive and review the resulting context in Elastic.
- Compare an IP's latest analysis with its stored history.

These results support investigation. A match or suspicious classification alone does not prove a successful attack. Automatic IP blocking and response actions are outside the current scope.

## Setup

### 1. Install the integration

Install the supplied package in the target Kibana Space using your organization's custom integration installation process. Then open:

`[Logs Criminal IP] Firewall, Threat Intelligence, and Cortex Overview` for the primary detection/investigation workflow. `[Logs Criminal IP] IP Intelligence Overview` is for optional explicitly configured IP lookups, not observed firewall communications.

For firewall detection, follow **Collect firewall logs**, then **Collect TI Feed indicators and enable alerts** below. Cortex and configured IP lookups can be used independently; configure only the paths you need. Existing dashboard IDs and stored data are retained.

Configure the features you selected below. Uploading a package and completing installation are separate steps; neither starts collection by itself. Open the managed dashboard from the installed assets, since existing custom dashboard copies do not receive its updates automatically.

### 2. Collect firewall logs

#### Configure the Agent listener

1. Register the collection server in Fleet and confirm that its Agent is `Healthy`.
2. Enable **FortiGate logs (UDP)** or **FortiGate logs (TCP)**.
3. Set **Listen address** to the receiving address and port. The default is `0.0.0.0:9514`.
4. Save the policy and confirm that it is applied. Allow traffic from the firewall to the selected listener.

`0.0.0.0` listens on all local IPv4 interfaces. The firewall must send to an actual, reachable IP of the Agent server, using the same protocol and port. Binding to one local IP limits which interface receives traffic. Check routing and port exposure in Docker, VM, or WSL deployments. A healthy Agent does not establish that syslog messages are arriving.

#### Configure the FortiGate sender

The TCP listener uses RFC 6587 framing for FortiGate reliable syslog. It accepts octet-counted messages (a byte length followed by the message) and legacy newline-delimited messages, including multiple messages on a persistent connection.

Set the remote syslog destination to the Agent server IP. The following is a **UDP/9514 example**; adapt it to your FortiOS version, VDOM, and existing configuration.

```text
config log syslogd setting
    set status enable
    set server "<AGENT_SERVER_IP>"
    set mode udp
    set port 9514
    set format default
end
```

Replace `<AGENT_SERVER_IP>` with the collection server address. Use the default FortiGate key=value format, enable the required traffic logging and syslog filters, and confirm receipt at the receiver. A UDP send success message does not confirm delivery.

Reference: [FortiGate syslog configuration](https://docs.fortinet.com/document/fortigate/7.0.0/cli-reference/456620/config-log-syslogd-setting).

#### Connect other vendors

Configure the vendor's official Elastic integration separately for Palo Alto PAN-OS, Juniper SRX, or Cisco ASA/FTD. The dashboard currently includes:

`criminalip.fortigate`, `fortinet_fortigate.log`, `panw.panos`, `juniper_srx.log`, `cisco_asa.log`, and `cisco_ftd.log`.

Firewall events need `event.category: network` and source or destination IP fields. Vendor/product labels use `observer.vendor` and `observer.product` when available. Other vendors' inputs are not configured automatically. Cortex is an analysis service shown in a separate dashboard section.

| Firewall | Collector/parser | Dashboard dataset |
| --- | --- | --- |
| FortiGate | Included key=value TCP/UDP collector, or official Fortinet integration | `criminalip.fortigate` or `fortinet_fortigate.log` |
| Palo Alto PAN-OS | Official vendor integration configured separately | `panw.panos` |
| Juniper SRX | Official vendor integration configured separately | `juniper_srx.log` |
| Cisco ASA / FTD | Official vendor integration configured separately | `cisco_asa.log` / `cisco_ftd.log` |

Use `source.ip`, `destination.ip`, available ports and `network.transport` for communication context; `observer.vendor` / `observer.product` for the reporting device; and `event.type` / `event.action` for decisions/session state. Missing action evidence stays Unclassified, not Allowed. Installing a vendor package or receiving a system syslog message does not prove that real forwarded traffic is being logged correctly.

### 3. Collect TI Feed indicators and enable alerts

1. Enable **Criminal IP Threat Intelligence Feed** in the Agent policy.
2. Enter a key with TI Feed access, the feed URL, and the interval. Defaults are `https://dl.criminalip.io/ti/v1/feed/outbound` and `5m`; confirm that they suit your subscription.
3. Verify indicators in `logs-criminalip.ti_feed-*` with `threat.indicator.ip`.
   Observation times in `criminalip.ti_feed.first_seen` and `criminalip.ti_feed.last_seen` are normalized to ISO 8601. Feed timestamps without an offset are interpreted as UTC; confirm the source timezone when using a custom feed. Invalid observation dates are omitted and reported in `error.message` while retaining the IP indicator. Updating the package affects new ingestion; previously ignored date fields require separate reprocessing.
   Numeric confidence is retained in `criminalip.ti_feed.confidence`. The ECS keyword `threat.indicator.confidence` uses the STIX 0–100 bands: 0 = None, greater than 0 and below 30 = Low, 30 to below 70 = Medium, and 70–100 = High. Out-of-range numeric values are retained with the label Not Specified; missing confidence is omitted. Existing indices that mapped ECS confidence as a number require a planned mapping migration/reindex; updating this package does not rewrite historical mappings.
4. In **Security → Rules → Add Elastic rules**, install `Criminal IP Firewall Indicator Match`.
5. Check collection and rule permissions, then enable the rule.

The rule compares firewall `source.ip` or `destination.ip` with TI Feed `threat.indicator.ip`. It runs every minute, searches the previous six minutes of firewall events using `event.ingested` (falling back to `@timestamp` when `event.ingested` is missing), and searches indicators within the previous 30 days. This allows delayed firewall logs to match based on their ingestion time without changing their original event timestamp. Events without `event.ingested` still depend on their original timestamp being within the search window.

The feed is polled as a snapshot and unchanged indicators are currently republished each interval. At the default five-minute interval this can produce 288 copies per active IP per day. Plan retention and the indicator search window for your feed volume. A latest-indicator destination with refresh and expiry handling is not included; suppressing repeat events alone would let still-active indicators age out of detection.

The feed key is sent as a query parameter required by the provider. Transport and decoding failures emit fixed messages without the request URL or key. Per-request automatic retries are disabled because the Agent retry logger can log query-string credentials before CEL error handling; the next configured polling interval attempts collection again. Do not enable request tracing without reviewing credential redaction.

Review the rule's source indices before enabling it: the packaged default is `logs-*` with ECS network/IP conditions, so other network datasets can also match. Narrow the source scope to your intended firewall indices when necessary. Dashboard traffic panels include the listed firewall datasets; detection scope and displayed traffic scope must be checked together.

The packaged rule is disabled by default with no external actions. Collection or Cortex analysis success alone does not create match alerts. Zero alerts can be expected when no firewall event matches a feed indicator in the search windows.

### 4. Connect TheHive/Cortex (optional investigation)

**Already using Cortex?** Keep your existing services, organizations, and users. Install the separate Criminal IP analyzer, enter its four connection settings, and use your existing TheHive connection. There is no need to deploy another TheHive/Cortex stack or install Docker if you use host execution.

**No Cortex environment?** Use the firewall/TI workflow or optional IP Report collection first. Building a case-management/analysis platform is optional. Follow StrangeBee's supported deployment and license guidance if you need those platforms.

#### Prepare the services and analyzer

Run TheHive, Cortex, and their dependencies with versions and roles supported by your organization. Docker deployments require the related containers and services to be running. WSL is one way to run Linux on Windows; it is not required.

The custom Criminal IP analyzer is distributed separately. It is not included in this package or automatically registered in the official Cortex catalog. Contact the package maintainer for the analyzer's distribution and deployment documentation before enabling this optional path.

Reload Cortex while retaining existing analyzers and enable `CriminalIP_2_0` in the intended organization. Consult the separate analyzer README for deployment details.

References: [Cortex with Docker](https://docs.strangebee.com/cortex/installation-and-configuration/run-cortex-with-docker/), [Docker analyzer parameters](https://docs.strangebee.com/cortex/installation-and-configuration/parameters-docker/).

#### Configure the analyzer in Cortex

| Setting | Value |
| --- | --- |
| `key` | Criminal IP API key with IP Report access |
| `timeout` | Request timeout in seconds; default `20`, range `1–120` |
| `elastic_url` | Elasticsearch HTTPS root endpoint, not a Kibana dashboard or Cloud management URL |
| `elastic_api_key` | Elasticsearch API key's **encoded value**, with result-index write permissions |

Use the following Elasticsearch role descriptor. The issuing user must also have the relevant permissions.

To prepare the Elastic connection:

1. Copy the **Elasticsearch endpoint** from your deployment's connection details.
2. Open **API Keys** in Kibana and create a key. Enable custom security privileges and enter the role descriptor below.
3. Copy the new key's **encoded value** when it is displayed. The key ID alone cannot authenticate requests.
4. Save the endpoint and encoded key in the Criminal IP analyzer's organization configuration in Cortex.

```json
{
  "cortex_criminalip_writer": {
    "cluster": [],
    "indices": [
      {
        "names": ["criminalip-cortex-results"],
        "privileges": ["auto_configure", "create_doc"],
        "allow_restricted_indices": false
      }
    ]
  }
}
```

The first successful write can create the result index. Dashboard users need separate read permissions. Keep the writer scoped to the result index and leave restricted index access disabled in Serverless. Store actual keys in secret configuration fields.

#### Connect TheHive and run an analysis

1. Prepare a Cortex organization user/API key with analyzer execution permissions.
2. Connect TheHive to the Cortex URL with that Cortex key and assign the intended organization, following your TheHive version's configuration procedure. TheHive must reach Cortex; `localhost` inside one container does not address another container.
3. Add the **public IP you want to investigate** as an `ip` observable in a TheHive case and run the Criminal IP analyzer.
4. Check the report's `elastic_delivery.status`: `created` confirms document creation; `failed` means delivery failed. An analyzer job can succeed and retain its report even when delivery to Elasticsearch fails.
5. For automatic analysis of newly created observables, configure a supported `CaseObservableCreated` trigger and `RunAnalyzer` notifier in TheHive after verifying manual execution. Check analyzer selection, organization, permissions, and TLP/PAP limits.

The analyzer rejects private, reserved, loopback, and other non-public addresses. Queries send the investigated IP to Criminal IP and consume API usage.

The result path is:

`TheHive observable → Cortex → Criminal IP API → Elasticsearch summary → Kibana dashboard`

The integration does not automatically forward Elastic alerts or TI Feed entries to TheHive. Cortex result delivery does not create firewall match alerts.

### 5. Optional configured IP Report lookups

1. Register an Elastic Agent in Fleet and add the Criminal IP integration to its policy.
2. Explicitly enable the **Criminal IP API** stream, which is disabled by default. Installing TI Feed collection alone does not opt into these quota-consuming lookups.
3. Enter an IP Report key and the primary public **IP Address** to investigate. For more IPs, use **Additional IP Addresses → Add row**, one IP per row, not comma-separated values.
4. Set the API URL and collection interval, save the policy, and confirm that the Agent receives it.

Default API endpoint: `https://api.criminalip.io/v1/asset/ip/report`.

The primary and additional IPs are queried sequentially each interval. Existing single-IP policies continue to work. Empty additional rows are ignored and identical values after trimming whitespace are queried once per cycle. Failed requests do not discard other results; every request retains its configured value in `criminalip.query_ip`, including HTTP-200 responses containing an application-level failure or no usable IP report.

These are fixed lookups, not automatic extraction from logs. The configured IP does not have to be your own. Each distinct IP consumes API usage per cycle: ten IPs at five-minute intervals can make about 2,880 requests per day, before retries or restarts. Large lists take longer to complete; this is not bulk threat-feed import. Use one collecting Agent per configured report input unless duplicated API calls are intentional.

Open **[Logs Criminal IP] IP Intelligence Overview** for stored report totals, collection times, inbound-risk distribution and history. Latest Results by IP takes all fields from the same newest successful document in the selected period. Repeated lookups remain in history; tables show up to 100 entries with ten rows per page. Missing flags are Not Available, not No. Collection time is not provider observation time, and risk distributions count snapshots rather than unique IPs. Failed collections are excluded from result tables. Use Discover for complete history.

An IP report does not prove that your network communicated with the IP and does not generate a firewall match alert.

## Verify that it works

In Discover, select the data view and enter the KQL in the **main search bar**. Start with a recent period and expand it if necessary.

| Feature | Data view | Verification query |
| --- | --- | --- |
| IP Report | `logs-criminalip.ip_report-*` | `threat.indicator.ip: "<QUERIED_IP>"` |
| TI Feed | `logs-criminalip.ti_feed-*` | `threat.indicator.ip:*` |
| FortiGate logs | `logs-*` | `event.dataset: "criminalip.fortigate"` |
| ECS network events | `logs-*` | `event.category: network and (source.ip:* or destination.ip:*)` |
| Cortex results | `criminalip-cortex-results*` | `event.dataset: "criminalip.cortex" and criminalip.ip: "<ANALYZED_PUBLIC_IP>"` |

Replace the IP placeholders. For firewall documents, check timestamps, IP fields, category, action, and parsing errors. For alerts, check rule execution results and match evidence in Elastic Security Alerts.

After documents arrive, open the managed dashboard. Cortex panels query the result index directly; a Cortex data view is needed only for Discover.

### Distinguish test evidence from operational validation

- Synthetic vendor-format events verify parser/mapping/rule behavior only; they are not evidence of real attacks or physical appliance interoperability.
- Receipt of a virtual FortiGate system syslog message verifies that sender/receiver path, not real forwarded traffic or every FortiOS event type.
- Real forwarded traffic must be verified separately using the intended firewall policy, logging configuration and license.
- PAN-OS, SRX and ASA/FTD real-device support must be validated with their configured collectors and representative versions; dashboard dataset compatibility alone is not certification.
- The production-oriented firewall/TI dashboard excludes `firewall_lab` and `synthetic` events. Inspect synthetic events in a dedicated test data view/dashboard; preserve their labels rather than removing them to make production panels populate. Review whether a test rule should be isolated from operational alerts.
- TheHive manual analyzer execution, automatic execution on observable creation, Elastic delivery and dashboard rendering are separate checks. Test each advertised path; manual success does not prove automation.

### Validate synthetic events with the packaged test dashboard

Starting with 0.1.0, open **[Logs Criminal IP] Firewall and TI Validation · Synthetic
Only**. This is a separate managed asset with a stable ID; it does not overwrite
the production dashboard or existing user-created copies. All firewall summary,
action, source/vendor, recent-event, alert-summary/trend/investigation panels and
the matched-IP evidence chart require `tags: synthetic`. The `firewall_lab`
namespace alone is not sufficient. Cortex is intentionally omitted because it
is a separate investigation path, not synthetic firewall traffic.

Use a dedicated lab input tagged `synthetic`, select the test time range (default
last hour), and clear inherited global queries. Optionally filter a vendor using
`event.dataset`, for example `event.dataset: "juniper_srx.log"`. Neither dashboard
starts collection or enables detection rules. The production dashboard continues
to exclude synthetic/firewall_lab events. Investigation timestamp columns have
explicit display widths in both assets, without changing stored field types.

No manual query changes are required for the packaged synthetic-only dashboard.
Preserve the `synthetic` tag on test logs and derived alerts. For official vendor
inputs dedicated to the lab, configure the input tags to include `synthetic`;
do not tag operational inputs as synthetic. Traffic summaries count original
logs and alert tables count rule matches, so their totals need not be equal.
For customizations, duplicate a managed dashboard and save the copy separately.

## Understand the dashboard

### Investigation workflow

1. Find a Criminal IP rule alert and review its actual source/destination match evidence and indicator context in Elastic Security Alerts.
2. Read both communication endpoints, the reporting firewall, its raw action and the normalized action/session state. Source is not always the attacker or an internal host; use addresses, zones and network direction where available to interpret the event.
3. Open the alert's original event in Elastic Security/Discover and inspect the relevant time range for repeated activity and other affected endpoints. Alert creation time and original event time are different fields.
4. If more context is needed, investigate the observed public IP with the optional TheHive/Cortex analyzer or configured IP Report lookup. This is a separate user-initiated path, not automatic alert enrichment.
5. Record the investigation decision. A feed match, a denied connection and a successful compromise are different outcomes. No automatic blocking is performed.

### Firewall activity

Review event totals, unique IPs, action/session categories, top sources, vendor/product comparisons, hourly trends, and recent details.

Allowed/denied classification uses ECS `event.type` and explicit custom FortiGate actions as a fallback. `event.outcome: failure` is not treated as denial. Start, end, and timeout events describe session state rather than proving an allowed or denied connection.

Comparison charts exclude IPv6 multicast destinations in `ff00::/8`; summary and recent-event tables retain them, so totals can differ. Firewall/TI panels exclude the `firewall_lab` namespace and events tagged `synthetic`. Firewall dates/times follow Kibana's configured time zone.

### Indicator match alerts

Review totals, **Open / Acknowledged / Closed** counts, hourly trends, top matched IPs, and recent alerts for the fixed Criminal IP rule ID.

The recent-alert table also shows available original event time, reporting vendor/product, raw action, normalized action/session state, transport and ports. Missing fields remain unavailable; never infer a firewall decision from rule severity or alert workflow status. Open the alert details to establish which endpoint matched and inspect the TI provider/description; the two endpoint columns are not both necessarily malicious.

Matched IPs come from `threat.enrichments.matched.atomic` and source/destination match evidence. Duplicate indicators for one IP in one alert count once. One alert can match multiple IPs, so IP-specific totals can exceed total alerts.

The alert panels use the **default Space** alias, `.alerts-security.alerts-default`. For another Space, update every alert ES|QL `FROM` and the matched IP visualization's `data.url.index` to `.alerts-security.alerts-<space-id>`. Before the first alert, a missing alert index can produce a panel error.

### Cortex results

**Cortex · Latest Results by IP** selects the newest stored document per IP within the chosen period. All attributes come from that same document. **Analyses in Selected Period** counts stored documents in the chosen period, not lifetime queries.

**Cortex · Recent Analysis History** lists individual results in descending analysis time order. A repeated analysis that is successfully delivered adds a document, updates the latest result when it falls in the selected period, and remains in the history.

The latest table shows up to 100 IPs in IP order; history shows the latest 100 records. Both show ten rows per page and analysis time in **UTC**. Unavailable attributes display as `Not Available`. Use Discover for the complete history.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| No IP Report or TI Feed data | API key/endpoint, plan access, Agent policy, Agent logs, and rate limits |
| Agent is healthy but no firewall logs arrive | Reachable destination IP, matching protocol/port, sender logging, routing, and network access |
| Old logs are missing from a recent search | Event timestamps and time range |
| Firewall logs arrive but no match alerts appear | Rule installation/enabled state, permissions, event/indicator time windows, and an actual IP match |
| TheHive has a report but no Elastic Cortex document | `elastic_delivery`, Elasticsearch root URL, encoded key, key permissions/expiry, and connectivity |
| Cortex job fails with `AccessDeniedException` | Check the Cortex process UID/GID and job-directory mount permissions using the separately distributed analyzer's deployment documentation |
| Discover shows a result but the dashboard does not | Managed dashboard version, time range, filters, and read permissions |
| An updated dashboard still displays previous labels | Open the managed dashboard, review any unsaved changes, choose **More → Reset changes**, then reload the page to clear the previous browser state |
| Empty panels after installation | Whether the corresponding feature is configured and has produced data |
| Alert panel errors in a new or different Space | Alert index existence and the Space-specific alias |

A dashboard-wide `event.category: network` filter hides Cortex documents, which use the threat category. Event, connection, attack, and alert counts describe different things.

Local validation checks package structure and generated assets. Installation, permissions, data arrival, and rendering still require verification in the target Kibana environment. Package installation does not migrate old data, API keys, or Agent registrations.

## Reference

- [FortiGate syslog configuration](https://docs.fortinet.com/document/fortigate/7.0.0/cli-reference/456620/config-log-syslogd-setting)
- [Cortex with Docker](https://docs.strangebee.com/cortex/installation-and-configuration/run-cortex-with-docker/)
- [Elasticsearch document creation](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-create)
- [Install detection rules](https://www.elastic.co/docs/solutions/security/detect-and-alert/install-prebuilt-rules)
- [ES|QL time zones](https://www.elastic.co/docs/explore-analyze/query-filter/languages/esql-kibana#timezone-handling)
- [ECS threat match fields](https://www.elastic.co/docs/reference/ecs/ecs-threat)
- [Vega dashboard filters](https://www.elastic.co/docs/explore-analyze/visualize/custom-visualizations-with-vega)

The FortiGate `date` and `time` fields populate `@timestamp`; when `tz` is present, its offset is applied. Repeated `tz` fields use the first valid offset, and forms such as `UTC-5:00` are normalized to `-0500`. If the log has no timezone, the timestamp is interpreted as UTC. The original date, time, and `eventtime` remain available under `fortigate.*`, and `event.ingested` records receipt time.
