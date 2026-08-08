# Service Info

The Syslog Router integration routes incoming syslog events to the correct Elastic integration data stream using regex pattern matching on the `message` field. It is an Elastic-built routing tool, not a third-party vendor integration.

## Common use cases

- **Centralized syslog ingestion**: Receive syslog from many different network devices on a single port and automatically route each event to its corresponding integration (Cisco ASA, Fortinet FortiGate, Palo Alto Next-Gen Firewall, etc.) for proper parsing.
- **Multi-vendor firewall environments**: Organizations running firewalls and security appliances from multiple vendors can consolidate syslog collection through a single Elastic Agent policy rather than deploying separate inputs per vendor.
- **Rapid onboarding of syslog sources**: Add support for new device types by adding a single `if/then` block with a regex pattern, without needing to deploy additional agents or inputs.

## Data types collected

This integration collects syslog events (raw log lines) and does not parse them itself. It routes each event to the target integration's data stream, where the actual parsing happens in that integration's ingest pipeline.

- **Single data stream**: `syslog_router.log` — all incoming events land here initially.
- **Routing mechanism**: Each event is matched against ordered regex patterns on the `message` field. When a match is found, the `_conf.dataset` field is set (e.g. `cisco_asa.log`, `fortinet_fortigate.log`). The `routing_rules.yml` then reroutes the event to the target data stream `{_conf.dataset}`.
- **Ingest pipeline**: Minimal — sets `ecs.version` and handles errors. Actual parsing is performed by the target integration's ingest pipeline.

Events that do not match any pattern, such as custom logs, would remain in the `syslog_router.log` data stream. We recommend against relying on unmatched events in production. The best practice in such cases is to create a custom integration (for example, with Automatic Import) and route to it.

### Inputs

| Input      | Default address       | Default port | Enabled by default |
| ---------- | --------------------- | ------------ | ------------------ |
| TCP        | `localhost`           | `9514`       | Yes                |
| UDP        | `localhost`           | `9514`       | Yes                |
| Filestream | `/var/log/syslog.log` | N/A          | No                 |

## Compatibility

This integration requires Kibana ^8.14.3 or ^9.0.0, and a basic Elastic subscription.

### Pre-configured routing patterns (22 integrations)

The following integrations (listed here alphabetically, but processed in a different order) are supported out of the box. The target integration's assets must be installed in Kibana before events can be properly indexed.

| Integration                     | Target dataset                   | Regex pattern summary                                   |
| ------------------------------- | -------------------------------- | ------------------------------------------------------- |
| Arista NG Firewall              | `arista_ngfw.log`                | `class com\.untangle\.`                                 |
| Check Point                     | `checkpoint.firewall`            | `CheckPoint [0-9]+ -` (with surrounding spaces)         |
| Cisco ASA                       | `cisco_asa.log`                  | `%ASA-`                                                 |
| Cisco FTD                       | `cisco_ftd.log`                  | `%FTD-`                                                 |
| Cisco IOS                       | `cisco_ios.log`                  | `%\S+-\d-\S+\s?:`                                       |
| Cisco ISE                       | `cisco_ise.log`                  | `CISE_+`                                                |
| Cisco Secure Email Gateway      | `cisco_secure_email_gateway.log` | `(?:(?:amp\|antispam\|...):\s+(?:CEF\|Critical\|...):)` |
| Citrix WAF (CEF only)           | `citrix_waf.log`                 | `CEF:0\|Citrix\|NetScaler`                              |
| Fortinet FortiEDR               | `fortinet_fortiedr.log`          | `enSilo` (with surrounding spaces)                      |
| Fortinet FortiGate              | `fortinet_fortigate.log`         | `devid="?FG`                                            |
| Fortinet FortiMail              | `fortinet_fortimail.log`         | `device_id="?FE`                                        |
| Fortinet FortiManager           | `fortinet_fortimanager.log`      | `device_id="?FMG`                                       |
| Fortinet FortiProxy             | `fortinet_fortiproxy.log`        | `devid="?FPX`                                           |
| Imperva SecureSphere (CEF only) | `imperva.securesphere`           | `CEF:0\|Imperva Inc.\|SecureSphere`                     |
| Iptables                        | `iptables.log`                   | `IN=`                                                   |
| Juniper SRX                     | `juniper_srx.log`                | `RT_UTM -` or `RT_FLOW -`                               |
| Palo Alto Next-Gen Firewall                | `panw.panos`                     | `1,[0-9]{4}/[0-9]{2}/[0-9]{2}`                          |
| QNAP NAS                        | `qnap_nas.log`                   | `qulogd\[[0-9]+\]:`                                     |
| Snort                           | `snort.log`                      | `\[[0-9]:[0-9]+:[0-9]\]`                                |
| Sonicwall Firewall              | `sonicwall_firewall.log`         | `<[0-9]+>  id=firewall sn=[0-9a-zA-Z]+`                 |
| Sophos XG                       | `sophos.xg`                      | `device="SFW"`                                          |
| Stormshield                     | `stormshield.log`                | `id=firewall time="`                                    |

**DISCLAIMER**: Due to subtle differences in how devices emit syslog events, the default patterns may not work in all cases. Some integrations that support syslog are not listed here because their patterns would be too complex or could overlap with other integrations. Custom patterns may need to be created for those cases.

## Scaling and Performance

- **Pattern ordering matters**: Patterns are evaluated in order and stop at the first match. Place stricter (more specific) patterns before broader ones (such as `IN=` used for iptables) to avoid false matches. Place high-traffic integrations near the top to reduce wasted regex evaluations.
- **Regex complexity**: Simpler patterns match faster. Avoid overly broad patterns like `.*` that can cause backtracking.
- **Single data stream routing**: All events flow through one data stream (`syslog_router.log`) and are rerouted at the Elasticsearch level through routing rules, so there is no duplication of data at rest.

## Set Up Instructions

### Prerequisites

The Syslog Router is an Elastic-built tool (not a third-party vendor product), so there are no vendor-side prerequisites. The prerequisites are all on the Elastic side:

- **Elastic Agent**: An Elastic Agent must be installed and enrolled in a Fleet policy on a host that can receive syslog traffic from the network devices.
- **Kibana/Elasticsearch**: Requires Kibana ^8.14.3 or ^9.0.0, with a basic subscription.
- **Target integration assets**: The Elastic integration assets for each target data stream must be installed in Kibana before events can be correctly parsed. For example, to route Cisco ASA syslog events, the Cisco ASA integration assets must be installed first.
- **Network access**: The syslog-sending devices must be able to reach the Elastic Agent host on the configured listen port (default `9514` for TCP/UDP).

### Elastic setup steps

#### 1. Install target integration assets

Before adding the Syslog Router, install the assets for each integration you want to route to:

1. In Kibana, navigate to **Management > Integrations**.
2. Search for the target integration (for example, "Cisco ASA").
3. Navigate to the **Settings** tab and click **Install Cisco ASA assets**. Confirm in the popup.

Repeat for each integration whose syslog events you expect to receive.

#### 2. Add the Syslog Router integration

1. In Kibana, navigate to **Management > Integrations**.
2. Search for **Syslog Router** and select it.
3. Click **Add Syslog Router**.
4. Enable the desired input(s) — TCP, UDP, or Filestream — and configure listen address/port.
5. Review the **Reroute configuration** YAML to confirm the pattern list matches your environment.
6. Select the **Elastic Agent policy** to assign this integration to.
7. Click **Save and continue**.

#### Input configuration reference

The `preserve_original_event` setting is not handled by this integration, but rather
by the integration to which the events are routed (to avoid duplicate handling).
If the user implements a custom integration, they should also implement this processing.

##### TCP input

| Setting                     | Variable                  | Default                        | Description                                                                                                                                      |
| --------------------------- | ------------------------- | ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Listen Address**          | `listen_address`          | `localhost`                    | Bind address for TCP connections. Set to `0.0.0.0` for all interfaces.                                                                           |
| **Listen Port**             | `listen_port`             | `9514`                         | TCP port number to listen on.                                                                                                                    |
| **Preserve original event** | `preserve_original_event` | `false`                        | Store raw event in `event.original`.                                                                                                             |
| **Reroute configuration**   | `reroute_config`          | _(22 pre-configured patterns)_ | YAML list of `if/then` blocks for pattern matching.                                                                                              |
| **SSL Configuration**       | `ssl`                     | _(turned off)_                 | SSL/TLS settings. Refer to [SSL documentation](https://www.elastic.co/guide/en/beats/filebeat/current/configuration-ssl.html#ssl-common-config). |
| **Custom TCP Options**      | `tcp_options`             | _(commented out)_              | Additional TCP input options. See [TCP input docs](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-tcp.html).              |
| **Tags**                    | `tags`                    | `['forwarded']`                | Custom tags for filtering.                                                                                                                       |

##### UDP input

| Setting                     | Variable                  | Default                        | Description                                                                                                                         |
| --------------------------- | ------------------------- | ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------- |
| **Listen Address**          | `listen_host`             | `localhost`                    | Bind address for UDP connections. Set to `0.0.0.0` for all interfaces.                                                              |
| **Listen Port**             | `listen_port`             | `9514`                         | UDP port number to listen on.                                                                                                       |
| **Preserve original event** | `preserve_original_event` | `false`                        | Store raw event in `event.original`.                                                                                                |
| **Reroute configuration**   | `reroute_config`          | _(22 pre-configured patterns)_ | YAML list of `if/then` blocks for pattern matching.                                                                                 |
| **Custom UDP Options**      | `udp_options`             | _(commented out)_              | Additional UDP input options. See [UDP input docs](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-udp.html). |
| **Tags**                    | `tags`                    | `['forwarded']`                | Custom tags for filtering.                                                                                                          |

##### Filestream input (turned off by default)

| Setting                       | Variable                  | Default                        | Description                                                                                                                                        |
| ----------------------------- | ------------------------- | ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Paths**                     | `paths`                   | `['/var/log/syslog.log']`      | File paths to monitor.                                                                                                                             |
| **Preserve original event**   | `preserve_original_event` | `false`                        | Store raw event in `event.original`.                                                                                                               |
| **Reroute configuration**     | `reroute_config`          | _(22 pre-configured patterns)_ | YAML list of `if/then` blocks for pattern matching.                                                                                                |
| **Custom Filestream Options** | `filestream_options`      | —                              | Additional filestream options. See [filestream input docs](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-filestream.html). |
| **Tags**                      | `tags`                    | `['forwarded']`                | Custom tags for filtering.                                                                                                                         |

### Configuring routing patterns

#### Overview

The integration uses [Beats conditionals and processors](https://www.elastic.co/guide/en/beats/filebeat/current/defining-processors.html) to match incoming syslog messages to target data streams. Pattern definitions are evaluated in the order they appear. Each pattern is an `if/then` block:

```yaml
- if:
    and:
      - not.has_fields: _conf.dataset
      - regexp.message: "%ASA-"
  then:
    - add_fields:
        target: ""
        fields:
          _conf.dataset: "cisco_asa.log"
          _conf.tz_offset: "UTC"
          _temp_.internal_zones: ["trust"]
          _temp_.external_zones: ["untrust"]
```

The `not.has_fields: _conf.dataset` condition ensures only the first matching pattern sets the routing target.

#### Reordering patterns

Move the entire `if/then` block up or down in the YAML list. Place stricter patterns before more relaxed ones, and high-traffic integrations near the top.

#### Disabling a pattern

Remove the block entirely, or comment it out with `#`:

```yaml
# - if:
#     and:
#       - not.has_fields: _conf.dataset
#       - regexp.message: "%ASA-"
#   then:
#     - add_fields:
#         target: ''
#         fields:
#           _conf.dataset: "cisco_asa.log"
#           _conf.tz_offset: "UTC"
#           _temp_.internal_zones: ['trust']
#           _temp_.external_zones: ['untrust']
```

#### Adding a new pattern

At minimum, an `add_fields` processor must set `_conf.dataset` to the target integration's dataset name (`integration.data_stream`):

```yaml
- if:
    and:
      - not.has_fields: _conf.dataset
      - regexp.message: "MY_PATTERN"
  then:
    - add_fields:
        target: ""
        fields:
          _conf.dataset: "my_integration.my_data_stream"
```

Multiple regex patterns can be combined with `or`:

```yaml
- if:
    and:
      - not.has_fields: _conf.dataset
      - or:
          - regexp.message: <PATTERN_1>
          - regexp.message: <PATTERN_2>
```

Additional processors such as `decode_cef` or `syslog` may be added in the `then` block if the target integration requires light pre-processing. However, for any complex processing of custom logs, we recommend creating a separate integration and routing to it.

## Validation Steps

### 1. Verify the agent is receiving data

1. Check the Elastic Agent logs for the configured input (TCP/UDP) to confirm it is listening.
2. Send a test syslog message to the agent host on the configured port (for example, `echo "<190>%ASA-6-302013: test message" | nc localhost 9514`).

### 2. Check data in Kibana

1. Navigate to **Analytics > Discover**.
2. Select the `logs-*` data view.
3. Search for the test event using KQL: `data_stream.dataset : "cisco_asa.log"`.
4. Verify the event was routed to the correct data stream and parsed by the target integration's pipeline.

### 3. Check unmatched events

1. Filter for `data_stream.dataset : "syslog_router.log"` to find events that did not match any pattern.
2. Examine the `message` field of unmatched events and consider adding new patterns if needed.

## Troubleshooting

### Common Configuration Issues

**Issue**: Events are not being routed to the correct integration

- **Solution**: Verify that the regex pattern matches the syslog message format from your device. Test the regex against a sample message. Ensure the pattern block is not below a more relaxed pattern that matches first.

**Issue**: Events appear in `syslog_router.log` instead of the target data stream

- **Solution**: The event did not match any pattern. Check the `message` field against the configured regex patterns. You may need to add a custom pattern for your device's syslog format.

**Issue**: Routed events are not parsed correctly

- **Solution**: Ensure the target integration's assets are installed in Kibana. The Syslog Router only routes events; it does not parse them. The target integration's ingest pipeline handles parsing.

### Ingestion Errors

**Issue**: `error.message` is set on routed events

- **Solution**: The target integration's ingest pipeline encountered a parsing error. Check that the syslog format matches what the target integration expects. Some integrations require specific syslog formats (e.g. Citrix WAF requires CEF format).

**Issue**: High volume of unmatched events

- **Solution**: Review the unmatched events to identify their source. Add custom routing patterns for device types not covered by the default patterns.

## Documentation sites

- [Beats Processors and Conditionals](https://www.elastic.co/guide/en/beats/filebeat/current/defining-processors.html)
- [TCP input configuration](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-tcp.html)
- [UDP input configuration](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-udp.html)
- [Filestream input configuration](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-filestream.html)
- [SSL configuration](https://www.elastic.co/guide/en/beats/filebeat/current/configuration-ssl.html#ssl-common-config)
