# Common Event Format (CEF) Integration

This is an integration for parsing Common Event Format (CEF) data. It can accept
data over syslog or read it from a file.

CEF data is a format like

`CEF:0|Elastic|Vaporware|1.0.0-alpha|18|Web request|low|eventId=3457 msg=hello`

When syslog is used as the transport the CEF data becomes the message that is
contained in the syslog envelope. This integration will parse the syslog
timestamp if it is present. Depending on the syslog RFC used the message will
have a format like one of these:

`<189> Jun 18 10:55:50 host CEF:0|Elastic|Vaporware|1.0.0-alpha|18|Web request|low|eventId=3457 msg=hello`

`<189>1 2021-06-18T10:55:50.000003Z host app - - - CEF:0|Elastic|Vaporware|1.0.0-alpha|18|Web request|low|eventId=3457 msg=hello`

In both cases the integration will use the syslog timestamp as the `@timestamp`
unless the CEF data contains a device receipt timestamp.

The Elastic Agent's `decode_cef` processor is applied to parse the CEF encoded
data. The decoded data is written into a `cef` object field. Lastly any Elastic
Common Schema (ECS) fields that can be populated with the CEF data are
populated.

## Compatibility

### Forcepoint NGFW Security Management Center

This module will process CEF data from Forcepoint NGFW Security Management
Center (SMC).  In the SMC configure the logs to be forwarded to the address set
in `var.syslog_host` in format CEF and service UDP on `var.syslog_port`.
Instructions can be found in [KB
15002](https://support.forcepoint.com/KBArticle?id=000015002) for configuring
the SMC.

Testing was done with CEF logs from SMC version 6.6.1 and custom string mappings
were taken from 'CEF Connector Configuration Guide' dated December 5, 2011.

### Check Point devices

This module will parse CEF data from Check Point devices as documented in [Log
Exporter CEF Field
Mappings](https://community.checkpoint.com/t5/Logging-and-Reporting/Log-Exporter-CEF-Field-Mappings/td-p/41060).

Check Point CEF extensions are mapped as follows:


| CEF Extension              | CEF Label value             | ECS Fields               | Non-ECS Field                  |
|----------------------------|-----------------------------|--------------------------|--------------------------------|
| cp_app_risk                | -                           | event.risk_score         | checkpoint.app_risk            |
| cp_severity                | -                           | event.severity           | checkpoint.severity            |
| baseEventCount             | -                           | -                        | checkpoint.event_count         |
| deviceExternalId           | -                           | observer.type            | -                              |
| deviceFacility             | -                           | observer.type            | -                              |
| deviceInboundInterface     | -                           | observer.ingress.interface.name | -                       |
| deviceOutboundInterface    | -                           | observer.egress.interface.name | -                        |
| externalId                 | -                           | -                        | checkpoint.uuid                |
| fileHash                   | -                           | file.hash.\{md5,sha1\}   | -                              |
| reason                     | -                           | -                        | checkpoint.termination_reason  |
| requestCookies             | -                           | -                        | checkpoint.cookie              |
| sourceNtDomain             | -                           | dns.question.name        | -                              |
| Signature                  | -                           | vulnerability.id         | -                              |
| Recipient                  | -                           | email.to.address         | -                              |
| Sender                     | -                           | email.from.address       | -                              |
| deviceCustomFloatingPoint1 | update version              | observer.version         | -                              |
| deviceCustomIPv6Address2   | source ipv6 address         | source.ip                | -                              |
| deviceCustomIPv6Address3   | destination ipv6 address    | destination.ip           | -                              |
| deviceCustomNumber1        | elapsed time in seconds     | event.duration           | -                              |
| deviceCustomNumber1        | email recipients number     | -                        | checkpoint.email_recipients_num |
| deviceCustomNumber1        | payload                     | network.bytes            | -                              |
| deviceCustomNumber2        | icmp type                   | -                        | checkpoint.icmp_type           |
| deviceCustomNumber2        | duration in seconds         | event.duration           | -                              |
| deviceCustomNumber3        | icmp code                   | -                        | checkpoint.icmp_code           |
| deviceCustomString1        | connectivity state          | -                        | checkpoint.connectivity_state  |
| deviceCustomString1        | application rule name       | rule.name                | -                              |
| deviceCustomString1        | threat prevention rule name | rule.name                | -                              |
| deviceCustomString1        | voip log type               | -                        | checkpoint.voip_log_type       |
| deviceCustomString1        | dlp rule name               | rule.name                | -                              |
| deviceCustomString1        | email id                    | -                        | checkpoint.email_id            |
| deviceCustomString2        | category                    | -                        | checkpoint.category            |
| deviceCustomString2        | email subject               | email.subject            | checkpoint.email_subject       |
| deviceCustomString2        | sensor mode                 | -                        | checkpoint.sensor_mode         |
| deviceCustomString2        | protection id               | -                        | checkpoint.protection_id       |
| deviceCustomString2        | scan invoke type            | -                        | checkpoint.integrity_av_invoke_type |
| deviceCustomString2        | update status               | -                        | checkpoint.update_status       |
| deviceCustomString2        | peer gateway                | -                        | checkpoint.peer_gateway        |
| deviceCustomString2        | categories                  | rule.category            | -                              |
| deviceCustomString6        | application name            | network.application      | -                              |
| deviceCustomString6        | virus name                  | -                        | checkpoint.virus_name          |
| deviceCustomString6        | malware name                | -                        | checkpoint.spyware_name        |
| deviceCustomString6        | malware family              | -                        | checkpoint.malware_family      |
| deviceCustomString3        | user group                  | group.name               | -                              |
| deviceCustomString3        | incident extension          | -                        | checkpoint.incident_extension  |
| deviceCustomString3        | protection type             | -                        | checkpoint.protection_type     |
| deviceCustomString3        | email spool id              | -                        | checkpoint.email_spool_id      |
| deviceCustomString3        | identity type               | -                        | checkpoint.identity_type       |
| deviceCustomString4        | malware status              | -                        | checkpoint.spyware_status      |
| deviceCustomString4        | threat prevention rule id   | rule.id                  | -                              |
| deviceCustomString4        | scan result                 | -                        | checkpoint.scan_result         |
| deviceCustomString4        | tcp flags                   | -                        | checkpoint.tcp_flags           |
| deviceCustomString4        | destination os              | os.name                  | -                              |
| deviceCustomString4        | protection name             | -                        | checkpoint.protection_name     |
| deviceCustomString4        | email control               | -                        | checkpoint.email_control       |
| deviceCustomString4        | frequency                   | -                        | checkpoint.frequency           |
| deviceCustomString4        | user response               | -                        | checkpoint.user_status         |
| deviceCustomString5        | matched category            | rule.category            | -                              |
| deviceCustomString5        | vlan id                     | network.vlan.id          | -                              |
| deviceCustomString5        | authentication method       | -                        | checkpoint.auth_method         |
| deviceCustomString5        | email session id            | email.message_id         | checkpoint.email_session_id    |
| deviceCustomDate2          | subscription expiration     | -                        | checkpoint.subs_exp            |
| deviceFlexNumber1          | confidence                  | -                        | checkpoint.confidence_level    |
| deviceFlexNumber2          | performance impact          | -                        | checkpoint.performance_impact  |
| deviceFlexNumber2          | destination phone number    | -                        | checkpoint.dst_phone_number    |
| flexString1                | application signature id    | -                        | checkpoint.app_sig_id          |
| flexString2                | malware action              | rule.description         | -                              |
| flexString2                | attack information          | event.action             | -                              |
| rule_uid                   | -                           | rule.uuid                | -                              |
| ifname                     | -                           | observer.ingress.interface.name | -                       |
| inzone                     | -                           | observer.ingress.zone    | -                              |
| outzone                    | -                           | observer.egress.zone     | -                              |
| product                    | -                           | observer.product         | -                              |

## Logs

### CEF log

This is the CEF `log` dataset.

{{event "log"}}

{{fields "log"}}
