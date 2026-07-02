# Destination identity review list

- **git HEAD:** `d43ff234d21161ef4cbbc25d56415e4aa72680d9`
- **generated (UTC):** 2026-05-20T08:56:42Z
- **integration packages scanned:** 445
- **packages with `destination.user` in pipeline:** 29
- **packages with `destination.host` / `destination.hostname` in pipeline:** 3
- **packages with either:** 31
- **evidence rows:** 202

Use [`destination_identity_hits.csv`](destination_identity_hits.csv) for line-level evidence.

## Package checklist (sorted A–Z)

Review each integration: confirm whether `destination.user` / `destination.host`
represents the **target** of the action (candidate for `user.target.*` / `host.target.*`)
or only network/session context.

| # | package | destination.user | destination.host | data_streams |
| ---: | --- | :---: | :---: | --- |
| 1 | abnormal_security | yes |  | ai_security_mailbox |
| 2 | beyondtrust_pra | yes | yes | access_session |
| 3 | cef | yes |  | log |
| 4 | checkpoint | yes |  | firewall |
| 5 | checkpoint_email | yes |  | event |
| 6 | cisco_asa | yes |  | log |
| 7 | cisco_ftd | yes |  | log |
| 8 | citrix_adc | yes |  | log |
| 9 | claroty_ctd |  | yes | event |
| 10 | crowdstrike | yes |  | alert |
| 11 | cyberark_pta | yes |  | events |
| 12 | cyberarkpas | yes |  | audit |
| 13 | fortinet_fortigate | yes |  | log |
| 14 | google_secops | yes |  | alert |
| 15 | jumpcloud | yes |  | events |
| 16 | microsoft_exchange_online_message_trace | yes |  | log |
| 17 | nozomi_networks | yes |  | alert |
| 18 | o365 | yes |  | audit |
| 19 | panw | yes |  | panos |
| 20 | ping_federate | yes |  | audit |
| 21 | prisma_access | yes |  | event |
| 22 | sentinel_one_cloud_funnel | yes |  | event |
| 23 | sophos | yes |  | xg |
| 24 | swimlane | yes |  | tenant_api, turbine_api |
| 25 | trellix_epo_cloud | yes |  | event |
| 26 | trend_micro_vision_one | yes |  | detection |
| 27 | trendmicro | yes |  | deep_security |
| 28 | tychon |  | yes | arp |
| 29 | watchguard_firebox | yes |  | log |
| 30 | windows | yes |  | forwarded, powershell_operational |
| 31 | zoom | yes |  | webhook |

## Per-package detail

### abnormal_security

- **destination.user** — `destination.user` — `packages/abnormal_security/data_stream/ai_security_mailbox/elasticsearch/ingest_pipeline/default.yml:219` — data_stream: `ai_security_mailbox`
- **destination.user** — `destination.user` — `packages/abnormal_security/data_stream/ai_security_mailbox/elasticsearch/ingest_pipeline/default.yml:220` — data_stream: `ai_security_mailbox`

### beyondtrust_pra

- **destination.host** — `json.destination.hostname` — `packages/beyondtrust_pra/data_stream/access_session/elasticsearch/ingest_pipeline/default.yml:81` — data_stream: `access_session`
- **destination.host** — `beyondtrust_pra.access_session.destination.hostname` — `packages/beyondtrust_pra/data_stream/access_session/elasticsearch/ingest_pipeline/default.yml:83` — data_stream: `access_session`
- **destination.host** — `beyondtrust_pra.access_session.destination.hostname` — `packages/beyondtrust_pra/data_stream/access_session/elasticsearch/ingest_pipeline/default.yml:88` — data_stream: `access_session`
- **destination.user** — `destination.user.id` — `packages/beyondtrust_pra/data_stream/access_session/elasticsearch/ingest_pipeline/default.yml:96` — data_stream: `access_session`
- **destination.user** — `destination.user.name` — `packages/beyondtrust_pra/data_stream/access_session/elasticsearch/ingest_pipeline/default.yml:253` — data_stream: `access_session`
- **destination.user** — `destination.user` — `packages/beyondtrust_pra/data_stream/access_session/elasticsearch/ingest_pipeline/default.yml:993` — data_stream: `access_session`
- **destination.user** — `destination.user` — `packages/beyondtrust_pra/data_stream/access_session/elasticsearch/ingest_pipeline/default.yml:998` — data_stream: `access_session`
- **destination.host** — `destination.host` — `packages/beyondtrust_pra/data_stream/access_session/elasticsearch/ingest_pipeline/default.yml:1019` — data_stream: `access_session`

### cef

- **destination.user** — `destination.user` — `packages/cef/data_stream/log/elasticsearch/ingest_pipeline/cp-pipeline.yml:123` — data_stream: `log`
- **destination.user** — `destination.user` — `packages/cef/data_stream/log/elasticsearch/ingest_pipeline/cp-pipeline.yml:292` — data_stream: `log`
- **destination.user** — `destination.user` — `packages/cef/data_stream/log/elasticsearch/ingest_pipeline/default.yml:103` — data_stream: `log`

### checkpoint

- **destination.user** — `destination.user.name` — `packages/checkpoint/data_stream/firewall/elasticsearch/ingest_pipeline/default.yml:378` — data_stream: `firewall`
- **destination.user** — `destination.user.domain` — `packages/checkpoint/data_stream/firewall/elasticsearch/ingest_pipeline/default.yml:383` — data_stream: `firewall`
- **destination.user** — `destination.user.email` — `packages/checkpoint/data_stream/firewall/elasticsearch/ingest_pipeline/default.yml:579` — data_stream: `firewall`
- **destination.user** — `destination.user` — `packages/checkpoint/data_stream/firewall/elasticsearch/ingest_pipeline/default.yml:584` — data_stream: `firewall`
- **destination.user** — `destination.user` — `packages/checkpoint/data_stream/firewall/elasticsearch/ingest_pipeline/default.yml:589` — data_stream: `firewall`
- **destination.user** — `destination.user.id` — `packages/checkpoint/data_stream/firewall/elasticsearch/ingest_pipeline/default.yml:634` — data_stream: `firewall`
- **destination.user** — `destination.user.name` — `packages/checkpoint/data_stream/firewall/elasticsearch/ingest_pipeline/default.yml:824` — data_stream: `firewall`
- **destination.user** — `destination.user.email` — `packages/checkpoint/data_stream/firewall/elasticsearch/ingest_pipeline/default.yml:1515` — data_stream: `firewall`
- **destination.user** — `destination.user.name` — `packages/checkpoint/data_stream/firewall/elasticsearch/ingest_pipeline/default.yml:1516` — data_stream: `firewall`
- **destination.user** — `destination.user` — `packages/checkpoint/data_stream/firewall/elasticsearch/ingest_pipeline/default.yml:1518` — data_stream: `firewall`
- **destination.user** — `destination.user.email` — `packages/checkpoint/data_stream/firewall/elasticsearch/ingest_pipeline/default.yml:1520` — data_stream: `firewall`
- **destination.user** — `destination.user` — `packages/checkpoint/data_stream/firewall/elasticsearch/ingest_pipeline/default.yml:1521` — data_stream: `firewall`
- **destination.user** — `destination.user` — `packages/checkpoint/data_stream/firewall/elasticsearch/ingest_pipeline/default.yml:1529` — data_stream: `firewall`
- **destination.user** — `destination.user` — `packages/checkpoint/data_stream/firewall/elasticsearch/ingest_pipeline/default.yml:1535` — data_stream: `firewall`
- **destination.user** — `destination.user` — `packages/checkpoint/data_stream/firewall/elasticsearch/ingest_pipeline/default.yml:1541` — data_stream: `firewall`

### checkpoint_email

- **destination.user** — `destination.user.email` — `packages/checkpoint_email/data_stream/event/elasticsearch/ingest_pipeline/default.yml:261` — data_stream: `event`
- **destination.user** — `destination.user.email` — `packages/checkpoint_email/data_stream/event/elasticsearch/ingest_pipeline/default.yml:267` — data_stream: `event`
- **destination.user** — `destination.user` — `packages/checkpoint_email/data_stream/event/elasticsearch/ingest_pipeline/default.yml:269` — data_stream: `event`

### cisco_asa

- **destination.user** — `destination.user.name` — `packages/cisco_asa/data_stream/log/elasticsearch/ingest_pipeline/default.yml:2004` — data_stream: `log`
- **destination.user** — `destination.user` — `packages/cisco_asa/data_stream/log/elasticsearch/ingest_pipeline/default.yml:2022` — data_stream: `log`
- **destination.user** — `destination.user` — `packages/cisco_asa/data_stream/log/elasticsearch/ingest_pipeline/default.yml:2026` — data_stream: `log`
- **destination.user** — `destination.user` — `packages/cisco_asa/data_stream/log/elasticsearch/ingest_pipeline/default.yml:2030` — data_stream: `log`
- **destination.user** — `destination.user` — `packages/cisco_asa/data_stream/log/elasticsearch/ingest_pipeline/default.yml:2031` — data_stream: `log`
- **destination.user** — `destination.user` — `packages/cisco_asa/data_stream/log/elasticsearch/ingest_pipeline/default.yml:2032` — data_stream: `log`
- **destination.user** — `destination.user` — `packages/cisco_asa/data_stream/log/elasticsearch/ingest_pipeline/default.yml:3140` — data_stream: `log`
- **destination.user** — `destination.user` — `packages/cisco_asa/data_stream/log/elasticsearch/ingest_pipeline/default.yml:3142` — data_stream: `log`
- **destination.user** — `destination.user` — `packages/cisco_asa/data_stream/log/elasticsearch/ingest_pipeline/default.yml:3226` — data_stream: `log`
- **destination.user** — `destination.user` — `packages/cisco_asa/data_stream/log/elasticsearch/ingest_pipeline/default.yml:3227` — data_stream: `log`
- **destination.user** — `destination.user` — `packages/cisco_asa/data_stream/log/elasticsearch/ingest_pipeline/default.yml:3268` — data_stream: `log`

### cisco_ftd

- **destination.user** — `destination.user.name` — `packages/cisco_ftd/data_stream/log/elasticsearch/ingest_pipeline/default.yml:2176` — data_stream: `log`
- **destination.user** — `destination.user` — `packages/cisco_ftd/data_stream/log/elasticsearch/ingest_pipeline/default.yml:2202` — data_stream: `log`
- **destination.user** — `destination.user` — `packages/cisco_ftd/data_stream/log/elasticsearch/ingest_pipeline/default.yml:2206` — data_stream: `log`
- **destination.user** — `destination.user` — `packages/cisco_ftd/data_stream/log/elasticsearch/ingest_pipeline/default.yml:2210` — data_stream: `log`
- **destination.user** — `destination.user` — `packages/cisco_ftd/data_stream/log/elasticsearch/ingest_pipeline/default.yml:2211` — data_stream: `log`
- **destination.user** — `destination.user` — `packages/cisco_ftd/data_stream/log/elasticsearch/ingest_pipeline/default.yml:2212` — data_stream: `log`
- **destination.user** — `destination.user` — `packages/cisco_ftd/data_stream/log/elasticsearch/ingest_pipeline/default.yml:2995` — data_stream: `log`
- **destination.user** — `destination.user` — `packages/cisco_ftd/data_stream/log/elasticsearch/ingest_pipeline/default.yml:2997` — data_stream: `log`
- **destination.user** — `destination.user` — `packages/cisco_ftd/data_stream/log/elasticsearch/ingest_pipeline/default.yml:3116` — data_stream: `log`
- **destination.user** — `destination.user` — `packages/cisco_ftd/data_stream/log/elasticsearch/ingest_pipeline/default.yml:3117` — data_stream: `log`
- **destination.user** — `destination.user` — `packages/cisco_ftd/data_stream/log/elasticsearch/ingest_pipeline/default.yml:3158` — data_stream: `log`
- **destination.user** — `destination.user` — `packages/cisco_ftd/data_stream/log/elasticsearch/ingest_pipeline/default.yml:3159` — data_stream: `log`

### citrix_adc

- **destination.user** — `destination.user.domain` — `packages/citrix_adc/data_stream/log/elasticsearch/ingest_pipeline/alg_feature.yml:79` — data_stream: `log`
- **destination.user** — `destination.user.name` — `packages/citrix_adc/data_stream/log/elasticsearch/ingest_pipeline/alg_feature.yml:84` — data_stream: `log`
- **destination.user** — `destination.user.name` — `packages/citrix_adc/data_stream/log/elasticsearch/ingest_pipeline/default.yml:413` — data_stream: `log`
- **destination.user** — `destination.user.email` — `packages/citrix_adc/data_stream/log/elasticsearch/ingest_pipeline/default.yml:414` — data_stream: `log`
- **destination.user** — `destination.user` — `packages/citrix_adc/data_stream/log/elasticsearch/ingest_pipeline/default.yml:416` — data_stream: `log`
- **destination.user** — `destination.user.email` — `packages/citrix_adc/data_stream/log/elasticsearch/ingest_pipeline/default.yml:418` — data_stream: `log`
- **destination.user** — `destination.user` — `packages/citrix_adc/data_stream/log/elasticsearch/ingest_pipeline/default.yml:419` — data_stream: `log`
- **destination.user** — `destination.user` — `packages/citrix_adc/data_stream/log/elasticsearch/ingest_pipeline/default.yml:427` — data_stream: `log`
- **destination.user** — `destination.user` — `packages/citrix_adc/data_stream/log/elasticsearch/ingest_pipeline/default.yml:433` — data_stream: `log`

### claroty_ctd

- **destination.host** — `claroty_ctd.event.destination.host` — `packages/claroty_ctd/data_stream/event/elasticsearch/ingest_pipeline/default.yml:431` — data_stream: `event`
- **destination.host** — `claroty_ctd.event.destination.host` — `packages/claroty_ctd/data_stream/event/elasticsearch/ingest_pipeline/default.yml:436` — data_stream: `event`
- **destination.host** — `destination.host` — `packages/claroty_ctd/data_stream/event/elasticsearch/ingest_pipeline/default.yml:441` — data_stream: `event`
- **destination.host** — `destination.host` — `packages/claroty_ctd/data_stream/event/elasticsearch/ingest_pipeline/default.yml:2144` — data_stream: `event`

### crowdstrike

- **destination.user** — `destination.user.domain` — `packages/crowdstrike/data_stream/alert/elasticsearch/ingest_pipeline/default.yml:1931` — data_stream: `alert`
- **destination.user** — `destination.user` — `packages/crowdstrike/data_stream/alert/elasticsearch/ingest_pipeline/default.yml:1938` — data_stream: `alert`
- **destination.user** — `destination.user.name` — `packages/crowdstrike/data_stream/alert/elasticsearch/ingest_pipeline/default.yml:1947` — data_stream: `alert`
- **destination.user** — `destination.user` — `packages/crowdstrike/data_stream/alert/elasticsearch/ingest_pipeline/default.yml:1954` — data_stream: `alert`

### cyberark_pta

- **destination.user** — `destination.user.name` — `packages/cyberark_pta/data_stream/events/elasticsearch/ingest_pipeline/default.yml:87` — data_stream: `events`
- **destination.user** — `destination.user.email` — `packages/cyberark_pta/data_stream/events/elasticsearch/ingest_pipeline/default.yml:88` — data_stream: `events`
- **destination.user** — `destination.user` — `packages/cyberark_pta/data_stream/events/elasticsearch/ingest_pipeline/default.yml:90` — data_stream: `events`
- **destination.user** — `destination.user.email` — `packages/cyberark_pta/data_stream/events/elasticsearch/ingest_pipeline/default.yml:92` — data_stream: `events`
- **destination.user** — `destination.user` — `packages/cyberark_pta/data_stream/events/elasticsearch/ingest_pipeline/default.yml:93` — data_stream: `events`
- **destination.user** — `destination.user` — `packages/cyberark_pta/data_stream/events/elasticsearch/ingest_pipeline/default.yml:100` — data_stream: `events`
- **destination.user** — `destination.user` — `packages/cyberark_pta/data_stream/events/elasticsearch/ingest_pipeline/default.yml:106` — data_stream: `events`

### cyberarkpas

- **destination.user** — `destination.user.name` — `packages/cyberarkpas/data_stream/audit/elasticsearch/ingest_pipeline/audit.yml:504` — data_stream: `audit`
- **destination.user** — `destination.user.name` — `packages/cyberarkpas/data_stream/audit/elasticsearch/ingest_pipeline/audit.yml:522` — data_stream: `audit`
- **destination.user** — `destination.user.name` — `packages/cyberarkpas/data_stream/audit/elasticsearch/ingest_pipeline/audit.yml:612` — data_stream: `audit`
- **destination.user** — `destination.user.name` — `packages/cyberarkpas/data_stream/audit/elasticsearch/ingest_pipeline/audit.yml:752` — data_stream: `audit`
- **destination.user** — `destination.user.name` — `packages/cyberarkpas/data_stream/audit/elasticsearch/ingest_pipeline/audit.yml:771` — data_stream: `audit`
- **destination.user** — `destination.user.name` — `packages/cyberarkpas/data_stream/audit/elasticsearch/ingest_pipeline/audit.yml:792` — data_stream: `audit`
- **destination.user** — `destination.user.name` — `packages/cyberarkpas/data_stream/audit/elasticsearch/ingest_pipeline/audit.yml:815` — data_stream: `audit`
- **destination.user** — `destination.user.name` — `packages/cyberarkpas/data_stream/audit/elasticsearch/ingest_pipeline/audit.yml:848` — data_stream: `audit`
- **destination.user** — `destination.user.name` — `packages/cyberarkpas/data_stream/audit/elasticsearch/ingest_pipeline/audit.yml:867` — data_stream: `audit`
- **destination.user** — `destination.user.name` — `packages/cyberarkpas/data_stream/audit/elasticsearch/ingest_pipeline/audit.yml:886` — data_stream: `audit`
- **destination.user** — `destination.user.name` — `packages/cyberarkpas/data_stream/audit/elasticsearch/ingest_pipeline/audit.yml:907` — data_stream: `audit`
- **destination.user** — `destination.user.name` — `packages/cyberarkpas/data_stream/audit/elasticsearch/ingest_pipeline/audit.yml:935` — data_stream: `audit`
- **destination.user** — `destination.user.name` — `packages/cyberarkpas/data_stream/audit/elasticsearch/ingest_pipeline/audit.yml:950` — data_stream: `audit`
- **destination.user** — `destination.user` — `packages/cyberarkpas/data_stream/audit/elasticsearch/ingest_pipeline/audit.yml:1108` — data_stream: `audit`

### fortinet_fortigate

- **destination.user** — `destination.user` — `packages/fortinet_fortigate/data_stream/log/elasticsearch/ingest_pipeline/default.yml:754` — data_stream: `log`
- **destination.user** — `destination.user.name` — `packages/fortinet_fortigate/data_stream/log/elasticsearch/ingest_pipeline/traffic.yml:117` — data_stream: `log`

### google_secops

- **destination.user** — `destination.user.email` — `packages/google_secops/data_stream/alert/elasticsearch/ingest_pipeline/default.yml:1403` — data_stream: `alert`
- **destination.user** — `destination.user.group.id` — `packages/google_secops/data_stream/alert/elasticsearch/ingest_pipeline/default.yml:1458` — data_stream: `alert`
- **destination.user** — `destination.user.name` — `packages/google_secops/data_stream/alert/elasticsearch/ingest_pipeline/default.yml:1464` — data_stream: `alert`
- **destination.user** — `destination.user.id` — `packages/google_secops/data_stream/alert/elasticsearch/ingest_pipeline/default.yml:1469` — data_stream: `alert`

### jumpcloud

- **destination.user** — `destination.user` — `packages/jumpcloud/data_stream/events/elasticsearch/ingest_pipeline/default.yml:258` — data_stream: `events`

### microsoft_exchange_online_message_trace

- **destination.user** — `destination.user.id` — `packages/microsoft_exchange_online_message_trace/data_stream/log/elasticsearch/ingest_pipeline/default.yml:131` — data_stream: `log`
- **destination.user** — `destination.user.email` — `packages/microsoft_exchange_online_message_trace/data_stream/log/elasticsearch/ingest_pipeline/default.yml:135` — data_stream: `log`
- **destination.user** — `destination.user.name` — `packages/microsoft_exchange_online_message_trace/data_stream/log/elasticsearch/ingest_pipeline/default.yml:310` — data_stream: `log`
- **destination.user** — `destination.user.domain` — `packages/microsoft_exchange_online_message_trace/data_stream/log/elasticsearch/ingest_pipeline/default.yml:314` — data_stream: `log`

### nozomi_networks

- **destination.user** — `destination.user.roles` — `packages/nozomi_networks/data_stream/alert/elasticsearch/ingest_pipeline/default.yml:188` — data_stream: `alert`

### o365

- **destination.user** — `destination.user` — `packages/o365/data_stream/audit/elasticsearch/ingest_pipeline/default.yml:1019` — data_stream: `audit`
- **destination.user** — `destination.user` — `packages/o365/data_stream/audit/elasticsearch/ingest_pipeline/default.yml:1020` — data_stream: `audit`
- **destination.user** — `destination.user` — `packages/o365/data_stream/audit/elasticsearch/ingest_pipeline/default.yml:1022` — data_stream: `audit`
- **destination.user** — `destination.user` — `packages/o365/data_stream/audit/elasticsearch/ingest_pipeline/default.yml:1028` — data_stream: `audit`
- **destination.user** — `destination.user` — `packages/o365/data_stream/audit/elasticsearch/ingest_pipeline/default.yml:1032` — data_stream: `audit`
- **destination.user** — `destination.user.email` — `packages/o365/data_stream/audit/elasticsearch/ingest_pipeline/default.yml:1156` — data_stream: `audit`
- **destination.user** — `destination.user.id` — `packages/o365/data_stream/audit/elasticsearch/ingest_pipeline/default.yml:1172` — data_stream: `audit`
- **destination.user** — `destination.user` — `packages/o365/data_stream/audit/elasticsearch/ingest_pipeline/default.yml:1437` — data_stream: `audit`
- **destination.user** — `destination.user` — `packages/o365/data_stream/audit/elasticsearch/ingest_pipeline/default.yml:1441` — data_stream: `audit`
- **destination.user** — `destination.user` — `packages/o365/data_stream/audit/elasticsearch/ingest_pipeline/default.yml:1442` — data_stream: `audit`
- **destination.user** — `destination.user` — `packages/o365/data_stream/audit/elasticsearch/ingest_pipeline/default.yml:1443` — data_stream: `audit`
- **destination.user** — `destination.user.email` — `packages/o365/data_stream/audit/elasticsearch/ingest_pipeline/default.yml:1684` — data_stream: `audit`

### panw

- **destination.user** — `destination.user` — `packages/panw/data_stream/panos/elasticsearch/ingest_pipeline/default.yml:1406` — data_stream: `panos`
- **destination.user** — `destination.user` — `packages/panw/data_stream/panos/elasticsearch/ingest_pipeline/default.yml:1407` — data_stream: `panos`
- **destination.user** — `destination.user` — `packages/panw/data_stream/panos/elasticsearch/ingest_pipeline/default.yml:1408` — data_stream: `panos`
- **destination.user** — `destination.user` — `packages/panw/data_stream/panos/elasticsearch/ingest_pipeline/default.yml:1409` — data_stream: `panos`
- **destination.user** — `panw.panos.destination.user` — `packages/panw/data_stream/panos/elasticsearch/ingest_pipeline/default.yml:1423` — data_stream: `panos`
- **destination.user** — `destination.user.name` — `packages/panw/data_stream/panos/elasticsearch/ingest_pipeline/default.yml:1424` — data_stream: `panos`
- **destination.user** — `destination.user` — `packages/panw/data_stream/panos/elasticsearch/ingest_pipeline/default.yml:1889` — data_stream: `panos`
- **destination.user** — `destination.user` — `packages/panw/data_stream/panos/elasticsearch/ingest_pipeline/default.yml:1980` — data_stream: `panos`
- **destination.user** — `destination.user.email` — `packages/panw/data_stream/panos/elasticsearch/ingest_pipeline/threat.yml:235` — data_stream: `panos`

### ping_federate

- **destination.user** — `destination.user` — `packages/ping_federate/data_stream/audit/elasticsearch/ingest_pipeline/default.yml:350` — data_stream: `audit`

### prisma_access

- **destination.user** — `destination.user.domain` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:940` — data_stream: `event`
- **destination.user** — `destination.user` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:1007` — data_stream: `event`
- **destination.user** — `prisma_access.event.pan_os_value.destination.user.name` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:1012` — data_stream: `event`
- **destination.user** — `prisma_access.event.pan_os_value.destination.user.name` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:1018` — data_stream: `event`
- **destination.user** — `destination.user.domain` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:1021` — data_stream: `event`
- **destination.user** — `destination.user` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:1023` — data_stream: `event`
- **destination.user** — `destination.user.name` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:1027` — data_stream: `event`
- **destination.user** — `destination.user` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:1029` — data_stream: `event`
- **destination.user** — `destination.user` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:1035` — data_stream: `event`
- **destination.user** — `destination.user` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:1043` — data_stream: `event`
- **destination.user** — `prisma_access.event.pan_os_data.destination.user.name` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:1048` — data_stream: `event`
- **destination.user** — `prisma_access.event.pan_os_data.destination.user.name` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:1054` — data_stream: `event`
- **destination.user** — `destination.user.domain` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:1057` — data_stream: `event`
- **destination.user** — `destination.user` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:1059` — data_stream: `event`
- **destination.user** — `destination.user.name` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:1063` — data_stream: `event`
- **destination.user** — `destination.user` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:1065` — data_stream: `event`
- **destination.user** — `destination.user` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:1071` — data_stream: `event`
- **destination.user** — `prisma_access.event.pan_os.destination.user.domain` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:1077` — data_stream: `event`
- **destination.user** — `destination.user.domain` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:1080` — data_stream: `event`
- **destination.user** — `destination.user` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:1082` — data_stream: `event`
- **destination.user** — `prisma_access.event.destination.user.id` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:1088` — data_stream: `event`
- **destination.user** — `destination.user.id` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:1091` — data_stream: `event`
- **destination.user** — `destination.user` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:1093` — data_stream: `event`
- **destination.user** — `destination.user` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:1099` — data_stream: `event`
- **destination.user** — `destination.user` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:1107` — data_stream: `event`
- **destination.user** — `prisma_access.event.destination.user.name` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:1112` — data_stream: `event`
- **destination.user** — `prisma_access.event.destination.user.name` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:1118` — data_stream: `event`
- **destination.user** — `destination.user.domain` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:1121` — data_stream: `event`
- **destination.user** — `destination.user` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:1123` — data_stream: `event`
- **destination.user** — `destination.user.name` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:1127` — data_stream: `event`
- **destination.user** — `destination.user` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:1129` — data_stream: `event`
- **destination.user** — `destination.user` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:1135` — data_stream: `event`
- **destination.user** — `prisma_access.event.destination.user.uuid` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:1141` — data_stream: `event`
- **destination.user** — `destination.user.id` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:1144` — data_stream: `event`
- **destination.user** — `destination.user` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:1146` — data_stream: `event`
- **destination.user** — `destination.user` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:1152` — data_stream: `event`
- **destination.user** — `destination.user` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:5236` — data_stream: `event`
- **destination.user** — `destination.user` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:5237` — data_stream: `event`
- **destination.user** — `destination.user` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:5238` — data_stream: `event`
- **destination.user** — `destination.user` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:5239` — data_stream: `event`
- **destination.user** — `destination.user` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:5240` — data_stream: `event`
- **destination.user** — `destination.user` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:5241` — data_stream: `event`
- **destination.user** — `destination.user` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:5242` — data_stream: `event`
- **destination.user** — `destination.user` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:5243` — data_stream: `event`
- **destination.user** — `destination.user` — `packages/prisma_access/data_stream/event/elasticsearch/ingest_pipeline/default.yml:5244` — data_stream: `event`

### sentinel_one_cloud_funnel

- **destination.user** — `destination.user.name` — `packages/sentinel_one_cloud_funnel/data_stream/event/elasticsearch/ingest_pipeline/default.yml:107` — data_stream: `event`
- **destination.user** — `destination.user.domain` — `packages/sentinel_one_cloud_funnel/data_stream/event/elasticsearch/ingest_pipeline/default.yml:115` — data_stream: `event`
- **destination.user** — `destination.user.domain` — `packages/sentinel_one_cloud_funnel/data_stream/event/elasticsearch/ingest_pipeline/default.yml:123` — data_stream: `event`
- **destination.user** — `destination.user.name` — `packages/sentinel_one_cloud_funnel/data_stream/event/elasticsearch/ingest_pipeline/default.yml:131` — data_stream: `event`
- **destination.user** — `destination.user` — `packages/sentinel_one_cloud_funnel/data_stream/event/elasticsearch/ingest_pipeline/default.yml:136` — data_stream: `event`
- **destination.user** — `destination.user` — `packages/sentinel_one_cloud_funnel/data_stream/event/elasticsearch/ingest_pipeline/default.yml:141` — data_stream: `event`

### sophos

- **destination.user** — `destination.user.email` — `packages/sophos/data_stream/xg/elasticsearch/ingest_pipeline/antispam.yml:107` — data_stream: `xg`
- **destination.user** — `destination.user` — `packages/sophos/data_stream/xg/elasticsearch/ingest_pipeline/antispam.yml:117` — data_stream: `xg`
- **destination.user** — `destination.user.email` — `packages/sophos/data_stream/xg/elasticsearch/ingest_pipeline/antivirus.yml:122` — data_stream: `xg`
- **destination.user** — `destination.user` — `packages/sophos/data_stream/xg/elasticsearch/ingest_pipeline/antivirus.yml:132` — data_stream: `xg`

### swimlane

- **destination.user** — `destination.user.changes.id` — `packages/swimlane/data_stream/tenant_api/elasticsearch/ingest_pipeline/default.yml:178` — data_stream: `tenant_api`
- **destination.user** — `destination.user.changes.name` — `packages/swimlane/data_stream/tenant_api/elasticsearch/ingest_pipeline/default.yml:182` — data_stream: `tenant_api`
- **destination.user** — `destination.user.changes.id` — `packages/swimlane/data_stream/turbine_api/elasticsearch/ingest_pipeline/default.yml:195` — data_stream: `turbine_api`
- **destination.user** — `destination.user.changes.name` — `packages/swimlane/data_stream/turbine_api/elasticsearch/ingest_pipeline/default.yml:199` — data_stream: `turbine_api`

### trellix_epo_cloud

- **destination.user** — `destination.user.name` — `packages/trellix_epo_cloud/data_stream/event/elasticsearch/ingest_pipeline/default.yml:178` — data_stream: `event`
- **destination.user** — `destination.user` — `packages/trellix_epo_cloud/data_stream/event/elasticsearch/ingest_pipeline/default.yml:184` — data_stream: `event`

### trend_micro_vision_one

- **destination.user** — `trend_micro_vision_one.detection.destination.user` — `packages/trend_micro_vision_one/data_stream/detection/elasticsearch/ingest_pipeline/default.yml:171` — data_stream: `detection`
- **destination.user** — `destination.user.name` — `packages/trend_micro_vision_one/data_stream/detection/elasticsearch/ingest_pipeline/default.yml:1269` — data_stream: `detection`
- **destination.user** — `trend_micro_vision_one.detection.destination.user` — `packages/trend_micro_vision_one/data_stream/detection/elasticsearch/ingest_pipeline/default.yml:1271` — data_stream: `detection`
- **destination.user** — `trend_micro_vision_one.detection.destination.user` — `packages/trend_micro_vision_one/data_stream/detection/elasticsearch/ingest_pipeline/default.yml:1597` — data_stream: `detection`
- **destination.user** — `destination.user` — `packages/trend_micro_vision_one/data_stream/detection/elasticsearch/ingest_pipeline/default.yml:1789` — data_stream: `detection`

### trendmicro

- **destination.user** — `destination.user.name` — `packages/trendmicro/data_stream/deep_security/elasticsearch/ingest_pipeline/default.yml:687` — data_stream: `deep_security`
- **destination.user** — `destination.user` — `packages/trendmicro/data_stream/deep_security/elasticsearch/ingest_pipeline/default.yml:694` — data_stream: `deep_security`

### tychon

- **destination.host** — `destination.host` — `packages/tychon/data_stream/arp/elasticsearch/ingest_pipeline/rest.yml:26` — data_stream: `arp`

### watchguard_firebox

- **destination.user** — `destination.user.name` — `packages/watchguard_firebox/data_stream/log/elasticsearch/ingest_pipeline/pipeline_traffic.yml:446` — data_stream: `log`
- **destination.user** — `destination.user.domain` — `packages/watchguard_firebox/data_stream/log/elasticsearch/ingest_pipeline/pipeline_traffic.yml:451` — data_stream: `log`

### windows

- **destination.user** — `destination.user.domain` — `packages/windows/data_stream/forwarded/elasticsearch/ingest_pipeline/powershell_operational.yml:170` — data_stream: `forwarded`
- **destination.user** — `destination.user.name` — `packages/windows/data_stream/forwarded/elasticsearch/ingest_pipeline/powershell_operational.yml:176` — data_stream: `forwarded`
- **destination.user** — `destination.user.domain` — `packages/windows/data_stream/powershell_operational/elasticsearch/ingest_pipeline/default.yml:170` — data_stream: `powershell_operational`
- **destination.user** — `destination.user.name` — `packages/windows/data_stream/powershell_operational/elasticsearch/ingest_pipeline/default.yml:176` — data_stream: `powershell_operational`

### zoom

- **destination.user** — `destination.user.id` — `packages/zoom/data_stream/webhook/elasticsearch/ingest_pipeline/phone.yml:175` — data_stream: `webhook`
