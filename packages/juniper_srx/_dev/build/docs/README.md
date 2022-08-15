# Juniper SRX integration

This is an integration for ingesting logs from [Juniper SRX](https://www.juniper.net/documentation/en_US/release-independent/junos/information-products/pathway-pages/srx-series/product/).

### Log

The SRX Log integration only supports syslog messages in the format "structured-data + brief". See the [JunOS Documentation on structured-data.](https://www.juniper.net/documentation/en_US/junos/topics/reference/configuration-statement/structured-data-edit-system.html)

To configure a remote syslog destination, please reference the [SRX Getting Started - Configure System Logging.](https://kb.juniper.net/InfoCenter/index?page=content&id=kb16502)
The syslog format choosen should be `Default`.

The following processes and tags are supported:

| JunOS processes | JunOS tags                                |
|-----------------|-------------------------------------------|
| RT_FLOW         | RT_FLOW_SESSION_CREATE                    |
|                 | RT_FLOW_SESSION_CLOSE                     |
|                 | RT_FLOW_SESSION_DENY                      |
|                 | APPTRACK_SESSION_CREATE                   |
|                 | APPTRACK_SESSION_CLOSE                    |
|                 | APPTRACK_SESSION_VOL_UPDATE               |
| RT_IDS          | RT_SCREEN_TCP                             |
|                 | RT_SCREEN_UDP                             |
|                 | RT_SCREEN_ICMP                            |
|                 | RT_SCREEN_IP                              |
|                 | RT_SCREEN_TCP_DST_IP                      |
|                 | RT_SCREEN_TCP_SRC_IP                      |
| RT_UTM          | WEBFILTER_URL_PERMITTED                   |
|                 | WEBFILTER_URL_BLOCKED                     |
|                 | AV_VIRUS_DETECTED_MT                      |
|                 | CONTENT_FILTERING_BLOCKED_MT              |
|                 | ANTISPAM_SPAM_DETECTED_MT                 |
| RT_IDP          | IDP_ATTACK_LOG_EVENT                      |
|                 | IDP_APPDDOS_APP_STATE_EVENT               |
| RT_AAMW         | SRX_AAMW_ACTION_LOG                       |
|                 | AAMW_MALWARE_EVENT_LOG                    |
|                 | AAMW_HOST_INFECTED_EVENT_LOG              |
|                 | AAMW_ACTION_LOG                           |
| RT_SECINTEL     | SECINTEL_ACTION_LOG                       |


{{fields "log"}}