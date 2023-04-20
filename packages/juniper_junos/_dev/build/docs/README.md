# Juniper JunOS integration

This is an integration for ingesting logs from [Juniper JunOS](https://www.juniper.net/documentation/product/us/en/junos-os).  For more information on sending syslog messages from JunOS to a remote destination such as a file / syslog host, see: [Directing System Log Messages to a Remote Machine or the Other Routing Engine](https://www.juniper.net/documentation/us/en/software/junos/network-mgmt/topics/topic-map/directing-system-log-messages-to-a-remote-destination.html).

### Log

The `log` dataset collects Juniper JunOS logs.

{{event "log"}}

{{fields "log"}}