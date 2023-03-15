# HP iLO integration

This is an integration for ingesting logs from [HP iLO](https://www.hpe.com/us/en/servers/integrated-lights-out-ilo.html).

### Log

To configure remote syslog, please see [HP-iLO Configure syslog](https://support.hpe.com/hpesc/public/docDisplay?docId=emr_na-a00045612en_us). Policies are included herein for tcp and udp though by default hp-ilo remote syslog supports udp with default port:514.

### Support

Supported version should be any version of hp-ilo that allows for remote syslog, as it is syslog it ought to be pretty stable. Any OS that supports this should work.

{{event "log"}}

{{fields "log"}}