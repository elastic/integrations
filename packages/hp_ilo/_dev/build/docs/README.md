# HP iLO integration

This is an integration for ingesting logs from [HP iLO](https://www.hpe.com/us/en/servers/integrated-lights-out-ilo.html).

### Log

To configure a remote syslog destination, please see [Configure syslog](https://support.hpe.com/hpesc/public/docDisplay?docId=emr_na-a00045612en_us). Example system tests are included herein for tcp, udp, tls, thought at present hp-ilo remote logging only supports udp, default port:514.


{{fields "log"}}