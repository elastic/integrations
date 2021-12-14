# QNAP NAS

The QNAP NAS integration collects Event and Access logs from QNAP NAS devices.

## Log

The `log` dataset receives QNAP NAS Event and Access logs over the syslog protocol. This has been tested with QTS 4.5.4 but is expected to work with new versions.  This integration is only compatible with the "Send to Syslog Server" option which uses the RFC-3164 syslog format. Both Event and Access events are supported. All protocols; UDP, TCP, TLS are supported.

### Example event

{{event "log"}}

**Exported fields**

{{fields "log"}}
