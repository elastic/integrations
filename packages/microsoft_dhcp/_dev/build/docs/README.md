# Microsoft DHCP

This integration collects logs and metrics from Microsoft DHCP logs.

## Compatibility

This integration has been made to support the DHCP log format from Windows Server 2008 and later.

### Logs

Ingest logs from Microsoft DHCP Server, by default logged with the filename format:
`%windir%\System32\DHCP\DhcpSrvLog-*.log`

Relevant documentation for Microsoft DHCP can be found on [this]https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd183591(v=ws.10) location.

{{event "log"}}

{{fields "log"}}