# Microsoft DHCP

This integration collects logs and metrics from [Microsoft DHCP logs](https://docs.microsoft.com/en-us/windows-server/networking/technologies/dhcp/dhcp-dns-events/).

## Compatibility

This integration has been made to support the DHCP log format from Windows Server 2008 and later.

### Logs

Ingest logs from Microsoft DHCP Server, by default logged with the filename format:
`%windir%\System32\DHCP\DhcpSrvLog-*.log`

Logs may also be ingested from Microsoft DHCPv6 Server, by default logged with the filename format:
`%windir%\System32\DHCP\DhcpV6SrvLog-*.log`

{{event "log"}}

{{fields "log"}}