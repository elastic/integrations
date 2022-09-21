# Microsoft Exchange Online Message Trace

This integration is for Microsoft Exchange Online Message Trace logs. It includes the following
datasets for receiving logs over syslog or read from a file:

- `log` dataset: supports Microsoft Exchange Online Message Trace logs.

## Logs

Logs are either gathered via the rest API or via a logfile.

Sample Powershell script to get the logs and put them into a JSON file:

```powershell
# Install-Module -Name ExchangeOnlineManagement
$password = ConvertTo-SecureString "PASSWORD" -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential ("USERNAME@DOMAIN.TLD", $password)

Connect-ExchangeOnline -Credential $Credential
$messageTrace = Get-MessageTrace | ConvertTo-Json
$messageTrace | Out-File -FilePath ".\messageTrace.json" -Encoding UTF8
```

### Microsoft Exchange Online Message Trace

The `log` dataset collects the Microsoft Exchange Online Message Trace logs.

[Log Documentation](https://docs.microsoft.com/en-us/previous-versions/office/developer/o365-enterprise-developers/jj984335(v=office.15))

{{event "log"}}

{{fields "log"}}