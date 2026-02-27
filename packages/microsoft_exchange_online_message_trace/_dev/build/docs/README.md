# Microsoft Exchange Online Message Trace

This integration is for Microsoft Exchange Online Message Trace logs. It includes the following datasets for receiving logs over the Microsoft Exchange Online Message Trace API or read from a file:

- `log` dataset: supports Microsoft Exchange Online Message Trace logs.

## Migration from the Legacy Message Trace API to the Graph API

Microsoft has announced the deprecation on March 18th, 2026 of the legacy Message Trace API support in the Reporting Webservice.

This integration has been updated to use the new Graph-based message trace API.  New credential setup will be required, as described below.

The new Message Trace experience includes an updated PowerShell cmdlet, `Get-MessageTraceV2`, in General Availability since June 3rd, 2025, which can be used to collect data with a manual script, to be ingested from a log file. However, the Graph-based message trace API is preferred.

## Setup

### Graph API setup

To collect message trace logs from Microsoft's Graph API, you need to:
- Create an Entra app and record the Directory ID (tenant ID) and Application ID (client ID).
- Add the `ExchangeMessageTrace.Read.All` permission and grant admin consent for it.
- Create a client secret and record it.
- Create a service principal for Microsoft's internal Message Trace app in the tenant.

For more details, refer to Microsoft's [Graph-based message trace API onboarding guide](https://learn.microsoft.com/en-us/exchange/monitoring/trace-an-email-message/graph-api-message-trace).

After that is done, you can configure the Microsoft Exchange Online Message Trace integration using the Tenant ID, Client ID and Client Secret.

These are different from the OAuth credentails used previously with the legacy Message Trace API in the Reporting Webservice.

### Integration settings

To configure `Local Domains` you can check your [Microsoft Admin Exchange Center](https://admin.exchange.microsoft.com/) for the domains
available in your organization. They are usually under the sections [Accepted Domains](https://admin.exchange.microsoft.com/#/accepteddomains) and [Remote Domains](https://admin.exchange.microsoft.com/#/remotedomains).

### Log file collection 

It is possible to collect data using a PowerShell script and have the integration ingest it from a log file. However, the Graph API-based method above is preferred.

**Disclaimer:** You may need to adapt the authentication method of the script
below to match your environment. For more information about authentication
methods available in PowerShell, please see the
[guides here](https://learn.microsoft.com/en-us/powershell/exchange/connect-to-exchange-online-powershell?view=exchange-ps).
Note that basic authentication (with `-Authentication Basic`) is no longer
supported.

The following example PowerShell script can be adapted to fetch the logs and
write them into a JSON file that the integration can consume (via the logfile
input).

Prerequisites:

Install the Exchange Online Management module by running the following command:

````powershell
Install-Module -Name ExchangeOnlineManagement
````

Import the Exchange Online Management module by running the following command:

````powershell
Import-Module -Name ExchangeOnlineManagement
````

This script would have to be triggered at a certain interval, in accordance
with the look-back interval specified.  In this example script, the look back
is 24 hours, so the interval would need to be daily. For more information about
the `Get-MessageTraceV2` cmdlet, please refer to its
[documentation](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-messagetracev2?view=exchange-ps).

```powershell
# Username and Password
$username = "USERNAME@DOMAIN.TLD"
$password = "PASSWORD"
# Lookback in Hours
$lookback = "-24"
# Results per request (maximum 5000)
$resultSize = "5000"
# Output of the json file
# This would then be ingested via the integration
$output_location = "C:\temp\messageTrace.json"

$password = ConvertTo-SecureString $password -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential ($username, $password)
$startDate = (Get-Date).AddHours($lookback)
$endDate = Get-Date

Connect-ExchangeOnline -Credential $Credential

$paginate = 1
$output = @()

# Initialize V2-style pagination cursor values
$startingRecipientAddress = $null
$currentEndDate = $endDate

while ($paginate -eq 1)
{
    if ($startingRecipientAddress) {
        $messageTrace = Get-MessageTraceV2 -ResultSize $resultSize -StartDate $startDate -EndDate $currentEndDate -StartingRecipientAddress $startingRecipientAddress
    }
    else {
        $messageTrace = Get-MessageTraceV2 -ResultSize $resultSize -StartDate $startDate -EndDate $currentEndDate
    }

    if (!$messageTrace)
    {
        $paginate = 0
    }
    else
    {
        $output = $output + $messageTrace

        # If we got fewer than ResultSize rows, we've reached the end
        if ($messageTrace.Count -lt [int]$resultSize)
        {
            $paginate = 0
        }
        else
        {
            # Prepare the cursor data for the next query
            $last = $messageTrace[-1]
            $startingRecipientAddress = $last.RecipientAddress
            $currentEndDate = $last.Received
        }
    }
}

if (Test-Path $output_location)
{
    Remove-Item $output_location
}
foreach ($event in $output)
{
    $event.StartDate = [Xml.XmlConvert]::ToString(($event.StartDate), [Xml.XmlDateTimeSerializationMode]::Utc)
    $event.EndDate   = [Xml.XmlConvert]::ToString(($event.EndDate),   [Xml.XmlDateTimeSerializationMode]::Utc)
    $event.Received  = [Xml.XmlConvert]::ToString(($event.Received),  [Xml.XmlDateTimeSerializationMode]::Utc)
    $event = $event | ConvertTo-Json -Compress
    Add-Content $output_location $event -Encoding UTF8
}
```

{{event "log"}}

{{fields "log"}}
