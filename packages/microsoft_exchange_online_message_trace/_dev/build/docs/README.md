# Microsoft Exchange Online Message Trace

This integration is for Microsoft Exchange Online Message Trace logs. It includes the following
datasets for receiving logs over the Microsoft Exchange Online Message Trace API or read from a file:

- `log` dataset: supports Microsoft Exchange Online Message Trace logs.

## Logs

Logs are either gathered via the rest API or via a logfile.

### Microsoft Exchange Online Message Trace API

The `log` dataset collects the Microsoft Exchange Online Message Trace logs.

[Log Documentation](https://docs.microsoft.com/en-us/previous-versions/office/developer/o365-enterprise-developers/jj984335(v=office.15))

## Configuring with OAuth2
The basic authentication configuration fields have been removed from this integration as Microsoft has deprecated and disabled basic authentication for Exchange Online. See the [deprecation notification](https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/deprecation-of-basic-authentication-exchange-online) for details.
In order to continue using the Microsoft Exchange Online Message Trace you will need to enable and configure OAuth2 authentication.

### Steps :
You'll need to register your application with Azure Active Directory and obtain the necessary credentials: Client ID, Client Secret, and Tenant ID. 
You can follow these steps to create an Azure AD application:

1) Go to the Azure portal (https://portal.azure.com/) and sign in.
2) Click on "Azure Active Directory" in the left-hand menu.
3) Select "App registrations" and click "New registration".
4) Enter a name for your application, select "Accounts in this organizational directory only" for "Supported account types", and enter the redirect 
   URI for your application.
5) Click "Register" to create the application.
6) On the application page, make note of the "Application (client) ID" (which is your client ID) and the "Directory (tenant) ID" (which is your 
   tenant ID).
7) Under "Certificates & secrets", click "New client secret" to create a new secret. Make note of the secret value (which is your client secret).

With these credentials in hand, you can now configure the integration with the appropriate parameters.

### Logfile collection 

**Disclaimer:**  Due to Microsoft deprecating basic auth support recently, the powershell script provided below will not work as it is. However you can 
see the [guides here](https://learn.microsoft.com/en-us/powershell/exchange/connect-to-exchange-online-powershell?view=exchange-ps) on how 
to connect to powershell using different authentication techniques using the EXO V2 and V3 modules. With a combination of the script below
and the alternate authentication methods mentioned in the guide, you can possibly perform the logfile collection as usual.
<br>

The following sample Powershell script may be used to get the logs and put them into a JSON file that can then be
consumed by the logfile input:

Prerequisites:

Install the Exchange Online Management module by running the following command: 

````powershell
Install-Module -Name ExchangeOnlineManagement
````

Import the Exchange Online Management module by running the following command:

````powershell
Import-Module -Name ExchangeOnlineManagement
````

This script would have to be triggered at a certain interval, in accordance with the look back interval specified.
In this example script the look back would be 24 hours, so the interval would need to be daily.
According to the [documentation](https://learn.microsoft.com/en-us/powershell/module/exchange/get-messagetrace?view=exchange-ps)
it is only possible to get up to 1k pages. If this should be an issue, try reducing the `$looback` or increasing `$pageSize`.

```powershell
# Username and Password
$username = "USERNAME@DOMAIN.TLD"
$password = "PASSWORD"
# Lookback in Hours
$lookback = "-24"
# Page Size, should be no problem with 1k
$pageSize = "1000"
# Output of the json file
# This would then be ingested via the integration
$output_location = "C:\temp\messageTrace.json"

$password = ConvertTo-SecureString $password -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential ($username, $password)
$startDate = (Get-Date).AddHours($lookback)
$endDate = Get-Date

Connect-ExchangeOnline -Credential $Credential
$paginate = 1
$page = 1
$output = @()
while ($paginate -eq 1)
{
    $messageTrace = Get-MessageTrace -PageSize $pageSize -StartDate $startDate -EndDate $endDate -Page $page
    $page
    if (!$messageTrace)
    {
        $paginate = 0
    }
    else
    {
        $page++
        $output = $output + $messageTrace
    }
}
if (Test-Path $output_location)
{
    Remove-Item $output_location
}
foreach ($event in $output)
{
    $event.StartDate = [Xml.XmlConvert]::ToString(($event.StartDate), [Xml.XmlDateTimeSerializationMode]::Utc)
    $event.EndDate = [Xml.XmlConvert]::ToString(($event.EndDate), [Xml.XmlDateTimeSerializationMode]::Utc)
    $event.Received = [Xml.XmlConvert]::ToString(($event.Received), [Xml.XmlDateTimeSerializationMode]::Utc)
    $event = $event | ConvertTo-Json -Compress
    Add-Content $output_location $event -Encoding UTF8
}
```
{{event "log"}}

{{fields "log"}}