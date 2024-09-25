# Microsoft Exchange Online Message Trace

This integration is for Microsoft Exchange Online Message Trace logs. It includes the following
datasets for receiving logs over the Microsoft Exchange Online Message Trace API or read from a file:

- `log` dataset: supports Microsoft Exchange Online Message Trace logs.

## Basic Auth Deprecation notification
The basic authentication configuration fields have been removed from this integration as Microsoft has deprecated and disabled basic authentication for Exchange Online. See the [deprecation notification](https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/deprecation-of-basic-authentication-exchange-online) for details.

## Office 365 Account Requirements
At a minimum, your Office 365 service account should include a role with Message Tracking and View‑Only Recipients permissions, assigned to the Office 365 user account
that will be used for the integration. Assign these permissions using the [Exchange admin center](https://admin.exchange.microsoft.com).

## Logs
Logs are either gathered via the rest API or via a logfile. [Log Documentation](https://docs.microsoft.com/en-us/previous-versions/office/developer/o365-enterprise-developers/jj984335(v=office.15))

## Microsoft Exchange Online Message Trace API
The `log` dataset collects the Microsoft Exchange Online Message Trace logs. To search for ingested logs in Elasticsearch you need to query using `datastream.dataset: microsoft_exchange_online_message_trace.log`. This integration will poll the Microsoft Exchange Online Message Trace legacy API (https://reports.office365.com/ecp/reportingwebservice/reporting.svc/MessageTrace) to pull Message Trace logs and ingest them via the ingest pipelines.

## Configuring with OAuth2
In order to continue using the Microsoft Exchange Online Message Trace you will need to enable and configure OAuth2 authentication via your service app.
- ### Service App Configuration  
    1) In the [Azure portal](https://portal.azure.com/), create a Microsoft Entra App (service app) Registration. For details please refer to the official [Microsoft Documentation](https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal).
    2) In most cases under the `Redirect URI` section, you would want to configure the value `Web` for the `app type` and `http://localhost` for the `Redirect URI`, unless there are some specific requirements on your end.
    3) Assign the application at least one Microsoft Entra (Azure AD) role that will enable it to access the Reporting Web Service:
        - Security Reader
        - Global Reader
    4) The App Registration should contain the following API permissions: Office 365 Exchange Online > `ReportingWebService.Read.All` (application). See [Specify the permissions your app requires to access the Reporting Web Service](https://learn.microsoft.com/en-gb/previous-versions/office/developer/o365-enterprise-developers/jj984325(v=office.15)#specify-the-permissions-your-app-requires-to-access-the-reporting-web-service).

- ### Configuring OAuth2 Credentials
  Once you have your service app registered and configured, you can now configure your OAuth2 credentials as follows:- 
    1) Generate a client secret for your registered service app. Copy and store the `client secret value` with you as this will be required for your OAuth2 credentials.
    2) Fill in the following fields with the appropriate values from your `configured service app`:-
        
        - **Client ID**: The `client_id` of your `service app` to pass in the OAuth request parameter.
        - **Client secret**:  The `client_secret`  of your `service app` that you generated earlier, to pass in the OAuth request parameter.
        - **Tenant ID**: The Directory ID (tenant identifier) of your `service app` in your Microsoft Entra ID(Azure Active Directory).
  
  
  With these values now configured, the OAuth2 configuration for the integration should be ideally complete. For more details, please check the 
  official doc for [Getting Started with Reporting Web Service](https://learn.microsoft.com/en-gb/previous-versions/office/developer/o365-enterprise-developers/jj984325(v=office.15)#get-started-with-reporting-web-service).

### NOTE
- For configuring `Local Domains` you can check your [Microsoft Admin Exchange Center](https://admin.exchange.microsoft.com/) for the domains
available in your organization. They are usually under the sections [Accepted Domains](https://admin.exchange.microsoft.com/#/accepteddomains) and [Remote Domains](https://admin.exchange.microsoft.com/#/remotedomains).

- The default `Polling Interval` and `Initial Interval` values are configured to `1h`, you can however change these to your required values. The look-back 
  value of `Initial Interval` should not exceed `200 hours` as this might cause unexpected errors with the API.

- The default `Additional Look-back Time` value is configured for `1h`. 
  This is intended to capture events that may not have been initially present due to eventual consistency.
  This value does not need to exceed [`24h`](https://learn.microsoft.com/en-us/previous-versions/office/developer/o365-enterprise-developers/jj984335(v=office.15)#data-granularity-persistence-and-availability).
    - Note: The larger this value is, the less likely events will be missed, however, this will cause the integration to take longer to pull all events, making newer events take longer to become present.

- The default value of `Batch Size` is set to 1000. This means for every request Httpjson will paginate with a value of 1000 results per page. The 
   maximum page size supported by the Message Trace API is `2000`. The API will return an empty `value` array when there are no more logs to pull and the
   pagination will terminate with an error that can be ignored.

## Logfile collection 

**Disclaimer:**  With basic authentication support now disabled, the PowerShell script provided below will not work as is. However, you can 
see the [guides here](https://learn.microsoft.com/en-us/powershell/exchange/connect-to-exchange-online-powershell?view=exchange-ps) on how 
to connect to PowerShell using different authentication techniques using the EXO V2 and V3 modules. With a combination of the script below
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

This script would have to be triggered at a certain interval, in accordance with the look-back interval specified.
In this example script, the look back would be 24 hours, so the interval would need to be daily.
According to the [Documentation](https://learn.microsoft.com/en-us/powershell/module/exchange/get-messagetrace?view=exchange-ps),
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