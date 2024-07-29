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
An example event for `log` looks as following:

```json
{
    "@timestamp": "2022-10-21T17:25:36.969Z",
    "agent": {
        "ephemeral_id": "7db2c43f-4281-444d-b5b8-242a7ddf8ba2",
        "id": "d2a14a09-96fc-4f81-94ef-b0cd75ad71e7",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "microsoft_exchange_online_message_trace.log",
        "namespace": "63147",
        "type": "logs"
    },
    "destination": {
        "domain": "contoso.com",
        "registered_domain": "contoso.com",
        "top_level_domain": "com",
        "user": {
            "domain": "contoso.com",
            "email": "linus@contoso.com",
            "id": "linus@contoso.com",
            "name": "linus"
        }
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "d2a14a09-96fc-4f81-94ef-b0cd75ad71e7",
        "snapshot": false,
        "version": "8.13.0"
    },
    "email": {
        "attachments": {
            "file": {
                "size": 22761
            }
        },
        "delivery_timestamp": "2022-10-21T17:25:36.969376Z",
        "from": {
            "address": [
                "noreply@azure.microsoft.com"
            ]
        },
        "local_id": "a5e6dc0f-23df-4b20-d240-08dab38944a1",
        "message_id": "<GVAP278MB037586A65EF1FB2F844B0258DA2D9@GVAP278MB0375.CHEP278.PROD.OUTLOOK.COM>",
        "subject": "testmail 2",
        "to": {
            "address": [
                "linus@contoso.com"
            ]
        }
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "microsoft_exchange_online_message_trace.log",
        "end": "2022-10-22T09:40:10.000Z",
        "ingested": "2024-06-12T03:18:25Z",
        "original": "{\"Organization\":\"contoso.com\",\"MessageId\":\"\\u003cGVAP278MB037586A65EF1FB2F844B0258DA2D9@GVAP278MB0375.CHEP278.PROD.OUTLOOK.COM\\u003e\",\"Received\":\"2022-10-21T17:25:36.969376Z\",\"SenderAddress\":\"noreply@azure.microsoft.com\",\"RecipientAddress\":\"linus@contoso.com\",\"Subject\":\"testmail 2\",\"Status\":\"Delivered\",\"ToIP\":null,\"FromIP\":\"40.107.23.54\",\"Size\":22761,\"MessageTraceId\":\"a5e6dc0f-23df-4b20-d240-08dab38944a1\",\"StartDate\":\"2022-10-21T09:40:10Z\",\"EndDate\":\"2022-10-22T09:40:10Z\",\"Index\":0}",
        "outcome": "success",
        "start": "2022-10-21T09:40:10.000Z"
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/microsoft_exchange_online_message_trace_test.ndjson.log"
        },
        "offset": 0
    },
    "microsoft": {
        "online_message_trace": {
            "EndDate": "2022-10-22T09:40:10Z",
            "FromIP": "40.107.23.54",
            "Index": 0,
            "MessageId": "<GVAP278MB037586A65EF1FB2F844B0258DA2D9@GVAP278MB0375.CHEP278.PROD.OUTLOOK.COM>",
            "MessageTraceId": "a5e6dc0f-23df-4b20-d240-08dab38944a1",
            "Organization": "contoso.com",
            "Received": "2022-10-21T17:25:36.969376Z",
            "RecipientAddress": "linus@contoso.com",
            "SenderAddress": "noreply@azure.microsoft.com",
            "Size": 22761,
            "StartDate": "2022-10-21T09:40:10Z",
            "Status": "Delivered",
            "Subject": "testmail 2"
        }
    },
    "related": {
        "user": [
            "linus@contoso.com",
            "noreply@azure.microsoft.com",
            "linus",
            "noreply"
        ]
    },
    "source": {
        "domain": "azure.microsoft.com",
        "ip": "40.107.23.54",
        "registered_domain": "microsoft.com",
        "subdomain": "azure",
        "top_level_domain": "com",
        "user": {
            "domain": "azure.microsoft.com",
            "email": "noreply@azure.microsoft.com",
            "id": "noreply@azure.microsoft.com",
            "name": "noreply"
        }
    },
    "tags": [
        "preserve_original_event",
        "microsoft-defender-endpoint",
        "forwarded"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| input.type |  | keyword |
| log.offset |  | long |
| microsoft.online_message_trace.EndDate | This field is used to limit the report period. Use this field in a $filter query option to set the end date and time of the reporting period. If you supply EndDate in the $filter option, you must also supply StartDate. In this report, this field corresponds to the date and time of the last processing step recorded for the message. | date_nanos |
| microsoft.online_message_trace.FromIP | The IPv4 or IPv6 address that transmitted the message to the Office 365 email system. | keyword |
| microsoft.online_message_trace.Index |  | long |
| microsoft.online_message_trace.MessageId | The Internet MessageID header of the message, if one was supplied. This value can also be explicitly null.\</p\>\</td\> | keyword |
| microsoft.online_message_trace.MessageTraceId | An identifier used to get the detailed message transfer trace information.\</p\>\</td\> | keyword |
| microsoft.online_message_trace.Organization | The fully qualified domain name that was processing the email.\</p\>\</td\> | keyword |
| microsoft.online_message_trace.Received | The date and time when the email was received by the Office 365 email system. This corresponds to the Date field of the first message trace detail entry.\</p\>\</td\> | date_nanos |
| microsoft.online_message_trace.RecipientAddress | The SMTP email address of the user that the message was addressed to.\</p\>\</td\> | keyword |
| microsoft.online_message_trace.SenderAddress | The SMTP email address of the user the message was purportedly from. Because sender addresses are commonly spoofed in spam email, they are not considered completely reliable.\</p\>\</td\> | keyword |
| microsoft.online_message_trace.Size | The size of the message, in bytes. | long |
| microsoft.online_message_trace.StartDate | This field is used to limit the report period. Use this field in a $filter query option to set the start date and time of the reporting period. If you provide a StartDate in the $filter option, you must also specify an EndDate. In this report, this field corresponds to the date and time of the first processing step recorded for the message.\</p\>\</td\> | date_nanos |
| microsoft.online_message_trace.Status | The status of the message in the Office 365 email system. This corresponds to the Detail field of the last processing step recorded for the message.\</p\>\</td\> | keyword |
| microsoft.online_message_trace.Subject | The subject line of the message, if one was present for the message.\</p\>\</td\> | keyword |
| microsoft.online_message_trace.ToIP | The IPv4 or IPv6 address that the Office 365 email system sent the message to.\</p\>\</td\> | keyword |
