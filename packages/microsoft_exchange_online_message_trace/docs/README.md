# Microsoft Exchange Online Message Trace

This integration is for Microsoft Exchange Online Message Trace logs. It includes the following
datasets for receiving logs over the Microsoft Exchange Online Message Trace API or read from a file:

- `log` dataset: supports Microsoft Exchange Online Message Trace logs.

## Logs

Logs are either gathered via the rest API or via a logfile.

### Microsoft Exchange Online Message Trace API

The `log` dataset collects the Microsoft Exchange Online Message Trace logs.

[Log Documentation](https://docs.microsoft.com/en-us/previous-versions/office/developer/o365-enterprise-developers/jj984335(v=office.15))

### Logfile collection

The following sample Powershell script may be used to get the logs and put them into a JSON file that can then be
consumed by the logfile input:

Prerequisites:

````powershell
Install-Module -Name ExchangeOnlineManagement
````

This script would have to be triggered at a certain interval, in accordance with the look back interval specified.
In this example script the look back would be 24 hours, so the interval would need to be daily.
According to the
[documentation](https://learn.microsoft.com/en-us/powershell/module/exchange/get-messagetrace?view=exchange-ps)
it is only possible to get up to 1k pages.
If this should be an issue, try reducing the `$looback` or increasing `$pageSize`.

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
    "@timestamp": "2022-09-05T18:10:13.490Z",
    "agent": {
        "ephemeral_id": "8de97862-77fa-4e44-91be-5d3947dd67aa",
        "id": "6f0c420a-c434-4d40-90cb-956665a6fdd6",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.5.1"
    },
    "data_stream": {
        "dataset": "microsoft_exchange_online_message_trace.log",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "as": {
            "number": 209
        },
        "domain": "contoso.com",
        "geo": {
            "city_name": "Milton",
            "continent_name": "North America",
            "country_iso_code": "US",
            "country_name": "United States",
            "location": {
                "lat": 47.2513,
                "lon": -122.3149
            },
            "region_iso_code": "US-WA",
            "region_name": "Washington"
        },
        "ip": "216.160.83.56",
        "registered_domain": "contoso.com",
        "top_level_domain": "com"
    },
    "ecs": {
        "version": "8.6.0"
    },
    "elastic_agent": {
        "id": "6f0c420a-c434-4d40-90cb-956665a6fdd6",
        "snapshot": false,
        "version": "8.5.1"
    },
    "email": {
        "attachments": {
            "file": {
                "size": 87891
            }
        },
        "delivery_timestamp": "2022-09-05T18:10:13.4907658",
        "from": {
            "address": "azure-noreply@microsoft.com"
        },
        "local_id": "cf7a249a-5edd-4350-130a-08da8f69e0f6",
        "message_id": "\u003ca210cf91-4f2e-484c-8ada-3b27064ee5e3@az.uksouth.production.microsoft.com\u003e",
        "subject": "PIM: A privileged directory role was assigned outside of PIM",
        "to": {
            "address": "linus@contoso.com"
        }
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2023-02-05T23:16:02.721Z",
        "dataset": "microsoft_exchange_online_message_trace.log",
        "end": "2022-09-06T09:01:46.036Z",
        "ingested": "2023-02-05T23:16:03Z",
        "original": "{\"EndDate\":\"2022-09-06T09:01:46.0369423Z\",\"FromIP\":\"81.2.69.144\",\"Index\":0,\"MessageId\":\"\\u003ca210cf91-4f2e-484c-8ada-3b27064ee5e3@az.uksouth.production.microsoft.com\\u003e\",\"MessageTraceId\":\"cf7a249a-5edd-4350-130a-08da8f69e0f6\",\"Organization\":\"contoso.com\",\"Received\":\"2022-09-05T18:10:13.4907658\",\"RecipientAddress\":\"linus@contoso.com\",\"SenderAddress\":\"azure-noreply@microsoft.com\",\"Size\":87891,\"StartDate\":\"2022-09-04T09:01:46.0369423Z\",\"Status\":\"Delivered\",\"Subject\":\"PIM: A privileged directory role was assigned outside of PIM\",\"ToIP\":\"216.160.83.56\"}",
        "outcome": "Delivered",
        "start": "2022-09-04T09:01:46.036Z"
    },
    "input": {
        "type": "httpjson"
    },
    "microsoft": {
        "online_message_trace": {
            "EndDate": "2022-09-06T09:01:46.0369423Z",
            "FromIP": "81.2.69.144",
            "Index": 0,
            "MessageId": "\u003ca210cf91-4f2e-484c-8ada-3b27064ee5e3@az.uksouth.production.microsoft.com\u003e",
            "MessageTraceId": "cf7a249a-5edd-4350-130a-08da8f69e0f6",
            "Organization": "contoso.com",
            "Received": "2022-09-05T18:10:13.4907658",
            "RecipientAddress": "linus@contoso.com",
            "SenderAddress": "azure-noreply@microsoft.com",
            "Size": 87891,
            "StartDate": "2022-09-04T09:01:46.0369423Z",
            "Status": "Delivered",
            "Subject": "PIM: A privileged directory role was assigned outside of PIM",
            "ToIP": "216.160.83.56"
        }
    },
    "source": {
        "domain": "microsoft.com",
        "geo": {
            "city_name": "London",
            "continent_name": "Europe",
            "country_iso_code": "GB",
            "country_name": "United Kingdom",
            "location": {
                "lat": 51.5142,
                "lon": -0.0931
            },
            "region_iso_code": "GB-ENG",
            "region_name": "England"
        },
        "ip": "81.2.69.144",
        "registered_domain": "microsoft.com",
        "top_level_domain": "com"
    },
    "tags": [
        "preserve_original_event",
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
| destination.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.as.organization.name.text | Multi-field of `destination.as.organization.name`. | match_only_text |
| destination.domain | The domain name of the destination system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.registered_domain | The highest registered destination domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| destination.subdomain | The subdomain portion of a fully qualified domain name includes all of the names except the host name under the registered_domain.  In a partially qualified domain, or if the the qualification level of the full name cannot be determined, subdomain contains all of the names below the registered domain. For example the subdomain portion of "www.east.mydomain.co.uk" is "east". If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| destination.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| destination.user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| destination.user.email | User email address. | keyword |
| destination.user.id | Unique identifier of the user. | keyword |
| destination.user.name | Short name or login of the user. | keyword |
| destination.user.name.text | Multi-field of `destination.user.name`. | match_only_text |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| email.attachments.file.size | Attachment file size in bytes. | long |
| email.delivery_timestamp | The date and time when the email message was received by the service or client. | date |
| email.direction | The direction of the message based on the sending and receiving domains. | keyword |
| email.from.address | The email address of the sender, typically from the RFC 5322 `From:` header field. | keyword |
| email.local_id | Unique identifier given to the email by the source that created the event. Identifier is not persistent across hops. | keyword |
| email.message_id | Identifier from the RFC 5322 `Message-ID:` email header that refers to a particular email message. | wildcard |
| email.subject | A brief summary of the topic of the message. | keyword |
| email.subject.text | Multi-field of `email.subject`. | match_only_text |
| email.to.address | The email address of recipient | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| input.type |  | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
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
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.domain | The domain name of the source system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.registered_domain | The highest registered source domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| source.subdomain | The subdomain portion of a fully qualified domain name includes all of the names except the host name under the registered_domain.  In a partially qualified domain, or if the the qualification level of the full name cannot be determined, subdomain contains all of the names below the registered domain. For example the subdomain portion of "www.east.mydomain.co.uk" is "east". If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| source.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| source.user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| source.user.email | User email address. | keyword |
| source.user.id | Unique identifier of the user. | keyword |
| source.user.name | Short name or login of the user. | keyword |
| source.user.name.text | Multi-field of `source.user.name`. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.email | User email address. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
