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
    "@timestamp": "2022-10-21T17:25:36.969376Z",
    "agent": {
        "ephemeral_id": "2e812a1b-8325-40ec-b03f-94d26ef6cf76",
        "id": "4d88038c-4b3b-4bb4-95f4-cc5789c88852",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0"
    },
    "data_stream": {
        "dataset": "microsoft_exchange_online_message_trace.log",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "domain": "contoso.com",
        "registered_domain": "contoso.com",
        "top_level_domain": "com"
    },
    "ecs": {
        "version": "8.5.0"
    },
    "elastic_agent": {
        "id": "4d88038c-4b3b-4bb4-95f4-cc5789c88852",
        "snapshot": false,
        "version": "8.0.0"
    },
    "email": {
        "attachments": {
            "file": {
                "size": 22761
            }
        },
        "delivery_timestamp": "2022-10-21T17:25:36.969376Z",
        "from": {
            "address": "noreply@azure.microsoft.com"
        },
        "local_id": "a5e6dc0f-23df-4b20-d240-08dab38944a1",
        "message_id": "\u003cGVAP278MB037586A65EF1FB2F844B0258DA2D9@GVAP278MB0375.CHEP278.PROD.OUTLOOK.COM\u003e",
        "subject": "testmail 2",
        "to": {
            "address": "linus@contoso.com"
        }
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "microsoft_exchange_online_message_trace.log",
        "end": "2022-10-22T09:40:10.000Z",
        "ingested": "2022-10-25T10:21:12Z",
        "original": "{\"Organization\":\"contoso.com\",\"MessageId\":\"\\u003cGVAP278MB037586A65EF1FB2F844B0258DA2D9@GVAP278MB0375.CHEP278.PROD.OUTLOOK.COM\\u003e\",\"Received\":\"2022-10-21T17:25:36.969376Z\",\"SenderAddress\":\"noreply@azure.microsoft.com\",\"RecipientAddress\":\"linus@contoso.com\",\"Subject\":\"testmail 2\",\"Status\":\"Delivered\",\"ToIP\":null,\"FromIP\":\"40.107.23.54\",\"Size\":22761,\"MessageTraceId\":\"a5e6dc0f-23df-4b20-d240-08dab38944a1\",\"StartDate\":\"2022-10-21T09:40:10Z\",\"EndDate\":\"2022-10-22T09:40:10Z\",\"Index\":0}",
        "outcome": "Delivered"
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
    "source": {
        "domain": "azure.microsoft.com",
        "ip": "40.107.23.54",
        "registered_domain": "microsoft.com",
        "subdomain": "azure",
        "top_level_domain": "com"
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
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| input.type |  | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.offset |  | long |
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
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
