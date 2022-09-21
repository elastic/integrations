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

An example event for `log` looks as following:

```json
{
    "@timestamp": "2022-09-14T07:40:51.940Z",
    "agent": {
        "ephemeral_id": "cc87017e-49e4-4b91-b5a2-e2a5e830da56",
        "id": "174d960c-8eb9-4247-ae1b-9c01978d94c2",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.3.3"
    },
    "data_stream": {
        "dataset": "microsoft_exchange_online_message_trace.log",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.3.1"
    },
    "elastic_agent": {
        "id": "174d960c-8eb9-4247-ae1b-9c01978d94c2",
        "snapshot": false,
        "version": "8.3.3"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "microsoft_exchange_online_message_trace.log",
        "ingested": "2022-09-14T07:40:52Z",
        "original": "{\"odata.metadata\":\"https://reports.office365.com/ecp/ReportingWebService/Reporting.svc/$metadata#MessageTrace\",\"value\":[{\"Organization\":\"wildsecurity.onmicrosoft.com\",\"MessageId\":\"\u003ca210cf91-4f2e-484c-8ada-3b27064ee5e3@az.uksouth.production.microsoft.com\u003e\",\"Received\":\"2022-09-05T18:10:13.4907658\",\"SenderAddress\":\"azure-noreply@microsoft.com\",\"RecipientAddress\":\"linus@wildsecurity.onmicrosoft.com\",\"Subject\":\"PIM: A privileged directory role was assigned outside of PIM\",\"Status\":\"Delivered\",\"ToIP\":\"216.160.83.56\",\"FromIP\":\"81.2.69.144\",\"Size\":87891,\"MessageTraceId\":\"cf7a249a-5edd-4350-130a-08da8f69e0f6\",\"StartDate\":\"2022-09-04T09:01:46.0369423Z\",\"EndDate\":\"2022-09-06T09:01:46.0369423Z\",\"Index\":0}]}"
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/defender_atp-test.json.log"
        },
        "offset": 0
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
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.as.organization.name.text | Multi-field of `destination.as.organization.name`. | match_only_text |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
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
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
