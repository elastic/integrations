# Microsoft integration (Deprecated)

_This integration is deprecated. Please use one of the other Microsoft integrations
that are specific to a Microsoft product._

This integration is for Microsoft logs. It includes the following datasets for receiving logs over syslog or read from a file:

- `defender_atp` dataset: Supports Microsoft Defender for Endpoint (Microsoft Defender ATP)
- `dhcp` dataset: Supports Microsoft DHCP logs.

## Logs

### Defender ATP

To allow the integration to ingest data from the Microsoft Defender API, you would need to create a new application on your Azure domain.

The procedure to create an application is found on the below link:

https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/exposed-apis-create-app-webapp[Create a new Azure Application]

When giving the application the API permissions described in the documentation (`Windows Defender ATP Alert.Read.All`) it will only grant access to read alerts from ATP and nothing else in the Azure Domain.

After the application has been created, it should contain 3 values that you need to apply to the module configuration.

These values are:

- Client ID
- Client Secret
- Tenant ID

#### ECS mappings

| Defender ATP Fields                 | ECS Fields                     |
|-------------------------------------|--------------------------------|
| alertCreationTime                   | @timestamp                     |
| aadTenantId                         | cloud.account.id               |
| category                            | threat.technique.name          |
| computerDnsName                     | host.hostname                  |
| description                         | rule.description               |
| detectionSource                     | observer.name                  |
| evidence.fileName                   | file.name                      |
| evidence.filePath                   | file.path                      |
| evidence.processId                  | process.pid                    |
| evidence.processCommandLine         | process.command_line           |
| evidence.processCreationTime        | process.start                  |
| evidence.parentProcessId            | process.parent.pid             |
| evidence.parentProcessCreationTime  | process.parent.start           |
| evidence.sha1                       | file.hash.sha1                 |
| evidence.sha256                     | file.hash.sha256               |
| evidence.url                        | url.full                       |
| firstEventTime                      | event.start                    |
| id                                  | event.id                       |
| lastEventTime                       | event.end                      |
| machineId                           | cloud.instance.id              |
| relatedUser.userName                | host.user.name                 |
| relatedUser.domainName              | host.user.domain               |
| title                               | message                        |
| severity                            | event.severity                 |

{{event "defender_atp"}}

{{fields "defender_atp"}}
### DHCP

The `dhcp` dataset collects Microsoft DHCP logs.

{{fields "dhcp"}}
