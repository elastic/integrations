# Microsoft Defender for Endpoint integration

This integration is for [Microsoft Defender for Endpoint](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/microsoft-defender-endpoint?view=o365-worldwide) logs.

## Agentless Enabled Integration
Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

## Setting up

To allow the integration to ingest data from the Microsoft Defender API, you need to create a new application on your Azure domain. The procedure to create an application is found on the [Create a new Azure Application](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/exposed-apis-create-app-webapp) documentation page.

> Note: When giving the application the API permissions described in the documentation (`Windows Defender ATP Alert.Read.All`), it will only grant access to read alerts from ATP and nothing else in the Azure Domain

After the application has been created, it should contain 3 values that you need to apply to the module configuration.

These values are:

- Client ID
- Client Secret
- Tenant ID

## ECS mappings

| Defender for Endpoint fields       | ECS Fields            |
| ---------------------------------- | --------------------- |
| alertCreationTime                  | @timestamp            |
| aadTenantId                        | cloud.account.id      |
| category                           | threat.technique.name |
| computerDnsName                    | host.hostname         |
| description                        | rule.description      |
| detectionSource                    | observer.name         |
| evidence.fileName                  | file.name             |
| evidence.filePath                  | file.path             |
| evidence.processId                 | process.pid           |
| evidence.processCommandLine        | process.command_line  |
| evidence.processCreationTime       | process.start         |
| evidence.parentProcessId           | process.parent.pid    |
| evidence.parentProcessCreationTime | process.parent.start  |
| evidence.sha1                      | file.hash.sha1        |
| evidence.sha256                    | file.hash.sha256      |
| evidence.url                       | url.full              |
| firstEventTime                     | event.start           |
| id                                 | event.id              |
| lastEventTime                      | event.end             |
| machineId                          | cloud.instance.id     |
| title                              | message               |
| severity                           | event.severity        |

{{event "log"}}

{{fields "log"}}
