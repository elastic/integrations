# Atlassian Confluence Integration

The Confluence integration collects [audit logs](https://confluence.atlassian.com/doc/auditing-in-confluence-829076528.html) from the audit log files or the [audit API](https://developer.atlassian.com/cloud/confluence/rest/api-group-audit/).

## Authentication Set-Up

When setting up the Atlassian Confluence Integration for Atlassian Cloud you will need to use the "Confluence User Identifier" and "Confluence API Token" fields in the integration configuration. These will allow connection to the [Atlassian Cloud REST API](https://developer.atlassian.com/cloud/confluence/basic-auth-for-rest-apis/).

If you are using a self-hosted instance, you will be able to use either the "Confluence User Identifier" and "Confluence API Token" fields above, *or* use the "Personal Access Token" field to [authenticate with a PAT](https://confluence.atlassian.com/enterprise/using-personal-access-tokens-1026032365.html). If the "Personal Access Token" field is set in the configuration, it will take precedence over the User ID/API Token fields. 

## Logs

### Audit

The Confluence integration collects audit logs from the audit log files or the audit API from self hosted Confluence Data Center. It has been tested with Confluence 7.14.2 but is expected to work with newer versions. As of version 1.2.0, this integration added experimental support for Atlassian Confluence Cloud.  JIRA Cloud only supports Basic Auth using username and a Personal Access Token.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| confluence.audit.affected_objects | Affected Objects | flattened |
| confluence.audit.changed_values | Changed Values | flattened |
| confluence.audit.external_collaborator | Whether the user is an external collaborator user | boolean |
| confluence.audit.extra_attributes | Extra Attributes | flattened |
| confluence.audit.method | Method | keyword |
| confluence.audit.type.action | Action | keyword |
| confluence.audit.type.actionI18nKey | actionI18nKey | keyword |
| confluence.audit.type.area | Area | keyword |
| confluence.audit.type.category | Category | keyword |
| confluence.audit.type.categoryI18nKey | categoryI18nKey | keyword |
| confluence.audit.type.level | Audit Level | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |


An example event for `audit` looks as following:

```json
{
    "@timestamp": "2021-11-16T09:25:56.666Z",
    "agent": {
        "ephemeral_id": "5e7e2606-c5b7-4cca-bcf6-5a9959484395",
        "id": "1f67a92c-38d3-40a8-9093-c4495a7411a3",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.10.2"
    },
    "confluence": {
        "audit": {
            "external_collaborator": false,
            "type": {
                "action": "User deactivated",
                "category": "Users and groups"
            }
        }
    },
    "data_stream": {
        "dataset": "atlassian_confluence.audit",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "1f67a92c-38d3-40a8-9093-c4495a7411a3",
        "snapshot": false,
        "version": "8.10.2"
    },
    "event": {
        "action": "User deactivated",
        "agent_id_status": "verified",
        "created": "2023-11-06T13:17:04.339Z",
        "dataset": "atlassian_confluence.audit",
        "ingested": "2023-11-06T13:17:05Z",
        "kind": "event",
        "original": "{\"affectedObject\":{\"name\":\"\",\"objectType\":\"\"},\"associatedObjects\":[],\"author\":{\"accountType\":\"\",\"displayName\":\"System\",\"externalCollaborator\":false,\"isExternalCollaborator\":false,\"operations\":null,\"publicName\":\"Unknown user\",\"type\":\"user\"},\"category\":\"Users and groups\",\"changedValues\":[],\"creationDate\":1637054756666,\"description\":\"\",\"remoteAddress\":\"81.2.69.143\",\"summary\":\"User deactivated\",\"superAdmin\":false,\"sysAdmin\":false}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "related": {
        "ip": [
            "81.2.69.143"
        ]
    },
    "source": {
        "address": "81.2.69.143",
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
        "ip": "81.2.69.143"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "confluence-audit"
    ],
    "user": {
        "full_name": "System"
    }
}

```