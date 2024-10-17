# authentik

authentik is an IdP (Identity Provider) and SSO (single sign on) that is built with security at the forefront of every piece of code, every feature, with an emphasis on flexibility and versatility.

The authentik integration collects event, group, and user logs using REST API.

## Data streams

The authentik integration collects three types of logs:

- **[Event](https://docs.goauthentik.io/developer-docs/api/reference/events-events-list)**                         
- **[Group](https://docs.goauthentik.io/developer-docs/api/reference/core-groups-list)**                           
- **[User](https://docs.goauthentik.io/developer-docs/api/reference/core-users-list)**                             

## Requirements

Elastic Agent must be installed. For more details and installation instructions, please refer to the [Elastic Agent Installation Guide](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

### Installing and managing an Elastic Agent:

There are several options for installing and managing Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

Please note, there are minimum requirements for running Elastic Agent. For more information, refer to the  [Elastic Agent Minimum Requirements](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html#elastic-agent-installation-minimum-requirements).

## Setup

### To collect data from the authentik API:

- Log in to your authentik instance to obtain your API Token. Open the **Admin interface** and navigate to **Directory > Tokens and App passwords**. There, create an API Token, then save and copy this token.

### Enabling the integration in Elastic:

1. In Kibana navigate to Management > Integrations.
2. In "Search for integrations" top bar, search for `Authentik`.
3. Select the "authentik" integration from the search results.
4. Select "Add authentik" to add the integration.
5. Add all the required integration configuration parameters, including API Token, Interval and Page Size to enable data collection.
6. Select "Save and continue" to save the integration.

## Logs reference

### Event

This is the `event` dataset.

#### Example

An example event for `event` looks as following:

```json
{
    "@timestamp": "2024-08-05T15:41:18.411Z",
    "agent": {
        "ephemeral_id": "edde0bc1-0e59-44d9-b1bb-abbd7475a28a",
        "id": "e55a97d9-f895-45b2-8fca-cb45755f60cd",
        "name": "elastic-agent-86888",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "authentik": {
        "event": {
            "action": "user_write",
            "app": "authentik.events.signals",
            "brand": {
                "app": "authentik_brands",
                "model_name": "brand",
                "name": "Default brand",
                "pk": "fcba828076b94dedb2d5a6b4c5556fa1"
            },
            "client_ip": "67.43.156.0",
            "context": {
                "created": false,
                "email": "root@localhost",
                "http_request": {
                    "method": "GET",
                    "path": "/api/v3/flows/executor/default-user-settings-flow/"
                },
                "name": "authentik Default Admin",
                "username": "akadmin"
            },
            "created": "2024-08-05T15:41:18.411Z",
            "expires": "2024-08-06T15:41:18.410Z",
            "pk": "d012e8af-cb94-4fa2-9e92-961e4eebc060",
            "user": {
                "email": "root@localhost",
                "pk": "1",
                "username": "akadmin"
            }
        }
    },
    "data_stream": {
        "dataset": "authentik.event",
        "namespace": "62208",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "e55a97d9-f895-45b2-8fca-cb45755f60cd",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "user-write",
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "created": "2024-08-05T15:41:18.411Z",
        "dataset": "authentik.event",
        "id": "d012e8af-cb94-4fa2-9e92-961e4eebc060",
        "ingested": "2024-08-21T12:04:25Z",
        "kind": "event",
        "original": "{\"action\":\"user_write\",\"app\":\"authentik.events.signals\",\"brand\":{\"app\":\"authentik_brands\",\"model_name\":\"brand\",\"name\":\"Default brand\",\"pk\":\"fcba828076b94dedb2d5a6b4c5556fa1\"},\"client_ip\":\"67.43.156.0\",\"context\":{\"attributes\":{\"settings\":{\"locale\":\"\"}},\"created\":false,\"email\":\"root@localhost\",\"http_request\":{\"args\":{\"query\":\"\"},\"method\":\"GET\",\"path\":\"/api/v3/flows/executor/default-user-settings-flow/\"},\"name\":\"authentik Default Admin\",\"username\":\"akadmin\"},\"created\":\"2024-08-05T15:41:18.411017Z\",\"expires\":\"2024-08-06T15:41:18.410276Z\",\"pk\":\"d012e8af-cb94-4fa2-9e92-961e4eebc060\",\"user\":{\"email\":\"root@localhost\",\"pk\":1,\"username\":\"akadmin\"}}",
        "type": [
            "change"
        ]
    },
    "http": {
        "request": {
            "method": "GET"
        }
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "authentik",
        "vendor": "authentik"
    },
    "related": {
        "ip": [
            "67.43.156.0"
        ],
        "user": [
            "root@localhost",
            "1",
            "akadmin"
        ]
    },
    "source": {
        "geo": {
            "continent_name": "Asia",
            "country_iso_code": "BT",
            "country_name": "Bhutan",
            "location": {
                "lat": 27.5,
                "lon": 90.5
            }
        },
        "ip": "67.43.156.0"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "authentik-event"
    ],
    "url": {
        "path": "/api/v3/flows/executor/default-user-settings-flow/"
    },
    "user": {
        "domain": "localhost",
        "email": "root@localhost",
        "id": "1",
        "name": "akadmin"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| authentik.event.action |  | keyword |
| authentik.event.app |  | keyword |
| authentik.event.brand.app |  | keyword |
| authentik.event.brand.model_name |  | keyword |
| authentik.event.brand.name |  | keyword |
| authentik.event.brand.pk |  | keyword |
| authentik.event.client_ip |  | ip |
| authentik.event.context.auth_method |  | keyword |
| authentik.event.context.authorized_application.app |  | keyword |
| authentik.event.context.authorized_application.model_name |  | keyword |
| authentik.event.context.authorized_application.name |  | keyword |
| authentik.event.context.authorized_application.pk |  | keyword |
| authentik.event.context.binding.app |  | keyword |
| authentik.event.context.binding.model_name |  | keyword |
| authentik.event.context.binding.name |  | keyword |
| authentik.event.context.binding.pk |  | keyword |
| authentik.event.context.created |  | boolean |
| authentik.event.context.diff |  | flattened |
| authentik.event.context.email |  | keyword |
| authentik.event.context.expression |  | keyword |
| authentik.event.context.flow |  | keyword |
| authentik.event.context.http_request.args.client_id |  | keyword |
| authentik.event.context.http_request.args.format_result |  | keyword |
| authentik.event.context.http_request.args.include_groups |  | keyword |
| authentik.event.context.http_request.args.next |  | keyword |
| authentik.event.context.http_request.args.page_size |  | keyword |
| authentik.event.context.http_request.args.query |  | keyword |
| authentik.event.context.http_request.args.redirect_uri |  | keyword |
| authentik.event.context.http_request.args.response_type |  | keyword |
| authentik.event.context.http_request.args.scope |  | keyword |
| authentik.event.context.http_request.args.state |  | keyword |
| authentik.event.context.http_request.method |  | keyword |
| authentik.event.context.http_request.path |  | keyword |
| authentik.event.context.http_request.user_agent |  | keyword |
| authentik.event.context.message |  | keyword |
| authentik.event.context.model.app |  | keyword |
| authentik.event.context.model.model_name |  | keyword |
| authentik.event.context.model.name |  | keyword |
| authentik.event.context.model.pk |  | keyword |
| authentik.event.context.name |  | keyword |
| authentik.event.context.new_version |  | keyword |
| authentik.event.context.password |  | keyword |
| authentik.event.context.policy_uuid |  | keyword |
| authentik.event.context.request.context.event.app |  | keyword |
| authentik.event.context.request.context.event.model_name |  | keyword |
| authentik.event.context.request.context.event.name |  | keyword |
| authentik.event.context.request.context.event.pk |  | keyword |
| authentik.event.context.request.obj.app |  | keyword |
| authentik.event.context.request.obj.model_name |  | keyword |
| authentik.event.context.request.obj.name |  | keyword |
| authentik.event.context.request.obj.pk |  | keyword |
| authentik.event.context.request.user.email |  | keyword |
| authentik.event.context.request.user.pk |  | keyword |
| authentik.event.context.request.user.username |  | keyword |
| authentik.event.context.result.passing |  | boolean |
| authentik.event.context.scopes |  | keyword |
| authentik.event.context.secret.app |  | keyword |
| authentik.event.context.secret.model_name |  | keyword |
| authentik.event.context.secret.name |  | keyword |
| authentik.event.context.secret.pk |  | keyword |
| authentik.event.context.stage.app |  | keyword |
| authentik.event.context.stage.model_name |  | keyword |
| authentik.event.context.stage.name |  | keyword |
| authentik.event.context.stage.pk |  | keyword |
| authentik.event.context.token.app |  | keyword |
| authentik.event.context.token.model_name |  | keyword |
| authentik.event.context.token.name |  | keyword |
| authentik.event.context.token.pk |  | keyword |
| authentik.event.context.username |  | keyword |
| authentik.event.created |  | date |
| authentik.event.expires |  | date |
| authentik.event.pk |  | keyword |
| authentik.event.user.email |  | keyword |
| authentik.event.user.is_anonymous |  | boolean |
| authentik.event.user.on_behalf_of.email |  | keyword |
| authentik.event.user.on_behalf_of.pk |  | keyword |
| authentik.event.user.on_behalf_of.username |  | keyword |
| authentik.event.user.pk |  | keyword |
| authentik.event.user.username |  | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |


### Group

This is the `group` dataset.

#### Example

An example event for `group` looks as following:

```json
{
    "@timestamp": "2024-08-21T12:06:54.045Z",
    "agent": {
        "ephemeral_id": "131ab180-e0d2-4054-8ae7-06cc8f2c1d56",
        "id": "48ae0a0f-a7dc-4d47-b458-48c79d5d118e",
        "name": "elastic-agent-38018",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "authentik": {
        "group": {
            "attributes": {
                "ldap_uniq": "S-1-5-21-1234567890-1234567890-1234567890-1234"
            },
            "is_superuser": false,
            "name": "AllUsers",
            "num_pk": 55003,
            "pk": "29613be9-2db3-4488-9338-60ec7762f60d",
            "users": [
                "12",
                "14",
                "15",
                "7",
                "9",
                "13",
                "8",
                "16",
                "11",
                "6",
                "4"
            ]
        }
    },
    "data_stream": {
        "dataset": "authentik.group",
        "namespace": "24575",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "48ae0a0f-a7dc-4d47-b458-48c79d5d118e",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "dataset": "authentik.group",
        "ingested": "2024-08-21T12:06:57Z",
        "kind": "asset",
        "original": "{\"attributes\":{\"ldap_uniq\":\"S-1-5-21-1234567890-1234567890-1234567890-1234\"},\"is_superuser\":false,\"name\":\"AllUsers\",\"num_pk\":55003,\"parent\":null,\"parent_name\":null,\"pk\":\"29613be9-2db3-4488-9338-60ec7762f60d\",\"roles\":[],\"roles_obj\":[],\"users\":[12,14,15,7,9,13,8,16,11,6,4],\"users_obj\":null}",
        "type": [
            "group",
            "info"
        ]
    },
    "group": {
        "id": "29613be9-2db3-4488-9338-60ec7762f60d",
        "name": "AllUsers"
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "authentik",
        "vendor": "authentik"
    },
    "related": {
        "user": [
            "12",
            "14",
            "15",
            "7",
            "9",
            "13",
            "8",
            "16",
            "11",
            "6",
            "4"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "authentik-group"
    ],
    "user": {
        "id": [
            "12",
            "14",
            "15",
            "7",
            "9",
            "13",
            "8",
            "16",
            "11",
            "6",
            "4"
        ]
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| authentik.group.attributes.ldap_uniq |  | keyword |
| authentik.group.attributes.notes |  | keyword |
| authentik.group.is_superuser | Users added to this group will be superusers. | boolean |
| authentik.group.name |  | keyword |
| authentik.group.num_pk |  | long |
| authentik.group.parent |  | keyword |
| authentik.group.parent_name |  | keyword |
| authentik.group.pk |  | keyword |
| authentik.group.roles |  | keyword |
| authentik.group.roles_obj.name |  | keyword |
| authentik.group.roles_obj.pk |  | keyword |
| authentik.group.users |  | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |


### User

This is the `user` dataset.

#### Example

An example event for `user` looks as following:

```json
{
    "@timestamp": "2024-08-21T12:09:24.375Z",
    "agent": {
        "ephemeral_id": "5a57d88f-c696-4acf-bf3f-9d9e2a1fed79",
        "id": "584b670d-b9d7-43d3-879e-0da908afc09a",
        "name": "elastic-agent-32864",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "authentik": {
        "user": {
            "avatar": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI2NHB4IiBoZWlnaHQ9IjY0cHgiIHZpZXdCb3g9IjAgMCA2NCA2NCIgdmVyc2lvbj0iMS4xIj48cmVjdCBmaWxsPSIjMzc3YjM3IiBjeD0iMzIiIGN5PSIzMiIgd2lkdGg9IjY0IiBoZWlnaHQ9IjY0IiByPSIzMiIvPjx0ZXh0IHg9IjUwJSIgeT0iNTAlIiBzdHlsZT0iY29sb3I6ICNmZmY7IGxpbmUtaGVpZ2h0OiAxOyBmb250LWZhbWlseTogJ1JlZEhhdFRleHQnLCdPdmVycGFzcycsb3ZlcnBhc3MsaGVsdmV0aWNhLGFyaWFsLHNhbnMtc2VyaWY7ICIgZmlsbD0iI2ZmZiIgYWxpZ25tZW50LWJhc2VsaW5lPSJtaWRkbGUiIGRvbWluYW50LWJhc2VsaW5lPSJtaWRkbGUiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMjgiIGZvbnQtd2VpZ2h0PSI0MDAiIGR5PSIuMWVtIj5BQTwvdGV4dD48L3N2Zz4=",
            "email": "root123@example.com",
            "groups": [
                "722c1c38-3f82-4b58-9f2f-bed1c7f16f84",
                "9eeda44b-9bd3-474e-84f9-39c661427772"
            ],
            "is_active": true,
            "is_superuser": true,
            "last_login": "2024-08-13T05:33:54.801Z",
            "name": "authentik Default Admin",
            "path": "users",
            "pk": "4",
            "type": "internal",
            "uid": "0abfaa5432568967abcdef895517d6d9b012345677899abcde78befef4f5cd4e99",
            "username": "akadmin",
            "uuid": "abcdef12-1234-5678-1725-abcdefabcdef"
        }
    },
    "data_stream": {
        "dataset": "authentik.user",
        "namespace": "15430",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "584b670d-b9d7-43d3-879e-0da908afc09a",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "dataset": "authentik.user",
        "ingested": "2024-08-21T12:09:27Z",
        "kind": "asset",
        "original": "{\"attributes\":{},\"avatar\":\"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI2NHB4IiBoZWlnaHQ9IjY0cHgiIHZpZXdCb3g9IjAgMCA2NCA2NCIgdmVyc2lvbj0iMS4xIj48cmVjdCBmaWxsPSIjMzc3YjM3IiBjeD0iMzIiIGN5PSIzMiIgd2lkdGg9IjY0IiBoZWlnaHQ9IjY0IiByPSIzMiIvPjx0ZXh0IHg9IjUwJSIgeT0iNTAlIiBzdHlsZT0iY29sb3I6ICNmZmY7IGxpbmUtaGVpZ2h0OiAxOyBmb250LWZhbWlseTogJ1JlZEhhdFRleHQnLCdPdmVycGFzcycsb3ZlcnBhc3MsaGVsdmV0aWNhLGFyaWFsLHNhbnMtc2VyaWY7ICIgZmlsbD0iI2ZmZiIgYWxpZ25tZW50LWJhc2VsaW5lPSJtaWRkbGUiIGRvbWluYW50LWJhc2VsaW5lPSJtaWRkbGUiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZvbnQtc2l6ZT0iMjgiIGZvbnQtd2VpZ2h0PSI0MDAiIGR5PSIuMWVtIj5BQTwvdGV4dD48L3N2Zz4=\",\"email\":\"root123@example.com\",\"groups\":[\"722c1c38-3f82-4b58-9f2f-bed1c7f16f84\",\"9eeda44b-9bd3-474e-84f9-39c661427772\"],\"groups_obj\":null,\"is_active\":true,\"is_superuser\":true,\"last_login\":\"2024-08-13T05:33:54.801600Z\",\"name\":\"authentik Default Admin\",\"path\":\"users\",\"pk\":4,\"type\":\"internal\",\"uid\":\"0abfaa5432568967abcdef895517d6d9b012345677899abcde78befef4f5cd4e99\",\"username\":\"akadmin\",\"uuid\":\"abcdef12-1234-5678-1725-abcdefabcdef\"}",
        "type": [
            "user",
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "authentik",
        "vendor": "authentik"
    },
    "related": {
        "user": [
            "4",
            "akadmin",
            "authentik Default Admin",
            "root123@example.com",
            "0abfaa5432568967abcdef895517d6d9b012345677899abcde78befef4f5cd4e99",
            "abcdef12-1234-5678-1725-abcdefabcdef"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "authentik-user"
    ],
    "user": {
        "domain": "example.com",
        "email": "root123@example.com",
        "full_name": "authentik Default Admin",
        "group": {
            "id": [
                "722c1c38-3f82-4b58-9f2f-bed1c7f16f84",
                "9eeda44b-9bd3-474e-84f9-39c661427772"
            ]
        },
        "id": "4",
        "name": "akadmin"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| authentik.user.attributes.ldap_uniq |  | keyword |
| authentik.user.attributes.sn |  | keyword |
| authentik.user.attributes.upn |  | keyword |
| authentik.user.avatar |  | keyword |
| authentik.user.email |  | keyword |
| authentik.user.groups |  | keyword |
| authentik.user.is_active |  | boolean |
| authentik.user.is_superuser |  | boolean |
| authentik.user.last_login |  | date |
| authentik.user.name |  | keyword |
| authentik.user.path |  | keyword |
| authentik.user.pk |  | keyword |
| authentik.user.type |  | keyword |
| authentik.user.uid |  | keyword |
| authentik.user.username |  | keyword |
| authentik.user.uuid |  | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |

