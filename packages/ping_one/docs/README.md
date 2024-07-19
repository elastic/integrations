# PingOne

## Overview

The [PingOne](https://www.pingidentity.com/en.html) integration allows you to monitor audit activity. PingOne is a cloud-based framework for secure identity access management.

Use the PingOne integration to collect and parse data from the REST APIs or HTTP Endpoint input. Then visualize that data in Kibana.

For example, you could use the data from this integration to know which action or activity is performed against a defined PingOne resource, and also track the actor or agent who initiated the action.

## Data streams

The PingOne integration collects logs for one type of event: Audit.

**Audit** reporting stores incoming audit messages in a cache and provides endpoints for requesting audit events for a specific time period.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

This module has been tested against `PingOne API version 1.0`.

## Setup

### To collect data from the PingOne REST API, follow the steps below:

Create a worker application in PingOne and copy the credentials, as follows:

1. Go to [pingidentity.com](https://pingidentity.com/), click
   [Sign On](https://www.pingidentity.com/bin/ping/signOnLink) and carry out
   any necessary authentication steps. You will arrive at the PingIdentity
   console.
2. From the navigation sidebar, expand the **Applications** section and
   select **Applications**.
3. Click **+** to begin creating a new application.
4. Enter an **Application Name**.
5. Select **Worker** as the application type.
6. Click **Save**.
7. On the application flyout, ensure that the toggle switch in the header is
   activated, in order to enable the application.
8. Select the **Roles** tab of the application flyout.
9. Click the **Grant Roles** button.
10. Under **Available responsibilities**, in the **Environment Admin**,
    section, select the environment(s) to grant access to, then click **Save**.
11. Select the **Configuration** tab of the application flyout.
12. Expand the **URLs** section and copy the **Token Endpoint**.
13. From the **General** section, copy the **Client ID**, **Client Secret** and
    **Environment ID**.

For more information, see the PingOne documentation about
[Adding an application](https://docs.pingidentity.com/r/en-us/pingone/p1_add_app_worker).

In Elastic, navigate to the PingOne integration, then:

1. Click **Add PingOne**.
2. Deactivate the **Collect PingOne logs via HTTP Endpoint** input.
3. Activate the **Collect PingOne logs via API** input.
4. Enter the PingOne API URL for your region in the **URL** field.
5. Enter the credentails copied from the PingOne console into the corresponding
   fields.
6. In the **Audit logs** data stream section, set an **Initial Interval** of
   no more than 2 years.
7. Choose an agent policy to add the integration to and click
   **Save and Continue**.

### To collect data from PingOne via HTTP Endpoint, follow below steps:

In Elastic, navigate to the PingOne integration, then:

1. Click **Add PingOne**.
2. Deactivate the **Collect PingOne logs via API** input.
3. Activate the **Collect PingOne logs via HTTP Endpoint** input.
4. Set the **Listen Address**, and (from the **Audit logs** data stream
   settings) set and copy the **Listen Port** and (under **Advanced options**)
   the **URL Path**.
5. In the input settings, enter any **SSL Configuration** and **Secret header**
   settings appropriate for the endpoint. Make a note of these details for use
   while configuring the PingOne webhook. **Note**: This endpoint will expose a
   port to the Internet, so it is advised to have proper network access
   configured. PingOne webhooks will only work with a `https://` destination
   URL.
6. Choose an agent policy to add the integration to and click
   **Save and Continue**.

Create a webhook in PingOne, as follows:

1. Go to [pingidentity.com](https://pingidentity.com/), click
   [Sign On](https://www.pingidentity.com/bin/ping/signOnLink) and carry out
   any necessary authentication steps. You will arrive at the PingIdentity
   console.
2. From the navigation sidebar, expand the **Integrations** section and
   select **Webhooks**.
3. Click the **+ Add Webhook** button to begin creating a new webhook.
4. In **Destination URL**, enter the full endpoint URL, including the port.
   Example format: `https://{EXTERNAL_AGENT_LISTEN_ADDRESS}:{AGENT_LISTEN_PORT}/{URL_PATH}`.
5. As **Format** select **Ping Activity Format (JSON)**.
6. In the **Filters** section, select all the **Event Types** you want to
   collect.
7. Enter any **TLS settings** and **Headers** required for the webhook to
   establish connections with the Agent's HTTP endpoint.
8. Click **Save**.
9. Ensure that the toggle switch for the webhook is activated, so that the
   webhook is enabled.

For more information, see the PingOne documentation about
[Creating or editing a webhook](https://docs.pingidentity.com/r/en-us/pingone/p1_create_webhook).

## Logs Reference

#### audit

This is the `audit` dataset.

An example event for `audit` looks as following:

```json
{
    "@timestamp": "2022-08-08T15:31:08.237Z",
    "agent": {
        "ephemeral_id": "e4d8fc8f-71fa-4e20-bd11-1c06f2e1d137",
        "id": "f25d13cd-18cc-4e73-822c-c4f849322623",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.10.1"
    },
    "client": {
        "user": {
            "id": "123abc123-12ab-1234-1abc-abc123abc12",
            "name": "PingOne Admin Console"
        }
    },
    "data_stream": {
        "dataset": "ping_one.audit",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "f25d13cd-18cc-4e73-822c-c4f849322623",
        "snapshot": false,
        "version": "8.10.1"
    },
    "event": {
        "action": "user.access_allowed",
        "agent_id_status": "verified",
        "category": [
            "iam",
            "configuration"
        ],
        "dataset": "ping_one.audit",
        "id": "123abc123-12ab-1234-1abc-abc123abc12",
        "ingested": "2023-09-22T17:21:19Z",
        "kind": "event",
        "original": "{\"_embedded\":{},\"action\":{\"type\":\"USER.ACCESS_ALLOWED\"},\"actors\":{\"client\":{\"environment\":{\"id\":\"123abc123-12ab-1234-1abc-abc123abc12\"},\"href\":\"https://api.pingone.asia/v1/environments/123abc123-12ab-1234-1abc-abc123abc12/applications/123abc123-12ab-1234-1abc-abc123abc12\",\"id\":\"123abc123-12ab-1234-1abc-abc123abc12\",\"name\":\"PingOne Admin Console\",\"type\":\"CLIENT\"},\"user\":{\"environment\":{\"id\":\"123abc123-12ab-1234-1abc-abc123abc12\"},\"href\":\"https://api.pingone.asia/v1/environments/123abc123-12ab-1234-1abc-abc123abc12/users/123abc123-12ab-1234-1abc-abc123abc12\",\"id\":\"123abc123-12ab-1234-1abc-abc123abc12\",\"name\":\"example@gmail.com\",\"population\":{\"id\":\"123abc123-12ab-1234-1abc-abc123abc12\"},\"type\":\"USER\"}},\"id\":\"123abc123-12ab-1234-1abc-abc123abc12\",\"recordedAt\":\"2022-08-08T15:31:08.237Z\",\"resources\":[{\"environment\":{\"id\":\"123abc123-12ab-1234-1abc-abc123abc12\"},\"href\":\"https://api.pingone.asia/v1/environments/123abc123-12ab-1234-1abc-abc123abc12/users/123abc123-12ab-1234-1abc-abc123abc12\",\"id\":\"123abc123-12ab-1234-1abc-abc123abc12\",\"name\":\"example@gmail.com\",\"population\":{\"id\":\"123abc123-12ab-1234-1abc-abc123abc12\"},\"type\":\"USER\"}],\"result\":{\"description\":\"Passed role access control\",\"status\":\"SUCCESS\"}}",
        "outcome": "success",
        "type": [
            "user",
            "info",
            "access"
        ]
    },
    "input": {
        "type": "http_endpoint"
    },
    "ping_one": {
        "audit": {
            "action": {
                "type": "USER.ACCESS_ALLOWED"
            },
            "actors": {
                "client": {
                    "environment": {
                        "id": "123abc123-12ab-1234-1abc-abc123abc12"
                    },
                    "href": "https://api.pingone.asia/v1/environments/123abc123-12ab-1234-1abc-abc123abc12/applications/123abc123-12ab-1234-1abc-abc123abc12",
                    "id": "123abc123-12ab-1234-1abc-abc123abc12",
                    "name": "PingOne Admin Console",
                    "type": "CLIENT"
                },
                "user": {
                    "environment": {
                        "id": "123abc123-12ab-1234-1abc-abc123abc12"
                    },
                    "href": "https://api.pingone.asia/v1/environments/123abc123-12ab-1234-1abc-abc123abc12/users/123abc123-12ab-1234-1abc-abc123abc12",
                    "id": "123abc123-12ab-1234-1abc-abc123abc12",
                    "name": "example@gmail.com",
                    "population": {
                        "id": "123abc123-12ab-1234-1abc-abc123abc12"
                    },
                    "type": "USER"
                }
            },
            "id": "123abc123-12ab-1234-1abc-abc123abc12",
            "recorded_at": "2022-08-08T15:31:08.237Z",
            "resources": [
                {
                    "environment": {
                        "id": "123abc123-12ab-1234-1abc-abc123abc12"
                    },
                    "href": "https://api.pingone.asia/v1/environments/123abc123-12ab-1234-1abc-abc123abc12/users/123abc123-12ab-1234-1abc-abc123abc12",
                    "id": "123abc123-12ab-1234-1abc-abc123abc12",
                    "name": "example@gmail.com",
                    "population": {
                        "id": "123abc123-12ab-1234-1abc-abc123abc12"
                    },
                    "type": "USER"
                }
            ],
            "result": {
                "description": "Passed role access control",
                "status": "SUCCESS"
            }
        }
    },
    "related": {
        "user": [
            "123abc123-12ab-1234-1abc-abc123abc12",
            "PingOne Admin Console",
            "example@gmail.com"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "ping_one-audit"
    ],
    "url": {
        "domain": "api.pingone.asia",
        "original": "https://api.pingone.asia/v1/environments/123abc123-12ab-1234-1abc-abc123abc12/users/123abc123-12ab-1234-1abc-abc123abc12",
        "path": "/v1/environments/123abc123-12ab-1234-1abc-abc123abc12/users/123abc123-12ab-1234-1abc-abc123abc12",
        "scheme": "https"
    },
    "user": {
        "id": "123abc123-12ab-1234-1abc-abc123abc12",
        "name": "example@gmail.com"
    }
}

```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| ping_one.audit.action.description | A string that specifies the description of the action performed. | text |
| ping_one.audit.action.type | A string that specifies the type of action performed (such as authentication or password reset). | keyword |
| ping_one.audit.actors.client.environment.id | A string that specifies the ID of the environment resource associated with the client. | keyword |
| ping_one.audit.actors.client.href | A string that specifies the URL for the specified client resource. | keyword |
| ping_one.audit.actors.client.id | A string that specifies the ID of the client. | keyword |
| ping_one.audit.actors.client.name | A string that specifies the name assigned to the client for PingOne sign on. | keyword |
| ping_one.audit.actors.client.type | A string that specifies the type of actor. Options are USER or CLIENT. | keyword |
| ping_one.audit.actors.user.environment.id | A string that specifies the ID of the environment resource associated with the user. | keyword |
| ping_one.audit.actors.user.href | A string that specifies the URL for the specified user resource. | keyword |
| ping_one.audit.actors.user.id | A string that specifies the ID of the user. | keyword |
| ping_one.audit.actors.user.name | A string that specifies the name assigned to the user for PingOne sign on. | keyword |
| ping_one.audit.actors.user.population.id | A string that specifies the ID of the population resource associated with the user. | keyword |
| ping_one.audit.actors.user.type | A string that specifies the type of actor. Options are USER or CLIENT. | keyword |
| ping_one.audit.correlation.id | A string that specifies a PingOne identifier for multiple messages in a transaction. | keyword |
| ping_one.audit.created_at | The date and time at which the event was created (ISO 8601 format). | date |
| ping_one.audit.embedded |  | flattened |
| ping_one.audit.id | A string that specifies the ID of the audit activity event. | keyword |
| ping_one.audit.recorded_at | The date and time at which the event was recorded (ISO 8601 format). | date |
| ping_one.audit.resources.environment.id | The UUID assigned as the key for the environment resource. | keyword |
| ping_one.audit.resources.href | A string that specifies the URL for the specified resource. | keyword |
| ping_one.audit.resources.id | A string that specifies the ID assigned as the key for the identifier resource (such as the environment, population or event message). | keyword |
| ping_one.audit.resources.name | A string that can be either the user name or the name of the environment, based on the resource type. | keyword |
| ping_one.audit.resources.population.id | The UUID assigned as the key for the population resource. | keyword |
| ping_one.audit.resources.type | A string that specifies the type of resource associated with the event. Options are USER, ORGANIZATION, or ENVIRONMENT. | keyword |
| ping_one.audit.result.description | A string that specifies the description of the result of the operation. | text |
| ping_one.audit.result.id | A string that specifies the ID for the result of the operation. | keyword |
| ping_one.audit.result.status | A string that specifies the result of the operation. Options are succeeded or failed. | keyword |
| ping_one.audit.tags | A string identifying the activity as the action of an administrator on other administrators. | keyword |

