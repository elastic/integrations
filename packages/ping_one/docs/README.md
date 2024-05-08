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
| client.user.id | Unique identifier of the user. | keyword |
| client.user.name | Short name or login of the user. | keyword |
| client.user.name.text | Multi-field of `client.user.name`. | match_only_text |
| cloud.account.id | The cloud account or organization ID used to identify different entities in a multi-tenant environment. Examples: AWS account ID, Google Cloud ORG ID, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container ID. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host ID. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host IP addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
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
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| url.path | Path of the request, such as "/search". | wildcard |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |

