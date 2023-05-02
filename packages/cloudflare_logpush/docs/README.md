# Cloudflare Logpush

## Overview

The [Cloudflare Logpush](https://www.cloudflare.com/) integration allows you to monitor Audit, DNS, Firewall Event, HTTP Request, NEL Report, Network Analytics and Spectrum Event Logs. Cloudflare is a content delivery network and DDoS mitigation company. Cloudflare provides a network designed to make everything you connect to the Internet secure, private, fast, and reliable; secure your websites, APIs, and Internet applications; protect corporate networks, employees, and devices; and write and deploy code that runs on the network edge.

The Cloudflare Logpush integration can be used in three different modes to collect data:
- HTTP Endpoint mode - Cloudflare pushes logs directly to an HTTP endpoint hosted by your Elastic Agent.
- AWS S3 polling mode - Cloudflare writes data to S3 and Elastic Agent polls the S3 bucket by listing its contents and reading new files.
- AWS S3 SQS mode - Cloudflare writes data to S3, S3 pushes a new object notification to SQS, Elastic Agent receives the notification from SQS, and then reads the S3 object. Multiple Agents can be used in this mode.

For example, you could use the data from this integration to know which websites have the highest traffic, which areas have the highest network traffic, or observe mitigation statistics.

## Data streams

The Cloudflare Logpush integration collects logs for seven types of events: Audit, DNS, Firewall Event, HTTP Request, NEL Report, Network Analytics, and Spectrum Event.

**Audit**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/account/audit_logs/).

**DNS**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/zone/dns_logs/).

**Firewall Event**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/zone/firewall_events/).

**HTTP Request**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/zone/http_requests/).

**NEL Report**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/zone/nel_reports/).

**Network Analytics**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/account/network_analytics_logs/).

**Spectrum Event**: See Example Schema [here](https://developers.cloudflare.com/logs/reference/log-fields/zone/spectrum_events/).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

This module has been tested against **Cloudflare version v4**.

**Note**: It is recommended to use AWS SQS for Cloudflare Logpush.

## Setup

### To collect data from AWS S3 Bucket, follow the below steps:
- Configure the [Data Forwarder](https://developers.cloudflare.com/logs/get-started/enable-destinations/aws-s3/) to ingest data into an AWS S3 bucket.
- The default value of the "Bucket List Prefix" is listed below. However, the user can set the parameter "Bucket List Prefix" according to the requirement.

  | Data Stream Name  | Bucket List Prefix     |
  | ----------------- | ---------------------- |
  | Audit Logs        | audit_logs             |
  | DNS               | dns                    |
  | Firewall Event    | firewall_event         |
  | HTTP Request      | http_request           |
  | NEL Report        | nel_report             |
  | Network Analytics | network_analytics_logs |
  | Spectrum Event    | spectrum_event         |

### To collect data from AWS SQS, follow the below steps:
1. If data forwarding to an AWS S3 Bucket hasn't been configured, then first setup an AWS S3 Bucket as mentioned in the above documentation.
2. To setup an SQS queue, follow "Step 1: Create an Amazon SQS queue" mentioned in the [Documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ways-to-add-notification-config-to-bucket.html).
  - While creating an SQS Queue, please provide the same bucket ARN that has been generated after creating an AWS S3 Bucket.
3. Setup event notification for an S3 bucket. Follow this [Link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-event-notifications.html).
  - The user has to perform Step 3 for all the data-streams individually, and each time prefix parameter should be set the same as the S3 Bucket List Prefix as created earlier. (for example, `audit_logs/` for audit data stream.)
  - For all the event notifications that have been created, select the event type as s3:ObjectCreated:*, select the destination type SQS Queue, and select the queue that has been created in Step 2.

**Note**:
  - Credentials for the above AWS S3 and SQS input types should be configured using the [link](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html#aws-credentials-config).
  - Data collection via AWS S3 Bucket and AWS SQS are mutually exclusive in this case.
  - You can configure a global SQS queue for all data streams or a local SQS que for each data stream. Configuring
    data stream specific SQS queues will enable better performance and scalability. Data stream specific SQS queues
    will always override any global queue definitions for that specific data stream.

### To collect data from GCS Buckets, follow the below steps:
- Configure the [Data Forwarder](https://developers.cloudflare.com/logs/get-started/enable-destinations/google-cloud-storage/) to ingest data into a GCS bucket.
- Configure the GCS bucket names and credentials along with the required configs under the "Collect Cloudflare Logpush logs via Google Cloud Storage" section. 
- Make sure the service account and authentication being used, has proper levels of access to the GCS bucket [Manage Service Account Keys](https://cloud.google.com/iam/docs/creating-managing-service-account-keys/)

**Note**:
- The GCS input currently does not support fetching of buckets using bucket prefixes, so the bucket names have to be configured manually for each data stream.
- The GCS input currently only accepts a service account JSON key or a service account JSON file for authentication.
- The GCS input currently only supports json data.

### To collect data from the Cloudflare HTTP Endpoint, follow the below steps:
- Reference link to [Enable HTTP destination](https://developers.cloudflare.com/logs/get-started/enable-destinations/http/) for Cloudflare Logpush.
- Add same custom header along with its value on both the side for additional security.
- For example, while creating a job along with a header and value for a particular dataset:
```
curl --location --request POST 'https://api.cloudflare.com/client/v4/zones/<ZONE ID>/logpush/jobs' \
--header 'X-Auth-Key: <X-AUTH-KEY>' \
--header 'X-Auth-Email: <X-AUTH-EMAIL>' \
--header 'Authorization: <BASIC AUTHORIZATION>' \
--header 'Content-Type: application/json' \
--data-raw '{
    "name":"<public domain>",
    "destination_conf": "https://<public domain>:<public port>?header_<secret_header>=<secret_value>",
    "dataset": "http_requests",
    "logpull_options": "fields=RayID,EdgeStartTimestamp&timestamps=rfc3339"
}'
```

### Enabling the integration in Elastic
1. In Kibana, go to Management > Integrations
2. In the integrations search bar type **Cloudflare Logpush**.
3. Click the **Cloudflare Logpush** integration from the search results.
4. Click the **Add Cloudflare Logpush** button to add Cloudflare Logpush integration.
5. Enable the Integration with the HTTP Endpoint, AWS S3 input or GCS input.
6. Under the AWS S3 input, there are two types of inputs: using AWS S3 Bucket or using SQS.
7. Configure Cloudflare to send logs to the Elastic Agent.

## Logs reference

### audit

This is the `audit` dataset.
Default port for HTTP Endpoint: _9560_

#### Example

An example event for `audit` looks as following:

```json
{
    "@timestamp": "2021-11-30T20:19:48.000Z",
    "agent": {
        "ephemeral_id": "3605deda-1943-40cf-9ba2-a5d591fead25",
        "hostname": "docker-fleet-agent",
        "id": "8539930e-8f7a-48ac-af3e-7f098b7d6ea2",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.17.0"
    },
    "cloudflare_logpush": {
        "audit": {
            "action": {
                "result": "success",
                "type": "token_create"
            },
            "actor": {
                "email": "user@example.com",
                "id": "enl3j9du8rnx2swwd9l32qots7l54t9s",
                "ip": "81.2.69.142",
                "type": "user"
            },
            "id": "73fd39ed-5aab-4a2a-b93c-c9a4abf0c425",
            "interface": "UI",
            "metadata": {
                "token_name": "test",
                "token_tag": "b7261c49a793a82678d12285f0bc1401"
            },
            "new_value": {
                "key1": "value1",
                "key2": "value2"
            },
            "old_value": {
                "key3": "value4",
                "key4": "value4"
            },
            "owner": {
                "id": "enl3j9du8rnx2swwd9l32qots7l54t9s"
            },
            "resource": {
                "id": "enl3j9du8rnx2swwd9l32qots7l54t9s",
                "type": "account"
            },
            "timestamp": "2021-11-30T20:19:48.000Z"
        }
    },
    "data_stream": {
        "dataset": "cloudflare_logpush.audit",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.7.0"
    },
    "elastic_agent": {
        "id": "8539930e-8f7a-48ac-af3e-7f098b7d6ea2",
        "snapshot": false,
        "version": "7.17.0"
    },
    "event": {
        "action": "token_create",
        "agent_id_status": "verified",
        "category": [
            "authentication"
        ],
        "dataset": "cloudflare_logpush.audit",
        "id": "73fd39ed-5aab-4a2a-b93c-c9a4abf0c425",
        "ingested": "2022-09-01T10:05:51Z",
        "kind": "event",
        "original": "{\"ActionResult\":true,\"ActionType\":\"token_create\",\"ActorEmail\":\"user@example.com\",\"ActorID\":\"enl3j9du8rnx2swwd9l32qots7l54t9s\",\"ActorIP\":\"81.2.69.142\",\"ActorType\":\"user\",\"ID\":\"73fd39ed-5aab-4a2a-b93c-c9a4abf0c425\",\"Interface\":\"UI\",\"Metadata\":{\"token_name\":\"test\",\"token_tag\":\"b7261c49a793a82678d12285f0bc1401\"},\"NewValue\":{\"key1\":\"value1\",\"key2\":\"value2\"},\"OldValue\":{\"key3\":\"value4\",\"key4\":\"value4\"},\"OwnerID\":\"enl3j9du8rnx2swwd9l32qots7l54t9s\",\"ResourceID\":\"enl3j9du8rnx2swwd9l32qots7l54t9s\",\"ResourceType\":\"account\",\"When\":\"2021-11-30T20:19:48Z\"}",
        "outcome": "success",
        "provider": "UI",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "http_endpoint"
    },
    "related": {
        "ip": [
            "81.2.69.142"
        ],
        "user": [
            "enl3j9du8rnx2swwd9l32qots7l54t9s"
        ]
    },
    "source": {
        "ip": "81.2.69.142"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "cloudflare_logpush_audit"
    ],
    "user": {
        "email": "user@example.com",
        "id": "enl3j9du8rnx2swwd9l32qots7l54t9s"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization ID used to identify different entities in a multi-tenant environment. Examples: AWS account ID, Google Cloud ORG ID, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| cloudflare_logpush.audit.action.result | Whether the action was successful. | keyword |
| cloudflare_logpush.audit.action.type | Type of action taken. | keyword |
| cloudflare_logpush.audit.actor.email | Email of the actor. | keyword |
| cloudflare_logpush.audit.actor.id | Unique identifier of the actor in Cloudflare system. | keyword |
| cloudflare_logpush.audit.actor.ip | Physical network address of the actor. | ip |
| cloudflare_logpush.audit.actor.type | Type of user that started the audit trail. | keyword |
| cloudflare_logpush.audit.id | Unique identifier of an audit log. | keyword |
| cloudflare_logpush.audit.interface | Entry point or interface of the audit log. | text |
| cloudflare_logpush.audit.metadata | Additional audit log-specific information, Metadata is organized in key:value pairs, Key and Value formats can vary by ResourceType. | flattened |
| cloudflare_logpush.audit.new_value | Contains the new value for the audited item. | flattened |
| cloudflare_logpush.audit.old_value | Contains the old value for the audited item. | flattened |
| cloudflare_logpush.audit.owner.id | The identifier of the user that was acting or was acted on behalf of. | keyword |
| cloudflare_logpush.audit.resource.id | Unique identifier of the resource within Cloudflare system. | keyword |
| cloudflare_logpush.audit.resource.type | The type of resource that was changed. | keyword |
| cloudflare_logpush.audit.timestamp | When the change happened. | date |
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
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
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
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
| user.email | User email address. | keyword |
| user.id | Unique identifier of the user. | keyword |


### dns

This is the `dns` dataset.
Default port for HTTP Endpoint: _9561_

#### Example

An example event for `dns` looks as following:

```json
{
    "@timestamp": "2022-05-26T09:23:54.000Z",
    "agent": {
        "ephemeral_id": "5a08ea07-7e13-4f10-8bfa-5707606de846",
        "hostname": "docker-fleet-agent",
        "id": "8539930e-8f7a-48ac-af3e-7f098b7d6ea2",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.17.0"
    },
    "cloudflare_logpush": {
        "dns": {
            "colo": {
                "code": "MRS"
            },
            "edns": {
                "subnet": "1.128.0.0",
                "subnet_length": 0
            },
            "query": {
                "name": "example.com",
                "type": 65535
            },
            "response": {
                "cached": false,
                "code": 0
            },
            "source": {
                "ip": "175.16.199.0"
            },
            "timestamp": "2022-05-26T09:23:54.000Z"
        }
    },
    "data_stream": {
        "dataset": "cloudflare_logpush.dns",
        "namespace": "ep",
        "type": "logs"
    },
    "dns": {
        "question": {
            "name": "example.com"
        }
    },
    "ecs": {
        "version": "8.7.0"
    },
    "elastic_agent": {
        "id": "8539930e-8f7a-48ac-af3e-7f098b7d6ea2",
        "snapshot": false,
        "version": "7.17.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "cloudflare_logpush.dns",
        "ingested": "2022-09-01T10:06:44Z",
        "kind": "event",
        "original": "{\"ColoCode\":\"MRS\",\"EDNSSubnet\":\"1.128.0.0\",\"EDNSSubnetLength\":0,\"QueryName\":\"example.com\",\"QueryType\":65535,\"ResponseCached\":false,\"ResponseCode\":0,\"SourceIP\":\"175.16.199.0\",\"Timestamp\":\"2022-05-26T09:23:54Z\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "http_endpoint"
    },
    "related": {
        "ip": [
            "175.16.199.0",
            "1.128.0.0"
        ]
    },
    "source": {
        "ip": "175.16.199.0"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "cloudflare_logpush_dns"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization ID used to identify different entities in a multi-tenant environment. Examples: AWS account ID, Google Cloud ORG ID, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| cloudflare_logpush.dns.colo.code | IATA airport code of data center that received the request. | keyword |
| cloudflare_logpush.dns.edns.subnet | EDNS Client Subnet (IPv4 or IPv6). | ip |
| cloudflare_logpush.dns.edns.subnet_length | EDNS Client Subnet length. | long |
| cloudflare_logpush.dns.query.name | Name of the query that was sent. | keyword |
| cloudflare_logpush.dns.query.type | Integer value of query type. | long |
| cloudflare_logpush.dns.response.cached | Whether the response was cached or not. | boolean |
| cloudflare_logpush.dns.response.code | Integer value of response code. | long |
| cloudflare_logpush.dns.source.ip | IP address of the client (IPv4 or IPv6). | ip |
| cloudflare_logpush.dns.timestamp | Timestamp at which the query occurred. | date |
| container.id | Unique container ID. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| dns.question.name | The name being queried. If the name field contains non-printable characters (below 32 or above 126), those characters should be represented as escaped base 10 integers (\DDD). Back slashes and quotes should be escaped. Tabs, carriage returns, and line feeds should be converted to \t, \r, and \n respectively. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
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
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |


### firewall_event

This is the `firewall_event` dataset.
Default port for HTTP Endpoint: _9562_

#### Example

An example event for `firewall_event` looks as following:

```json
{
    "@timestamp": "2022-05-31T05:23:43.000Z",
    "agent": {
        "ephemeral_id": "af546795-5544-478a-b060-75816c879e33",
        "id": "8eb33de0-90ff-4a4c-82ff-082ffbaa315f",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.6.2"
    },
    "cloudflare_logpush": {
        "firewall_event": {
            "action": "block",
            "client": {
                "asn": {
                    "description": "CLOUDFLARENET",
                    "value": 15169
                },
                "country": "us",
                "ip": "175.16.199.0",
                "ip_class": "searchEngine",
                "referer": {
                    "host": "abc.example.com",
                    "path": "/abc/checkout",
                    "query": "?sourcerer=(default%3A(id%3A!n%2CselectedPatterns%3A!(eqldemo%2C%27logs-endpoint.*-eqldemo%27%2C%27logs-system.*-eqldemo%27%2C%27logs-windows.*-eqldemo%27%2Cmetricseqldemo)))\u0026timerange=(global%3A(linkTo%3A!()%2Ctimerange%3A(from%3A%272022-04-05T00%3A00%3A01.199Z%27%2CfromStr%3Anow-24h%2Ckind%3Arelative%2Cto%3A%272022-04-06T00%3A00%3A01.200Z%27%2CtoStr%3Anow))%2Ctimeline%3A(linkTo%3A!()%2Ctimerange%3A(from%3A%272022-04-05T00%3A00%3A01.201Z%27%2CfromStr%3Anow-24h%2Ckind%3Arelative%2Cto%3A%272022-04-06T00%3A00%3A01.202Z%27%2CtoStr%3Anow)))",
                    "scheme": "referer URL scheme"
                },
                "request": {
                    "host": "xyz.example.com",
                    "method": "GET",
                    "path": "/abc/checkout",
                    "protocol": "HTTP/1.1",
                    "query": "?sourcerer=(default%3A(id%3A!n%2CselectedPatterns%3A!(eqldemo%2C%27logs-endpoint.*-eqldemo%27%2C%27logs-system.*-eqldemo%27%2C%27logs-windows.*-eqldemo%27%2Cmetricseqldemo)))\u0026timerange=(global%3A(linkTo%3A!()%2Ctimerange%3A(from%3A%272022-04-05T00%3A00%3A01.199Z%27%2CfromStr%3Anow-24h%2Ckind%3Arelative%2Cto%3A%272022-04-06T00%3A00%3A01.200Z%27%2CtoStr%3Anow))%2Ctimeline%3A(linkTo%3A!()%2Ctimerange%3A(from%3A%272022-04-05T00%3A00%3A01.201Z%27%2CfromStr%3Anow-24h%2Ckind%3Arelative%2Cto%3A%272022-04-06T00%3A00%3A01.202Z%27%2CtoStr%3Anow)))",
                    "scheme": "https",
                    "user": {
                        "agent": "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
                    }
                }
            },
            "edge": {
                "colo": {
                    "code": "IAD"
                },
                "response": {
                    "status": 403
                }
            },
            "kind": "firewall",
            "match_index": 1,
            "meta_data": {
                "filter": "1ced07e066a34abf8b14f2a99593bc8d",
                "type": "customer"
            },
            "origin": {
                "ray": {
                    "id": "00"
                },
                "response": {
                    "status": 0
                }
            },
            "ray": {
                "id": "713d477539b55c29"
            },
            "rule": {
                "id": "7dc666e026974dab84884c73b3e2afe1"
            },
            "source": "firewallrules",
            "timestamp": "2022-05-31T05:23:43.000Z"
        }
    },
    "data_stream": {
        "dataset": "cloudflare_logpush.firewall_event",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.7.0"
    },
    "elastic_agent": {
        "id": "8eb33de0-90ff-4a4c-82ff-082ffbaa315f",
        "snapshot": false,
        "version": "8.6.2"
    },
    "event": {
        "action": "block",
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "cloudflare_logpush.firewall_event",
        "ingested": "2023-04-18T02:04:00Z",
        "kind": "event",
        "original": "{\"Action\":\"block\",\"ClientASN\":15169,\"ClientASNDescription\":\"CLOUDFLARENET\",\"ClientCountry\":\"us\",\"ClientIP\":\"175.16.199.0\",\"ClientIPClass\":\"searchEngine\",\"ClientRefererHost\":\"abc.example.com\",\"ClientRefererPath\":\"/abc/checkout\",\"ClientRefererQuery\":\"?sourcerer=(default%3A(id%3A!n%2CselectedPatterns%3A!(eqldemo%2C%27logs-endpoint.*-eqldemo%27%2C%27logs-system.*-eqldemo%27%2C%27logs-windows.*-eqldemo%27%2Cmetricseqldemo)))\\u0026timerange=(global%3A(linkTo%3A!()%2Ctimerange%3A(from%3A%272022-04-05T00%3A00%3A01.199Z%27%2CfromStr%3Anow-24h%2Ckind%3Arelative%2Cto%3A%272022-04-06T00%3A00%3A01.200Z%27%2CtoStr%3Anow))%2Ctimeline%3A(linkTo%3A!()%2Ctimerange%3A(from%3A%272022-04-05T00%3A00%3A01.201Z%27%2CfromStr%3Anow-24h%2Ckind%3Arelative%2Cto%3A%272022-04-06T00%3A00%3A01.202Z%27%2CtoStr%3Anow)))\",\"ClientRefererScheme\":\"referer URL scheme\",\"ClientRequestHost\":\"xyz.example.com\",\"ClientRequestMethod\":\"GET\",\"ClientRequestPath\":\"/abc/checkout\",\"ClientRequestProtocol\":\"HTTP/1.1\",\"ClientRequestQuery\":\"?sourcerer=(default%3A(id%3A!n%2CselectedPatterns%3A!(eqldemo%2C%27logs-endpoint.*-eqldemo%27%2C%27logs-system.*-eqldemo%27%2C%27logs-windows.*-eqldemo%27%2Cmetricseqldemo)))\\u0026timerange=(global%3A(linkTo%3A!()%2Ctimerange%3A(from%3A%272022-04-05T00%3A00%3A01.199Z%27%2CfromStr%3Anow-24h%2Ckind%3Arelative%2Cto%3A%272022-04-06T00%3A00%3A01.200Z%27%2CtoStr%3Anow))%2Ctimeline%3A(linkTo%3A!()%2Ctimerange%3A(from%3A%272022-04-05T00%3A00%3A01.201Z%27%2CfromStr%3Anow-24h%2Ckind%3Arelative%2Cto%3A%272022-04-06T00%3A00%3A01.202Z%27%2CtoStr%3Anow)))\",\"ClientRequestScheme\":\"https\",\"ClientRequestUserAgent\":\"Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)\",\"Datetime\":\"2022-05-31T05:23:43Z\",\"EdgeColoCode\":\"IAD\",\"EdgeResponseStatus\":403,\"Kind\":\"firewall\",\"MatchIndex\":1,\"Metadata\":{\"filter\":\"1ced07e066a34abf8b14f2a99593bc8d\",\"type\":\"customer\"},\"OriginResponseStatus\":0,\"OriginatorRayID\":\"00\",\"RayID\":\"713d477539b55c29\",\"RuleID\":\"7dc666e026974dab84884c73b3e2afe1\",\"Source\":\"firewallrules\"}",
        "type": [
            "info"
        ]
    },
    "http": {
        "request": {
            "method": "GET"
        },
        "response": {
            "status_code": 403
        },
        "version": "1.1"
    },
    "input": {
        "type": "http_endpoint"
    },
    "network": {
        "protocol": "http"
    },
    "related": {
        "hosts": [
            "abc.example.com",
            "xyz.example.com"
        ],
        "ip": [
            "175.16.199.0"
        ]
    },
    "rule": {
        "id": "7dc666e026974dab84884c73b3e2afe1"
    },
    "source": {
        "as": {
            "number": 15169
        },
        "geo": {
            "country_iso_code": "us"
        },
        "ip": "175.16.199.0"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "cloudflare_logpush_firewall_event"
    ],
    "url": {
        "domain": "xyz.example.com",
        "path": "/abc/checkout",
        "query": "?sourcerer=(default%3A(id%3A!n%2CselectedPatterns%3A!(eqldemo%2C%27logs-endpoint.*-eqldemo%27%2C%27logs-system.*-eqldemo%27%2C%27logs-windows.*-eqldemo%27%2Cmetricseqldemo)))\u0026timerange=(global%3A(linkTo%3A!()%2Ctimerange%3A(from%3A%272022-04-05T00%3A00%3A01.199Z%27%2CfromStr%3Anow-24h%2Ckind%3Arelative%2Cto%3A%272022-04-06T00%3A00%3A01.200Z%27%2CtoStr%3Anow))%2Ctimeline%3A(linkTo%3A!()%2Ctimerange%3A(from%3A%272022-04-05T00%3A00%3A01.201Z%27%2CfromStr%3Anow-24h%2Ckind%3Arelative%2Cto%3A%272022-04-06T00%3A00%3A01.202Z%27%2CtoStr%3Anow)))",
        "scheme": "https"
    },
    "user_agent": {
        "device": {
            "name": "Spider"
        },
        "name": "Googlebot",
        "original": "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "os": {
            "full": "Android 6.0.1",
            "name": "Android",
            "version": "6.0.1"
        },
        "version": "2.1"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization ID used to identify different entities in a multi-tenant environment. Examples: AWS account ID, Google Cloud ORG ID, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| cloudflare_logpush.firewall_event.action | The code of the first-class action the Cloudflare Firewall took on this request. | keyword |
| cloudflare_logpush.firewall_event.client.asn.description | The ASN of the visitor as string. | keyword |
| cloudflare_logpush.firewall_event.client.asn.value | The ASN number of the visitor. | long |
| cloudflare_logpush.firewall_event.client.country | Country from which request originated. | keyword |
| cloudflare_logpush.firewall_event.client.ip | The visitor IP address (IPv4 or IPv6). | ip |
| cloudflare_logpush.firewall_event.client.ip_class | The classification of the visitor IP address, possible values are:- 'unknown', 'badHost', 'searchEngine', 'allowlist', 'monitoringService', 'noRecord', 'scan' and 'tor'. | keyword |
| cloudflare_logpush.firewall_event.client.referer.host | The referer host. | keyword |
| cloudflare_logpush.firewall_event.client.referer.path | The referer path requested by visitor. | text |
| cloudflare_logpush.firewall_event.client.referer.query | The referer query-string was requested by the visitor. | keyword |
| cloudflare_logpush.firewall_event.client.referer.scheme | The referer URL scheme requested by the visitor. | text |
| cloudflare_logpush.firewall_event.client.request.host | The HTTP hostname requested by the visitor. | keyword |
| cloudflare_logpush.firewall_event.client.request.method | The HTTP method used by the visitor. | keyword |
| cloudflare_logpush.firewall_event.client.request.path | The path requested by visitor. | text |
| cloudflare_logpush.firewall_event.client.request.protocol | The version of HTTP protocol requested by the visitor. | keyword |
| cloudflare_logpush.firewall_event.client.request.query | The query-string was requested by the visitor. | keyword |
| cloudflare_logpush.firewall_event.client.request.scheme | The URL scheme requested by the visitor. | text |
| cloudflare_logpush.firewall_event.client.request.user.agent | Visitor's user-agent string. | text |
| cloudflare_logpush.firewall_event.edge.colo.code | The airport code of the Cloudflare datacenter that served this request. | keyword |
| cloudflare_logpush.firewall_event.edge.response.status | HTTP response status code returned to browser. | long |
| cloudflare_logpush.firewall_event.kind | The kind of event, currently only possible values are. | keyword |
| cloudflare_logpush.firewall_event.match_index | Rules match index in the chain. | long |
| cloudflare_logpush.firewall_event.meta_data | Additional product-specific information. | flattened |
| cloudflare_logpush.firewall_event.origin.ray.id | HTTP origin response status code returned to browser. | keyword |
| cloudflare_logpush.firewall_event.origin.response.status | The RayID of the request that issued the challenge/jschallenge. | long |
| cloudflare_logpush.firewall_event.ray.id | The RayID of the request. | keyword |
| cloudflare_logpush.firewall_event.rule.id | The Cloudflare security product-specific RuleID triggered by this request. | keyword |
| cloudflare_logpush.firewall_event.source | The Cloudflare security product triggered by this request. | keyword |
| cloudflare_logpush.firewall_event.timestamp | The date and time the event occurred at the edge. | date |
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
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
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
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.response.status_code | HTTP response status code. | long |
| http.version | HTTP version. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| rule.id | A rule ID that is unique within the scope of an agent, observer, or other entity using the rule for detection of this event. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.path | Path of the request, such as "/search". | wildcard |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.full.text | Multi-field of `user_agent.os.full`. | match_only_text |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.name.text | Multi-field of `user_agent.os.name`. | match_only_text |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |


### http_request

This is the `http_request` dataset.
Default port for HTTP Endpoint: _9563_

#### Example

An example event for `http_request` looks as following:

```json
{
    "@timestamp": "2022-05-25T13:25:26Z",
    "agent": {
        "ephemeral_id": "03f89c1e-b5e7-49b2-b26f-d53e4171772e",
        "id": "8eb33de0-90ff-4a4c-82ff-082ffbaa315f",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.6.2"
    },
    "cloudflare_logpush": {
        "http_request": {
            "bot": {
                "score": {
                    "src": "Verified Bot",
                    "value": 20
                },
                "tag": "bing"
            },
            "cache": {
                "response": {
                    "bytes": 983828,
                    "status": 200
                },
                "status": "dynamic",
                "tiered_fill": false
            },
            "client": {
                "asn": 43766,
                "country": "sa",
                "device": {
                    "type": "desktop"
                },
                "ip": "175.16.199.0",
                "ip_class": "noRecord",
                "mtls": {
                    "auth": {
                        "fingerprint": "Fingerprint",
                        "status": "unknown"
                    }
                },
                "request": {
                    "bytes": 5800,
                    "host": "xyz.example.com",
                    "method": "POST",
                    "path": "/xyz/checkout",
                    "protocol": "HTTP/1.1",
                    "referer": "https://example.com/s/example/default?sourcerer=(default:(id:!n,selectedPatterns:!(example,%27logs-endpoint.*-example%27,%27logs-system.*-example%27,%27logs-windows.*-example%27)))\u0026timerange=(global:(linkTo:!(),timerange:(from:%272022-05-16T06:26:36.340Z%27,fromStr:now-24h,kind:relative,to:%272022-05-17T06:26:36.340Z%27,toStr:now)),timeline:(linkTo:!(),timerange:(from:%272022-04-17T22:00:00.000Z%27,kind:absolute,to:%272022-04-18T21:59:59.999Z%27)))\u0026timeline=(activeTab:notes,graphEventId:%27%27,id:%279844bdd4-4dd6-5b22-ab40-3cd46fce8d6b%27,isOpen:!t)",
                    "scheme": "https",
                    "source": "edgeWorkerFetch",
                    "uri": "/s/example/api/telemetry/v2/clusters/_stats",
                    "user": {
                        "agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"
                    }
                },
                "src": {
                    "port": 0
                },
                "ssl": {
                    "cipher": "NONE",
                    "protocol": "TLSv1.2"
                },
                "tcp_rtt": {
                    "ms": 0
                },
                "xrequested_with": "Request With"
            },
            "cookies": {
                "key": "value"
            },
            "edge": {
                "cf_connecting_o2o": false,
                "colo": {
                    "code": "RUH",
                    "id": 339
                },
                "end_time": "2022-05-25T13:25:32.000Z",
                "pathing": {
                    "op": "wl",
                    "src": "macro",
                    "status": "nr"
                },
                "rate": {
                    "limit": {
                        "action": "unknown",
                        "id": 0
                    }
                },
                "request": {
                    "host": "abc.example.com"
                },
                "response": {
                    "body_bytes": 980397,
                    "bytes": 981308,
                    "compression_ratio": 0,
                    "content_type": "application/json",
                    "status": 200
                },
                "server": {
                    "ip": "1.128.0.0"
                },
                "start_time": "2022-05-25T13:25:26.000Z",
                "time_to_first_byte": {
                    "ms": 5333
                }
            },
            "origin": {
                "dns_response_time": {
                    "ms": 3
                },
                "ip": "67.43.156.0",
                "request_header_send_duration": {
                    "ms": 0
                },
                "response": {
                    "bytes": 0,
                    "duration": {
                        "ms": 5319
                    },
                    "header_receive_duration": {
                        "ms": 5155
                    },
                    "http": {
                        "expires": "2022-05-27T13:25:26.000Z",
                        "last_modified": "2022-05-26T13:25:26.000Z"
                    },
                    "status": 200,
                    "time": 5232000000
                },
                "ssl_protocol": "TLSv1.2",
                "tcp_handshake_duration": {
                    "ms": 24
                },
                "tls_handshake_duration": {
                    "ms": 53
                }
            },
            "parent_ray": {
                "id": "710e98d93d50357d"
            },
            "ray": {
                "id": "710e98d9367f357d"
            },
            "security_level": "off",
            "smart_route": {
                "colo": {
                    "id": 20
                }
            },
            "upper_tier": {
                "colo": {
                    "id": 0
                }
            },
            "waf": {
                "action": "unknown",
                "flag": "0",
                "matched_var": "example",
                "profile": "unknown",
                "rule": {
                    "id": "98d93d5",
                    "message": "matchad variable message"
                }
            },
            "worker": {
                "cpu_time": 0,
                "status": "unknown",
                "subrequest": {
                    "count": 0,
                    "value": true
                }
            },
            "zone": {
                "id": 393347122,
                "name": "example.com"
            }
        }
    },
    "data_stream": {
        "dataset": "cloudflare_logpush.http_request",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "ip": "67.43.156.0"
    },
    "ecs": {
        "version": "8.7.0"
    },
    "elastic_agent": {
        "id": "8eb33de0-90ff-4a4c-82ff-082ffbaa315f",
        "snapshot": false,
        "version": "8.6.2"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "cloudflare_logpush.http_request",
        "ingested": "2023-04-18T02:04:43Z",
        "kind": "event",
        "original": "{\"BotScore\":\"20\",\"BotScoreSrc\":\"Verified Bot\",\"BotTags\":\"bing\",\"CacheCacheStatus\":\"dynamic\",\"CacheResponseBytes\":983828,\"CacheResponseStatus\":200,\"CacheTieredFill\":false,\"ClientASN\":43766,\"ClientCountry\":\"sa\",\"ClientDeviceType\":\"desktop\",\"ClientIP\":\"175.16.199.0\",\"ClientIPClass\":\"noRecord\",\"ClientMTLSAuthCertFingerprint\":\"Fingerprint\",\"ClientMTLSAuthStatus\":\"unknown\",\"ClientRequestBytes\":5800,\"ClientRequestHost\":\"xyz.example.com\",\"ClientRequestMethod\":\"POST\",\"ClientRequestPath\":\"/xyz/checkout\",\"ClientRequestProtocol\":\"HTTP/1.1\",\"ClientRequestReferer\":\"https://example.com/s/example/default?sourcerer=(default:(id:!n,selectedPatterns:!(example,%27logs-endpoint.*-example%27,%27logs-system.*-example%27,%27logs-windows.*-example%27)))\\u0026timerange=(global:(linkTo:!(),timerange:(from:%272022-05-16T06:26:36.340Z%27,fromStr:now-24h,kind:relative,to:%272022-05-17T06:26:36.340Z%27,toStr:now)),timeline:(linkTo:!(),timerange:(from:%272022-04-17T22:00:00.000Z%27,kind:absolute,to:%272022-04-18T21:59:59.999Z%27)))\\u0026timeline=(activeTab:notes,graphEventId:%27%27,id:%279844bdd4-4dd6-5b22-ab40-3cd46fce8d6b%27,isOpen:!t)\",\"ClientRequestScheme\":\"https\",\"ClientRequestSource\":\"edgeWorkerFetch\",\"ClientRequestURI\":\"/s/example/api/telemetry/v2/clusters/_stats\",\"ClientRequestUserAgent\":\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36\",\"ClientSSLCipher\":\"NONE\",\"ClientSSLProtocol\":\"TLSv1.2\",\"ClientSrcPort\":0,\"ClientTCPRTTMs\":0,\"ClientXRequestedWith\":\"Request With\",\"Cookies\":{\"key\":\"value\"},\"EdgeCFConnectingO2O\":false,\"EdgeColoCode\":\"RUH\",\"EdgeColoID\":339,\"EdgeEndTimestamp\":\"2022-05-25T13:25:32Z\",\"EdgePathingOp\":\"wl\",\"EdgePathingSrc\":\"macro\",\"EdgePathingStatus\":\"nr\",\"EdgeRateLimitAction\":\"unknown\",\"EdgeRateLimitID\":0,\"EdgeRequestHost\":\"abc.example.com\",\"EdgeResponseBodyBytes\":980397,\"EdgeResponseBytes\":981308,\"EdgeResponseCompressionRatio\":0,\"EdgeResponseContentType\":\"application/json\",\"EdgeResponseStatus\":200,\"EdgeServerIP\":\"1.128.0.0\",\"EdgeStartTimestamp\":\"2022-05-25T13:25:26Z\",\"EdgeTimeToFirstByteMs\":5333,\"OriginDNSResponseTimeMs\":3,\"OriginIP\":\"67.43.156.0\",\"OriginRequestHeaderSendDurationMs\":0,\"OriginResponseBytes\":0,\"OriginResponseDurationMs\":5319,\"OriginResponseHTTPExpires\":\"2022-05-27T13:25:26Z\",\"OriginResponseHTTPLastModified\":\"2022-05-26T13:25:26Z\",\"OriginResponseHeaderReceiveDurationMs\":5155,\"OriginResponseStatus\":200,\"OriginResponseTime\":5232000000,\"OriginSSLProtocol\":\"TLSv1.2\",\"OriginTCPHandshakeDurationMs\":24,\"OriginTLSHandshakeDurationMs\":53,\"ParentRayID\":\"710e98d93d50357d\",\"RayID\":\"710e98d9367f357d\",\"SecurityLevel\":\"off\",\"SmartRouteColoID\":20,\"UpperTierColoID\":0,\"WAFAction\":\"unknown\",\"WAFFlags\":\"0\",\"WAFMatchedVar\":\"example\",\"WAFProfile\":\"unknown\",\"WAFRuleID\":\"98d93d5\",\"WAFRuleMessage\":\"matchad variable message\",\"WorkerCPUTime\":0,\"WorkerStatus\":\"unknown\",\"WorkerSubrequest\":true,\"WorkerSubrequestCount\":0,\"ZoneID\":393347122,\"ZoneName\":\"example.com\"}",
        "type": [
            "info"
        ]
    },
    "http": {
        "request": {
            "method": "POST"
        },
        "response": {
            "mime_type": "application/json",
            "status_code": 200
        },
        "version": "1.1"
    },
    "input": {
        "type": "http_endpoint"
    },
    "network": {
        "protocol": "http"
    },
    "related": {
        "ip": [
            "175.16.199.0",
            "67.43.156.0"
        ]
    },
    "source": {
        "as": {
            "number": 43766
        },
        "geo": {
            "country_iso_code": "sa"
        },
        "ip": "175.16.199.0"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "cloudflare_logpush_http_request"
    ],
    "tls": {
        "version": "1.2",
        "version_protocol": "tls"
    },
    "url": {
        "domain": "xyz.example.com",
        "original": "/s/example/api/telemetry/v2/clusters/_stats",
        "path": "/s/example/api/telemetry/v2/clusters/_stats",
        "scheme": "https"
    },
    "user_agent": {
        "device": {
            "name": "Mac"
        },
        "name": "Chrome",
        "original": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36",
        "os": {
            "full": "Mac OS X 10.10.5",
            "name": "Mac OS X",
            "version": "10.10.5"
        },
        "version": "51.0.2704.103"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization ID used to identify different entities in a multi-tenant environment. Examples: AWS account ID, Google Cloud ORG ID, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| cloudflare_logpush.http_request.bot.score.src | Detection engine responsible for generating the Bot Score. | text |
| cloudflare_logpush.http_request.bot.score.value | Cloudflare Bot Score, Scores below 30 are commonly associated with automated traffic. | long |
| cloudflare_logpush.http_request.bot.tag | Type of bot traffic (if available). | text |
| cloudflare_logpush.http_request.cache.response.bytes | Number of bytes returned by the cache. | long |
| cloudflare_logpush.http_request.cache.response.status | Cache status. | long |
| cloudflare_logpush.http_request.cache.status | HTTP status code returned by the cache to the edge. | keyword |
| cloudflare_logpush.http_request.cache.tiered_fill | Tiered Cache was used to serve this request. | boolean |
| cloudflare_logpush.http_request.client.asn | Client AS number. | long |
| cloudflare_logpush.http_request.client.country | Country of the client IP address. | keyword |
| cloudflare_logpush.http_request.client.device.type | Client device type. | keyword |
| cloudflare_logpush.http_request.client.ip | IP address of the client. | ip |
| cloudflare_logpush.http_request.client.ip_class | Class IP. | keyword |
| cloudflare_logpush.http_request.client.mtls.auth.fingerprint | The SHA256 fingerprint of the certificate presented by the client during mTLS authentication. | keyword |
| cloudflare_logpush.http_request.client.mtls.auth.status | The status of mTLS authentication, Only populated on the first request on an mTLS connection. | keyword |
| cloudflare_logpush.http_request.client.request.bytes | Number of bytes in the client request. | long |
| cloudflare_logpush.http_request.client.request.host | Host requested by the client. | keyword |
| cloudflare_logpush.http_request.client.request.method | HTTP method of client request. | text |
| cloudflare_logpush.http_request.client.request.path | URI path requested by the client. | text |
| cloudflare_logpush.http_request.client.request.protocol | HTTP protocol of client request. | keyword |
| cloudflare_logpush.http_request.client.request.referer | HTTP request referrer. | text |
| cloudflare_logpush.http_request.client.request.scheme | The URL scheme requested by the visitor. | text |
| cloudflare_logpush.http_request.client.request.source | Identifies requests as coming from an external source or another service within Cloudflare. | keyword |
| cloudflare_logpush.http_request.client.request.uri | URI requested by the client. | text |
| cloudflare_logpush.http_request.client.request.user.agent | User agent reported by the client. | text |
| cloudflare_logpush.http_request.client.src.port | Client source port. | long |
| cloudflare_logpush.http_request.client.ssl.cipher | Client SSL cipher. | text |
| cloudflare_logpush.http_request.client.ssl.protocol | Client SSL (TLS) protocol. | keyword |
| cloudflare_logpush.http_request.client.tcp_rtt.ms | The smoothed average of TCP round-trip time (SRTT), For the initial request on a connection, this is measured only during connection setup, For a subsequent request on the same connection, it is measured over the entire connection lifetime up until the time that request is received. | long |
| cloudflare_logpush.http_request.client.xrequested_with | X-Requested-With HTTP header. | text |
| cloudflare_logpush.http_request.cookies | String key-value pairs for Cookies. | flattened |
| cloudflare_logpush.http_request.edge.cf_connecting_o2o | True if the request looped through multiple zones on the Cloudflare edge. | boolean |
| cloudflare_logpush.http_request.edge.colo.code | IATA airport code of data center that received the request. | keyword |
| cloudflare_logpush.http_request.edge.colo.id | Cloudflare edge colo id. | long |
| cloudflare_logpush.http_request.edge.end_time | Timestamp at which the edge finished sending response to the client. | date |
| cloudflare_logpush.http_request.edge.pathing.op | Indicates what type of response was issued for this request. | text |
| cloudflare_logpush.http_request.edge.pathing.src | Details how the request was classified based on security checks. | text |
| cloudflare_logpush.http_request.edge.pathing.status | Indicates what data was used to determine the handling of this request. | text |
| cloudflare_logpush.http_request.edge.rate.limit.action | The action taken by the blocking rule; empty if no action taken. | keyword |
| cloudflare_logpush.http_request.edge.rate.limit.id | The internal rule ID of the rate-limiting rule that triggered a block (ban) or log action. | long |
| cloudflare_logpush.http_request.edge.request.host | Host header on the request from the edge to the origin. | keyword |
| cloudflare_logpush.http_request.edge.response.body_bytes | Size of the HTTP response body returned to clients. | long |
| cloudflare_logpush.http_request.edge.response.bytes | Number of bytes returned by the edge to the client. | long |
| cloudflare_logpush.http_request.edge.response.compression_ratio | Edge response compression ratio. | double |
| cloudflare_logpush.http_request.edge.response.content_type | Edge response Content-Type header value. | text |
| cloudflare_logpush.http_request.edge.response.status | HTTP status code returned by Cloudflare to the client. | long |
| cloudflare_logpush.http_request.edge.server.ip | IP of the edge server making a request to the origin. | ip |
| cloudflare_logpush.http_request.edge.start_time | Timestamp at which the edge received request from the client. | date |
| cloudflare_logpush.http_request.edge.time_to_first_byte.ms | Total view of Time To First Byte as measured at Cloudflare edge. | long |
| cloudflare_logpush.http_request.firewall.matches.action | Array of actions the Cloudflare firewall products performed on this request. | nested |
| cloudflare_logpush.http_request.firewall.matches.rule_id | Array of RuleIDs of the firewall product that has matched the request. | nested |
| cloudflare_logpush.http_request.firewall.matches.sources | The firewall products that matched the request. | nested |
| cloudflare_logpush.http_request.ja3_hash | The MD5 hash of the JA3 fingerprint used to profile SSL/TLS clients. | keyword |
| cloudflare_logpush.http_request.origin.dns_response_time.ms | Time taken to receive a DNS response for an origin name. | long |
| cloudflare_logpush.http_request.origin.ip | IP of the origin server. | ip |
| cloudflare_logpush.http_request.origin.request_header_send_duration.ms | Time taken to send request headers to origin after establishing a connection. | long |
| cloudflare_logpush.http_request.origin.response.bytes | Number of bytes returned by the origin server. | long |
| cloudflare_logpush.http_request.origin.response.duration.ms | Upstream response time, measured from the first datacenter that receives a request. | long |
| cloudflare_logpush.http_request.origin.response.header_receive_duration.ms | Time taken for origin to return response headers after Cloudflare finishes sending request headers. | long |
| cloudflare_logpush.http_request.origin.response.http.expires | Value of the origin expires header in RFC1123 format. | date |
| cloudflare_logpush.http_request.origin.response.http.last_modified | Value of the origin last-modified header in RFC1123 format. | date |
| cloudflare_logpush.http_request.origin.response.status | Status returned by the origin server. | long |
| cloudflare_logpush.http_request.origin.response.time | Number of nanoseconds it took the origin to return the response to edge. | long |
| cloudflare_logpush.http_request.origin.ssl_protocol | SSL (TLS) protocol used to connect to the origin. | text |
| cloudflare_logpush.http_request.origin.tcp_handshake_duration.ms | Time taken to complete TCP handshake with origin. | long |
| cloudflare_logpush.http_request.origin.tls_handshake_duration.ms | Time taken to complete TLS handshake with origin. | long |
| cloudflare_logpush.http_request.parent_ray.id | Ray ID of the parent request if this request was made using a Worker script. | keyword |
| cloudflare_logpush.http_request.ray.id | ID of the request. | keyword |
| cloudflare_logpush.http_request.request.headers | String key-value pairs for RequestHeaders. | flattened |
| cloudflare_logpush.http_request.response.headers | String key-value pairs for ResponseHeaders. | flattened |
| cloudflare_logpush.http_request.security_level | The security level configured at the time of this request. This is used to determine the sensitivity of the IP Reputation system. | text |
| cloudflare_logpush.http_request.smart_route.colo.id | The Cloudflare datacenter used to connect to the origin server if Argo Smart Routing is used. Available in Logpush v2 only. | long |
| cloudflare_logpush.http_request.upper_tier.colo.id | The “upper tier” datacenter that was checked for a cached copy if Tiered Cache is used. Available in Logpush v2 only. | long |
| cloudflare_logpush.http_request.waf.action | Action taken by the WAF, if triggered. | text |
| cloudflare_logpush.http_request.waf.flag | Additional configuration flags. | text |
| cloudflare_logpush.http_request.waf.matched_var | The full name of the most-recently matched variable. | text |
| cloudflare_logpush.http_request.waf.profile | The Profile of WAF. possible values are:- 'low', 'med', 'high'. | keyword |
| cloudflare_logpush.http_request.waf.rule.id | ID of the applied WAF rule. | keyword |
| cloudflare_logpush.http_request.waf.rule.message | Rule message associated with the triggered rule. | text |
| cloudflare_logpush.http_request.worker.cpu_time | Amount of time in microseconds spent executing a worker, if any. | long |
| cloudflare_logpush.http_request.worker.status | Status returned from worker daemon. | text |
| cloudflare_logpush.http_request.worker.subrequest.count | Number of subrequests issued by a worker when handling this request. | long |
| cloudflare_logpush.http_request.worker.subrequest.value | Whether or not this request was a worker subrequest. | boolean |
| cloudflare_logpush.http_request.worker.wall_time_us | Real-time in microseconds elapsed between start and end of worker invocation. | long |
| cloudflare_logpush.http_request.zone.id | Internal zone ID. | long |
| cloudflare_logpush.http_request.zone.name | The human-readable name of the zone. | keyword |
| container.id | Unique container ID. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
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
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.response.mime_type | Mime type of the body of the response. This value must only be populated based on the content of the response body, not on the `Content-Type` header. Comparing the mime type of a response with the response's Content-Type header can be helpful in detecting misconfigured servers. | keyword |
| http.response.status_code | HTTP response status code. | long |
| http.version | HTTP version. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
| tls.version | Numeric part of the version parsed from the original string. | keyword |
| tls.version_protocol | Normalized lowercase protocol name parsed from original string. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| url.path | Path of the request, such as "/search". | wildcard |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.full.text | Multi-field of `user_agent.os.full`. | match_only_text |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.name.text | Multi-field of `user_agent.os.name`. | match_only_text |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |


### nel_report

This is the `nel_report` dataset.
Default port for HTTP Endpoint: _9564_

#### Example

An example event for `nel_report` looks as following:

```json
{
    "@timestamp": "2021-07-27T00:01:07.000Z",
    "agent": {
        "ephemeral_id": "c38ba64f-2007-40ee-8ba6-7eead6aad5ee",
        "hostname": "docker-fleet-agent",
        "id": "8539930e-8f7a-48ac-af3e-7f098b7d6ea2",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.17.0"
    },
    "cloudflare_logpush": {
        "nel_report": {
            "client": {
                "ip": {
                    "asn": {
                        "description": "CLOUDFLARENET",
                        "value": 13335
                    },
                    "country": "US"
                }
            },
            "error": {
                "type": "network-error"
            },
            "last_known_good": {
                "colo": {
                    "code": "SJC"
                }
            },
            "phase": "connection",
            "timestamp": "2021-07-27T00:01:07.000Z"
        }
    },
    "data_stream": {
        "dataset": "cloudflare_logpush.nel_report",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.7.0"
    },
    "elastic_agent": {
        "id": "8539930e-8f7a-48ac-af3e-7f098b7d6ea2",
        "snapshot": false,
        "version": "7.17.0"
    },
    "error": {
        "type": "network-error"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "cloudflare_logpush.nel_report",
        "ingested": "2022-09-01T10:09:13Z",
        "kind": "event",
        "original": "{\"ClientIPASN\":\"13335\",\"ClientIPASNDescription\":\"CLOUDFLARENET\",\"ClientIPCountry\":\"US\",\"LastKnownGoodColoCode\":\"SJC\",\"Phase\":\"connection\",\"Timestamp\":\"2021-07-27T00:01:07Z\",\"Type\":\"network-error\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "http_endpoint"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "cloudflare_logpush_nel_report"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization ID used to identify different entities in a multi-tenant environment. Examples: AWS account ID, Google Cloud ORG ID, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| cloudflare_logpush.nel_report.client.ip.asn.description | Client ASN description. | keyword |
| cloudflare_logpush.nel_report.client.ip.asn.value | Client ASN. | long |
| cloudflare_logpush.nel_report.client.ip.country | Client country. | keyword |
| cloudflare_logpush.nel_report.error.type | The type of error in the phase. | keyword |
| cloudflare_logpush.nel_report.last_known_good.colo.code | IATA airport code of colo client connected to. | keyword |
| cloudflare_logpush.nel_report.phase | The phase of connection the error occurred in. | keyword |
| cloudflare_logpush.nel_report.timestamp | Timestamp for error report. | date |
| container.id | Unique container ID. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.type | The type of the error, for example the class name of the exception. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
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
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| tags | List of keywords used to tag each event. | keyword |


### network_analytics

This is the `network_analytics` dataset.
Default port for HTTP Endpoint: _9565_

#### Example

An example event for `network_analytics` looks as following:

```json
{
    "@timestamp": "2021-07-27T00:01:07.000Z",
    "agent": {
        "ephemeral_id": "a59f9c29-2b33-4505-be1c-b7bc89c786a7",
        "hostname": "docker-fleet-agent",
        "id": "8539930e-8f7a-48ac-af3e-7f098b7d6ea2",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.17.0"
    },
    "cloudflare_logpush": {
        "network_analytics": {
            "attack": {
                "campaign": {
                    "id": "xyz987"
                },
                "id": "abc777"
            },
            "colo": {
                "country": "AD",
                "geo_hash": "gbuun",
                "geo_location": "gbuun",
                "id": 46,
                "name": "SJC"
            },
            "destination": {
                "as": {
                    "number": {
                        "description": "asn description"
                    }
                },
                "asn": 1900,
                "country": "AD",
                "geo_hash": "gbuun",
                "geo_location": "gbuun",
                "ip": "175.16.199.0",
                "port": 0
            },
            "direction": "ingress",
            "gre": {
                "checksum": 10,
                "ether": {
                    "type": 10
                },
                "header": {
                    "length": 1024
                },
                "key": 10,
                "sequence": {
                    "number": 10
                },
                "version": 10
            },
            "icmp": {
                "checksum": 10,
                "code": 10,
                "type": 10
            },
            "ip": {
                "destination": {
                    "subnet": "/24"
                },
                "fragment": {
                    "offset": 1480
                },
                "header": {
                    "length": 20
                },
                "more": {
                    "fragments": 1480
                },
                "protocol": {
                    "name": "tcp",
                    "value": 6
                },
                "source": {
                    "subnet": "/24"
                },
                "total": {
                    "length": {
                        "buckets": 10,
                        "value": 1024
                    }
                },
                "ttl": {
                    "buckets": 2,
                    "value": 240
                }
            },
            "ipv4": {
                "checksum": 0,
                "dont_fragment": 0,
                "dscp": 46,
                "ecn": 1,
                "identification": 1,
                "options": 1
            },
            "ipv6": {
                "dscp": 46,
                "ecn": 1,
                "extension_headers": "header",
                "flow_label": 1,
                "identification": 1
            },
            "mitigation": {
                "reason": "BLOCKED",
                "scope": "local",
                "system": "flowtrackd"
            },
            "outcome": "success",
            "protocol_state": "OPEN",
            "rule": {
                "id": "rule1",
                "set": {
                    "id": "3b64149bfa6e4220bbbc2bd6db589552",
                    "override": {
                        "id": "id1"
                    }
                }
            },
            "sample_interval": 1,
            "source": {
                "as": {
                    "number": {
                        "description": "Source ASN Description"
                    }
                },
                "asn": 1500,
                "country": "AD",
                "geo_hash": "gbuun",
                "geo_location": "gbuun",
                "ip": "67.43.156.0",
                "port": 0
            },
            "tcp": {
                "acknowledgement_number": 1000,
                "checksum": 10,
                "dataoffset": 0,
                "flags": {
                    "string": "Human-readable flags string",
                    "value": 1
                },
                "mss": 512,
                "options": "mss",
                "sack": {
                    "blocks": 1,
                    "permitted": 1
                },
                "sequence_number": 100,
                "timestamp": {
                    "ecr": 100,
                    "value": 100
                },
                "urgent_pointer": 10,
                "window": {
                    "scale": 10,
                    "size": 10
                }
            },
            "timestamp": "2021-07-27T00:01:07.000Z",
            "udp": {
                "checksum": 10,
                "payload_length": 10
            },
            "verdict": "pass"
        }
    },
    "data_stream": {
        "dataset": "cloudflare_logpush.network_analytics",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "as": {
            "number": 1900
        },
        "ip": "175.16.199.0",
        "port": 0
    },
    "ecs": {
        "version": "8.7.0"
    },
    "elastic_agent": {
        "id": "8539930e-8f7a-48ac-af3e-7f098b7d6ea2",
        "snapshot": false,
        "version": "7.17.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "cloudflare_logpush.network_analytics",
        "ingested": "2022-09-01T10:10:02Z",
        "kind": "event",
        "original": "{\"AttackCampaignID\":\"xyz987\",\"AttackID\":\"abc777\",\"ColoCountry\":\"AD\",\"ColoGeoHash\":\"gbuun\",\"ColoID\":46,\"ColoName\":\"SJC\",\"Datetime\":\"2021-07-27T00:01:07Z\",\"DestinationASN\":1900,\"DestinationASNDescription\":\"asn description\",\"DestinationCountry\":\"AD\",\"DestinationGeoHash\":\"gbuun\",\"DestinationPort\":0,\"Direction\":\"ingress\",\"GREChecksum\":10,\"GREEthertype\":10,\"GREHeaderLength\":1024,\"GREKey\":10,\"GRESequenceNumber\":10,\"GREVersion\":10,\"ICMPChecksum\":10,\"ICMPCode\":10,\"ICMPType\":10,\"IPDestinationAddress\":\"175.16.199.0\",\"IPDestinationSubnet\":\"/24\",\"IPFragmentOffset\":1480,\"IPHeaderLength\":20,\"IPMoreFragments\":1480,\"IPProtocol\":6,\"IPProtocolName\":\"tcp\",\"IPSourceAddress\":\"67.43.156.0\",\"IPSourceSubnet\":\"/24\",\"IPTotalLength\":1024,\"IPTotalLengthBuckets\":10,\"IPTtl\":240,\"IPTtlBuckets\":2,\"IPv4Checksum\":0,\"IPv4DontFragment\":0,\"IPv4Dscp\":46,\"IPv4Ecn\":1,\"IPv4Identification\":1,\"IPv4Options\":1,\"IPv6Dscp\":46,\"IPv6Ecn\":1,\"IPv6ExtensionHeaders\":\"header\",\"IPv6FlowLabel\":1,\"IPv6Identification\":1,\"MitigationReason\":\"BLOCKED\",\"MitigationScope\":\"local\",\"MitigationSystem\":\"flowtrackd\",\"Outcome\":\"pass\",\"ProtocolState\":\"OPEN\",\"RuleID\":\"rule1\",\"RulesetID\":\"3b64149bfa6e4220bbbc2bd6db589552\",\"RulesetOverrideID\":\"id1\",\"SampleInterval\":1,\"SourceASN\":1500,\"SourceASNDescription\":\"Source ASN Description\",\"SourceCountry\":\"AD\",\"SourceGeoHash\":\"gbuun\",\"SourcePort\":0,\"TCPAcknowledgementNumber\":1000,\"TCPChecksum\":10,\"TCPDataOffset\":0,\"TCPFlags\":1,\"TCPFlagsString\":\"Human-readable flags string\",\"TCPMss\":512,\"TCPOptions\":\"mss\",\"TCPSackBlocks\":1,\"TCPSacksPermitted\":1,\"TCPSequenceNumber\":100,\"TCPTimestampEcr\":100,\"TCPTimestampValue\":100,\"TCPUrgentPointer\":10,\"TCPWindowScale\":10,\"TCPWindowSize\":10,\"UDPChecksum\":10,\"UDPPayloadLength\":10,\"Verdict\":\"pass\"}",
        "outcome": "success",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "http_endpoint"
    },
    "network": {
        "direction": "ingress",
        "transport": "tcp"
    },
    "related": {
        "hash": [
            "gbuun"
        ],
        "ip": [
            "67.43.156.0",
            "175.16.199.0"
        ]
    },
    "rule": {
        "id": "rule1"
    },
    "source": {
        "as": {
            "number": 1500
        },
        "ip": "67.43.156.0",
        "port": 0
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "cloudflare_logpush_network_analytics"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization ID used to identify different entities in a multi-tenant environment. Examples: AWS account ID, Google Cloud ORG ID, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| cloudflare_logpush.network_analytics.attack.campaign.id | Unique identifier of the attack campaign that this packet was a part of, if any. | keyword |
| cloudflare_logpush.network_analytics.attack.id | Unique identifier of the mitigation that matched the packet, if any. | keyword |
| cloudflare_logpush.network_analytics.colo.country | The country of colo that received the packet (ISO 3166-1 alpha-2). | keyword |
| cloudflare_logpush.network_analytics.colo.geo_hash | The Geo Hash where the colo that received the packet is located. | keyword |
| cloudflare_logpush.network_analytics.colo.geo_location | The latitude and longitude where the colo that received the packet is located. | geo_point |
| cloudflare_logpush.network_analytics.colo.id | The ID of the colo that received the DNS query. | long |
| cloudflare_logpush.network_analytics.colo.name | The name of the colo that received the DNS query. | keyword |
| cloudflare_logpush.network_analytics.destination.as.number.description | The ASN description associated with the destination IP of the packet. | text |
| cloudflare_logpush.network_analytics.destination.asn | The ASN associated with the destination IP of the packet. | long |
| cloudflare_logpush.network_analytics.destination.country | The country where the destination IP of the packet is located. | keyword |
| cloudflare_logpush.network_analytics.destination.geo_hash | The Geo Hash where the destination IP of the packet is located. | keyword |
| cloudflare_logpush.network_analytics.destination.geo_location | The latitude and longitude where the destination IP of the packet is located. | geo_point |
| cloudflare_logpush.network_analytics.destination.ip | Value of the Destination Address header field in the IPv4 or IPv6 packet. | ip |
| cloudflare_logpush.network_analytics.destination.port | Value of the Destination Port header field in the TCP or UDP packet. | long |
| cloudflare_logpush.network_analytics.direction | The direction in relation to customer network. | keyword |
| cloudflare_logpush.network_analytics.gre.checksum | Value of the Checksum header field in the GRE packet. | long |
| cloudflare_logpush.network_analytics.gre.ether.type | Value of the Ethertype header field in the GRE packet. | long |
| cloudflare_logpush.network_analytics.gre.header.length | Length of the GRE packet header, in bytes. | long |
| cloudflare_logpush.network_analytics.gre.key | Value of the Key header field in the GRE packet. | long |
| cloudflare_logpush.network_analytics.gre.sequence.number | Value of the Sequence Number header field in the GRE packet. | long |
| cloudflare_logpush.network_analytics.gre.version | Value of the Version header field in the GRE packet. | long |
| cloudflare_logpush.network_analytics.icmp.checksum | Value of the Checksum header field in the ICMP packet | long |
| cloudflare_logpush.network_analytics.icmp.code | Value of the Code header field in the ICMP packet | long |
| cloudflare_logpush.network_analytics.icmp.type | Value of the Type header field in the ICMP packet | long |
| cloudflare_logpush.network_analytics.ip.destination.subnet | Computed subnet of the Destination Address header field in the IPv4 or IPv6 packet. | keyword |
| cloudflare_logpush.network_analytics.ip.fragment.offset | Value of the Fragment Offset header field in the IPv4 or IPv6 packet. | long |
| cloudflare_logpush.network_analytics.ip.header.length | Length of the IPv4 or IPv6 packet header, in bytes. | long |
| cloudflare_logpush.network_analytics.ip.more.fragments | Value of the More Fragments header field in the IPv4 or IPv6 packet. | long |
| cloudflare_logpush.network_analytics.ip.protocol.name | Name of the protocol specified by the Protocol header field in the IPv4 or IPv6 packet. | text |
| cloudflare_logpush.network_analytics.ip.protocol.value | Value of the Protocol header field in the IPv4 or IPv6 packet. | long |
| cloudflare_logpush.network_analytics.ip.source.subnet | Computed subnet of the Source Address header field in the IPv4 or IPv6 packet. | keyword |
| cloudflare_logpush.network_analytics.ip.total.length.buckets | Total length of the IPv4 or IPv6 packet, in bytes, with the last two digits truncated. | long |
| cloudflare_logpush.network_analytics.ip.total.length.value | Total length of the IPv4 or IPv6 packet, in bytes. | long |
| cloudflare_logpush.network_analytics.ip.ttl.buckets | Value of the TTL header field in the IPv4 packet or the Hop Limit header field in the IPv6 packet, with the last digit truncated. | long |
| cloudflare_logpush.network_analytics.ip.ttl.value | Value of the TTL header field in the IPv4 packet or the Hop Limit header field in the IPv6 packet. | long |
| cloudflare_logpush.network_analytics.ipv4.checksum | Value of the Checksum header field in the IPv4 packet. | long |
| cloudflare_logpush.network_analytics.ipv4.dont_fragment | Value of the Don’t Fragment header field in the IPv4 packet. | long |
| cloudflare_logpush.network_analytics.ipv4.dscp | Value of the Differentiated Services Code Point header field in the IPv4 packet. | long |
| cloudflare_logpush.network_analytics.ipv4.ecn | Value of the Explicit Congestion Notification header field in the IPv4 packet. | long |
| cloudflare_logpush.network_analytics.ipv4.identification | Value of the Identification header field in the IPv4 packet. | long |
| cloudflare_logpush.network_analytics.ipv4.options | List of Options numbers included in the IPv4 packet header. | long |
| cloudflare_logpush.network_analytics.ipv6.dscp | Value of the Differentiated Services Code Point header field in the IPv6 packet. | long |
| cloudflare_logpush.network_analytics.ipv6.ecn | Value of the Explicit Congestion Notification header field in the IPv6 packet. | long |
| cloudflare_logpush.network_analytics.ipv6.extension_headers | List of Extension Header numbers included in the IPv6 packet header. | text |
| cloudflare_logpush.network_analytics.ipv6.flow_label | Value of the Flow Label header field in the IPv6 packet. | long |
| cloudflare_logpush.network_analytics.ipv6.identification | Value of the Identification extension header field in the IPv6 packet. | long |
| cloudflare_logpush.network_analytics.mitigation.reason | Reason for applying a mitigation to the packet, if any. | keyword |
| cloudflare_logpush.network_analytics.mitigation.scope | Whether the packet matched a local or global mitigation, if any. | keyword |
| cloudflare_logpush.network_analytics.mitigation.system | Which Cloudflare system dropped the packet, if any. | keyword |
| cloudflare_logpush.network_analytics.outcome | The action that Cloudflare systems took on the packet. | keyword |
| cloudflare_logpush.network_analytics.protocol_state | State of the packet in the context of the protocol, if any. | keyword |
| cloudflare_logpush.network_analytics.rule.id | Unique identifier of the rule contained with the Cloudflare L3/4 managed ruleset that this packet matched, if any. | text |
| cloudflare_logpush.network_analytics.rule.set.id | Unique identifier of the Cloudflare L3/4 managed ruleset containing the rule that this packet matched, if any. | keyword |
| cloudflare_logpush.network_analytics.rule.set.override.id | Unique identifier of the rule within the accounts root ddos_l4 phase ruleset which resulted in an override of the default sensitivity or action being applied/evaluated, if any. | text |
| cloudflare_logpush.network_analytics.sample_interval | The sample interval for this log. | long |
| cloudflare_logpush.network_analytics.source.as.number.description | The ASN description associated with the source IP of the packet. | text |
| cloudflare_logpush.network_analytics.source.asn | The ASN associated with the source IP of the packet. | long |
| cloudflare_logpush.network_analytics.source.country | The country where the source IP of the packet is located. | keyword |
| cloudflare_logpush.network_analytics.source.geo_hash | The Geo Hash where the source IP of the packet is located. | keyword |
| cloudflare_logpush.network_analytics.source.geo_location | The latitude and longitude where the source IP of the packet is located. | geo_point |
| cloudflare_logpush.network_analytics.source.ip | Value of the Source Address header field in the IPv4 or IPv6 packet. | ip |
| cloudflare_logpush.network_analytics.source.port | Value of the Source Port header field in the TCP or UDP packet. | long |
| cloudflare_logpush.network_analytics.tcp.acknowledgement_number | Value of the Acknowledgement Number header field in the TCP packet. | long |
| cloudflare_logpush.network_analytics.tcp.checksum | Value of the Checksum header field in the TCP packet. | long |
| cloudflare_logpush.network_analytics.tcp.dataoffset | Value of the Data Offset header field in the TCP packet. | long |
| cloudflare_logpush.network_analytics.tcp.flags.string | Human-readable string representation of the Flags header field in the TCP packet. | text |
| cloudflare_logpush.network_analytics.tcp.flags.value | Value of the Flags header field in the TCP packet. | long |
| cloudflare_logpush.network_analytics.tcp.mss | Value of the MSS option header field in the TCP packet. | long |
| cloudflare_logpush.network_analytics.tcp.options | List of Options numbers included in the TCP packet header. | text |
| cloudflare_logpush.network_analytics.tcp.sack.blocks | Value of the SACK Blocks option header in the TCP packet. | long |
| cloudflare_logpush.network_analytics.tcp.sack.permitted | Value of the SACK Permitted option header in the TCP packet. | long |
| cloudflare_logpush.network_analytics.tcp.sequence_number | Value of the Sequence Number header field in the TCP packet. | long |
| cloudflare_logpush.network_analytics.tcp.timestamp.ecr | Value of the Timestamp Echo Reply option header in the TCP packet. | long |
| cloudflare_logpush.network_analytics.tcp.timestamp.value | Value of the Timestamp option header in the TCP packet. | long |
| cloudflare_logpush.network_analytics.tcp.urgent_pointer | Value of the Urgent Pointer header field in the TCP packet. | long |
| cloudflare_logpush.network_analytics.tcp.window.scale | Value of the Window Scale option header in the TCP packet. | long |
| cloudflare_logpush.network_analytics.tcp.window.size | Value of the Window Size header field in the TCP packet. | long |
| cloudflare_logpush.network_analytics.timestamp | The date and time the event occurred at the edge. | date |
| cloudflare_logpush.network_analytics.udp.checksum | Value of the Checksum header field in the UDP packet. | long |
| cloudflare_logpush.network_analytics.udp.payload_length | Value of the Payload Length header field in the UDP packet. | long |
| cloudflare_logpush.network_analytics.verdict | The action that Cloudflare systems think should be taken on the packet (pass | drop). | keyword |
| container.id | Unique container ID. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
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
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. Learn more at https://github.com/corelight/community-id-spec. | keyword |
| network.direction | Direction of the network traffic. When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| rule.id | A rule ID that is unique within the scope of an agent, observer, or other entity using the rule for detection of this event. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |


### spectrum_event

This is the `spectrum_event` dataset.
Default port for HTTP Endpoint: _9566_

#### Example

An example event for `spectrum_event` looks as following:

```json
{
    "@timestamp": "2022-05-26T09:24:00.000Z",
    "agent": {
        "ephemeral_id": "34cad43e-ef45-4868-8da8-6e602991ef1a",
        "hostname": "docker-fleet-agent",
        "id": "8539930e-8f7a-48ac-af3e-7f098b7d6ea2",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.17.0"
    },
    "cloudflare_logpush": {
        "spectrum_event": {
            "action": "connect",
            "application": "7ef659a2f8ef4810a9bade96fdad7c75",
            "client": {
                "asn": 200391,
                "bytes": 0,
                "country": "bg",
                "ip": "67.43.156.0",
                "matched_ip_firewall": "UNKNOWN",
                "port": 40456,
                "protocol": "tcp",
                "tcp_rtt": 0,
                "tls": {
                    "cipher": "UNK",
                    "client_hello_server_name": "server name",
                    "protocol": "unknown",
                    "status": "UNKNOWN"
                }
            },
            "colo": {
                "code": "SOF"
            },
            "connect": {
                "time": "2022-05-26T09:24:00.000Z"
            },
            "disconnect": {
                "time": "1970-01-01T00:00:00.000Z"
            },
            "ip_firewall": false,
            "origin": {
                "bytes": 0,
                "ip": "175.16.199.0",
                "port": 3389,
                "protocol": "tcp",
                "tcp_rtt": 0,
                "tls": {
                    "cipher": "UNK",
                    "fingerprint": "0000000000000000000000000000000000000000000000000000000000000000.",
                    "mode": "off",
                    "protocol": "unknown",
                    "status": "UNKNOWN"
                }
            },
            "proxy": {
                "protocol": "off"
            },
            "status": 0,
            "timestamp": "2022-05-26T09:24:00.000Z"
        }
    },
    "data_stream": {
        "dataset": "cloudflare_logpush.spectrum_event",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "bytes": 0,
        "ip": "175.16.199.0",
        "port": 3389
    },
    "ecs": {
        "version": "8.7.0"
    },
    "elastic_agent": {
        "id": "8539930e-8f7a-48ac-af3e-7f098b7d6ea2",
        "snapshot": false,
        "version": "7.17.0"
    },
    "event": {
        "action": "connect",
        "agent_id_status": "verified",
        "category": [
            "network"
        ],
        "dataset": "cloudflare_logpush.spectrum_event",
        "end": "1970-01-01T00:00:00.000Z",
        "id": "7ef659a2f8ef4810a9bade96fdad7c75",
        "ingested": "2022-09-01T10:10:53Z",
        "kind": "event",
        "original": "{\"Application\":\"7ef659a2f8ef4810a9bade96fdad7c75\",\"ClientAsn\":200391,\"ClientBytes\":0,\"ClientCountry\":\"bg\",\"ClientIP\":\"67.43.156.0\",\"ClientMatchedIpFirewall\":\"UNKNOWN\",\"ClientPort\":40456,\"ClientProto\":\"tcp\",\"ClientTcpRtt\":0,\"ClientTlsCipher\":\"UNK\",\"ClientTlsClientHelloServerName\":\"server name\",\"ClientTlsProtocol\":\"unknown\",\"ClientTlsStatus\":\"UNKNOWN\",\"ColoCode\":\"SOF\",\"ConnectTimestamp\":\"2022-05-26T09:24:00Z\",\"DisconnectTimestamp\":\"1970-01-01T00:00:00Z\",\"Event\":\"connect\",\"IpFirewall\":false,\"OriginBytes\":0,\"OriginIP\":\"175.16.199.0\",\"OriginPort\":3389,\"OriginProto\":\"tcp\",\"OriginTcpRtt\":0,\"OriginTlsCipher\":\"UNK\",\"OriginTlsFingerprint\":\"0000000000000000000000000000000000000000000000000000000000000000.\",\"OriginTlsMode\":\"off\",\"OriginTlsProtocol\":\"unknown\",\"OriginTlsStatus\":\"UNKNOWN\",\"ProxyProtocol\":\"off\",\"Status\":0,\"Timestamp\":\"2022-05-26T09:24:00Z\"}",
        "start": "2022-05-26T09:24:00.000Z",
        "type": [
            "info"
        ]
    },
    "http": {
        "response": {
            "status_code": 0
        }
    },
    "input": {
        "type": "http_endpoint"
    },
    "network": {
        "community_id": "1:X7lywUVKlduqRq5SyCRaBj4hLP0=",
        "transport": "tcp"
    },
    "related": {
        "ip": [
            "67.43.156.0",
            "175.16.199.0"
        ]
    },
    "source": {
        "as": {
            "number": 200391
        },
        "bytes": 0,
        "geo": {
            "country_iso_code": "bg"
        },
        "ip": "67.43.156.0",
        "port": 40456
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "cloudflare_logpush_spectrum_event"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization ID used to identify different entities in a multi-tenant environment. Examples: AWS account ID, Google Cloud ORG ID, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| cloudflare_logpush.spectrum_event.action | Event Action. | keyword |
| cloudflare_logpush.spectrum_event.application | The unique public ID of the application on which the event occurred. | keyword |
| cloudflare_logpush.spectrum_event.client.asn | Client AS number. | long |
| cloudflare_logpush.spectrum_event.client.bytes | The number of bytes read from the client by the Spectrum service. | long |
| cloudflare_logpush.spectrum_event.client.country | Country of the client IP address. | keyword |
| cloudflare_logpush.spectrum_event.client.ip | Client IP address. | ip |
| cloudflare_logpush.spectrum_event.client.matched_ip_firewall | Whether the connection matched any IP Firewall rules. | keyword |
| cloudflare_logpush.spectrum_event.client.port | Client port. | long |
| cloudflare_logpush.spectrum_event.client.protocol | Transport protocol used by client. | keyword |
| cloudflare_logpush.spectrum_event.client.tcp_rtt | The TCP round-trip time in nanoseconds between the client and Spectrum. | long |
| cloudflare_logpush.spectrum_event.client.tls.cipher | The cipher negotiated between the client and Spectrum. | keyword |
| cloudflare_logpush.spectrum_event.client.tls.client_hello_server_name | The server name in the Client Hello message from client to Spectrum. | keyword |
| cloudflare_logpush.spectrum_event.client.tls.protocol | The TLS version negotiated between the client and Spectrum. | keyword |
| cloudflare_logpush.spectrum_event.client.tls.status | Indicates state of TLS session from the client to Spectrum. | keyword |
| cloudflare_logpush.spectrum_event.colo.code | IATA airport code of data center that received the request. | keyword |
| cloudflare_logpush.spectrum_event.connect.time | Timestamp at which both legs of the connection (client/edge, edge/origin or nexthop) were established. | date |
| cloudflare_logpush.spectrum_event.disconnect.time | Timestamp at which the connection was closed. | date |
| cloudflare_logpush.spectrum_event.ip_firewall | Whether IP Firewall was enabled at time of connection. | boolean |
| cloudflare_logpush.spectrum_event.origin.bytes | The number of bytes read from the origin by Spectrum. | long |
| cloudflare_logpush.spectrum_event.origin.ip | Origin IP address. | ip |
| cloudflare_logpush.spectrum_event.origin.port | Origin Port. | long |
| cloudflare_logpush.spectrum_event.origin.protocol | Transport protocol used by origin. | keyword |
| cloudflare_logpush.spectrum_event.origin.tcp_rtt | The TCP round-trip time in nanoseconds between Spectrum and the origin. | long |
| cloudflare_logpush.spectrum_event.origin.tls.cipher | The cipher negotiated between Spectrum and the origin. | keyword |
| cloudflare_logpush.spectrum_event.origin.tls.fingerprint | SHA256 hash of origin certificate. | keyword |
| cloudflare_logpush.spectrum_event.origin.tls.mode | If and how the upstream connection is encrypted. | keyword |
| cloudflare_logpush.spectrum_event.origin.tls.protocol | The TLS version negotiated between Spectrum and the origin. | keyword |
| cloudflare_logpush.spectrum_event.origin.tls.status | The state of the TLS session from Spectrum to the origin. | keyword |
| cloudflare_logpush.spectrum_event.proxy.protocol | Which form of proxy protocol is applied to the given connection. | keyword |
| cloudflare_logpush.spectrum_event.status | A code indicating reason for connection closure. | long |
| cloudflare_logpush.spectrum_event.timestamp | Timestamp at which the event took place. | date |
| container.id | Unique container ID. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.bytes | Bytes sent from the destination to the source. | long |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
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
| http.response.status_code | HTTP response status code. | long |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. Learn more at https://github.com/corelight/community-id-spec. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |
| tls.version | Numeric part of the version parsed from the original string. | keyword |
| tls.version_protocol | Normalized lowercase protocol name parsed from original string. | keyword |
