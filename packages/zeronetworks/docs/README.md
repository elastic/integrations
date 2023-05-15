# Zero Networks Integration

[Zero Networks](https://www.zeronetworks.com) is used by numerous orgazations to microsegment the network and apply MFA anywhere.

The **Zero Networks** integration uses Zero Networks' API to retrieve audit events and ingest them into Elasticsearch. This allows you to search, observe, and visualize the **Zero Networks** audit events through Elasticsearch.

The Elastic agent running this integration interacts with Zero Networks' infrastructure using their APIs to retrieve audit logs for an environment.

## Data streams

The **Zero Networks** integration collects one type of data streams: logs.

**Logs** help you keep a record of events happening in **Zero Networks**.
Log data streams collected by the **Zero Networks** integration include Audit events. 

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Other requirements including:
 - Zero Networks API Token with Read access

## Setup

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.


### Get an API Token

1. Log into the [Zero Networks portal](https://portal.zeronetworks.com).
2. Click **Setting**.
3. Click **API** under **Integrations**.
4. Click **Add new token**.
5. Enter a **Token Name** such as *Elastic Integration*. Set the **Expiry** to ** 36 Months**.  Click **Add**.
6. Copy the generated token for later use.

### Enabling the integration in Elastic

1. In Kibana go to **Management > Integrations**.
2. In the **"Search for integrations"** search bar type **Zero Networks**.
3. Click on **"Zero Networks"** integration from the search results.
4. Click on **Add Zero Networks** button to add the Zero Networks integration.

### Configure Zero Networks Audit logs data stream

Enter values **"API Token"**.

1. **API Token** copied from earlier steps.

***NOTE:*** Some operating systems may not have the root CA installed.  You can download the **[USERTrust RSA Certification Authority](https://ssl-tools.net/subjects/cd30d24c343a82ab1f0570158ad7a107762992e9)** and install it. As a work around, not recommended, you can set **verification_mode: none** in the **SSL** box under **Settings** by clicking **Advanced Options**.

## Logs reference

### Audt

The `Audit` data stream provides events from Zero Networks of the following types: audit.

#### Example

An example event for `audit` looks as following:

```json
{
	"@timestamp": [
		"2023-03-22T14:57:23.356Z"
	],
	"agent.ephemeral_id": [
		"01887fa8-409b-44a1-aa70-fa9cc4f2fd90"
	],
	"agent.id": [
		"55518990-e6d4-4350-b447-88837a15d1d2"
	],
	"agent.name": [
		"docker-fleet-agent"
	],
	"agent.type": [
		"filebeat"
	],
	"agent.version": [
		"8.6.2"
	],
	"data_stream.dataset": [
		"zeronetworks.audit"
	],
	"data_stream.namespace": [
		"default"
	],
	"data_stream.type": [
		"logs"
	],
	"ecs.version": [
		"8.0.0"
	],
	"elastic_agent.id": [
		"55518990-e6d4-4350-b447-88837a15d1d2"
	],
	"elastic_agent.snapshot": [
		false
	],
	"elastic_agent.version": [
		"8.6.2"
	],
	"event.action": [
		"API Token created"
	],
	"event.agent_id_status": [
		"verified"
	],
	"event.category": [
		"configuration"
	],
	"event.code": [
		"25"
	],
	"event.created": [
		"2023-03-24T14:45:14.459Z"
	],
	"event.dataset": [
		"zeronetworks.audit"
	],
	"event.id": [
		"+Ipxg6VvICbeFz5QoqS1i3GZETE="
	],
	"event.ingested": [
		"2023-03-24T14:45:15.000Z"
	],
	"event.kind": [
		"event"
	],
	"event.module": [
		"zeronetworks"
	],
	"event.original": [
		"{\"auditType\":25,\"destinationEntitiesList\":[{\"id\":\"m:6454ff4dd25ebda5279fd4823e5e1d026e2ae996\",\"name\":\"elastic\"}],\"details\":\"{\\\"name\\\":\\\"elastic\\\",\\\"clientId\\\":\\\"m:6454ff4dd25ebda5279fd4823e5e1d026e2ae996\\\",\\\"expiry\\\":\\\"2025-03-22T14:57:23.000Z\\\",\\\"issuedAt\\\":\\\"2023-03-22T14:57:23.000Z\\\",\\\"scope\\\":5,\\\"audience\\\":\\\"portal.zeronetworks.com\\\",\\\"issuer\\\":\\\"zeronetworks.com/api/v1/access-token\\\",\\\"type\\\":\\\"JWT\\\"}\",\"enforcementSource\":4,\"isoTimestamp\":\"2023-03-22T14:57:23.356Z\",\"parentObjectId\":\"\",\"performedBy\":{\"id\":\"39cc28f6-7bba-4310-95e6-a7e7189a3ed5\",\"name\":\"Nicholas DiCola\"},\"reportedObjectId\":\"m:6454ff4dd25ebda5279fd4823e5e1d026e2ae996\",\"timestamp\":1679497043356,\"userRole\":1}"
	],
	"event.outcome": [
		"success"
	],
	"event.type": [
		"info"
	],
	"input.type": [
		"httpjson"
	],
	"related.user": [
		"39cc28f6-7bba-4310-95e6-a7e7189a3ed5",
		"Nicholas DiCola"
	],
	"tags": [
		"forwarded",
		"zeronetworks-audit",
		"preserve_original_event"
	],
	"user.full_name": [
		"Nicholas DiCola"
	],
	"user.id": [
		"39cc28f6-7bba-4310-95e6-a7e7189a3ed5"
	],
	"zeronetworks.audit.destinationEntitiesList.id": [
		"m:6454ff4dd25ebda5279fd4823e5e1d026e2ae996"
	],
	"zeronetworks.audit.destinationEntitiesList.name": [
		"elastic"
	],
	"zeronetworks.audit.details.audience": [
		"portal.zeronetworks.com"
	],
	"zeronetworks.audit.details.clientId": [
		"m:6454ff4dd25ebda5279fd4823e5e1d026e2ae996"
	],
	"zeronetworks.audit.details.expiry": [
		"2025-03-22T14:57:23.000Z"
	],
	"zeronetworks.audit.details.issuedAt": [
		"2023-03-22T14:57:23.000Z"
	],
	"zeronetworks.audit.details.issuer": [
		"zeronetworks.com/api/v1/access-token"
	],
	"zeronetworks.audit.details.name": [
		"elastic"
	],
	"zeronetworks.audit.details.scope": [
		5
	],
	"zeronetworks.audit.details.type": [
		"JWT"
	],
	"zeronetworks.audit.enforcementSource": [
		4
	],
	"zeronetworks.audit.reportedObjectId": [
		"m:6454ff4dd25ebda5279fd4823e5e1d026e2ae996"
	],
	"zeronetworks.audit.userRole": [
		1
	]
}
```

#### Exported fields

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | The cloud project identifier. Examples: Google Cloud Project id, Azure Project id. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host, resource, or service is located. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.code | The audity type captured by the event| integer |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | Event creation time | date |
| event.dataset | Event dataset | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host MAC addresses. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Type of Filebeat input. | keyword |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| zeronetworks.audit.destinationEntitiesList.id | The `id` of the affected entity | keyword |
| zeronetworks.audit.destinationEntitiesList.name | The `name` of the affected entity | keyword |
| zeronetworks.audit.details.* | Various fields for properties of the audit `details`. Varies by audit type. | keyword |
| zeronetworks.audit.enforcementsource | The `platform` of the audit event | integer |
| zeronetworks.audit.userrole | The `user role` of the user performing the action | integer |
| zeronetworks.audit.userrolename | The `user role` of the user performing the action | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.full_name | User's full name, if available. | keyword |
| user.id | Unique identifier of the user. | keyword |
