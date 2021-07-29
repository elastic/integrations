# ZeroFox Cloud Platform Integration

The ZeroFox Platform integration collects and parses data from the the ZeroFox Alert APIs.

## Compatibility

This integration supports the ZeroFox API v1.0

### ZeroFox

Contains alert data received from the ZeroFox Cloud Platform

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | text |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` < `event.created` < `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.url | URL linking to an external system to continue investigation of this event. This URL links to another system where in-depth investigation of the specific occurrence of this event can take place. Alert events, indicated by `event.kind:alert`, are a common use case for this field. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| network.name | Name given by operators to sections of their network. | keyword |
| rule.category | A categorization value keyword used by the entity using the rule for detection of this event. | keyword |
| rule.id | A rule ID that is unique within the scope of an agent, observer, or other entity using the rule for detection of this event. | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| rule.ruleset | Name of the ruleset, policy, group, or parent category in which the rule used to generate this event is a member. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.roles | Array of user roles at the time of the event. | keyword |
| zerofox.content_actions |  | keyword |
| zerofox.darkweb_term |  | keyword |
| zerofox.entity.entity_group.id | The entity group identifier. | integer |
| zerofox.entity.entity_group.name | The entity group name. | keyword |
| zerofox.entity.id | The entity identifier. | keyword |
| zerofox.entity.image | The entity default image url. | keyword |
| zerofox.entity.labels.id | The entity label identifier | keyword |
| zerofox.entity.labels.name | The entity label text | keyword |
| zerofox.entity.name | The entity name. | keyword |
| zerofox.entity_account |  | keyword |
| zerofox.entity_term.deleted |  | boolean |
| zerofox.entity_term.id |  | keyword |
| zerofox.entity_term.name |  | keyword |
| zerofox.escalated |  | boolean |
| zerofox.last_modified |  | date |
| zerofox.metadata |  | flattened |
| zerofox.notes |  | text |
| zerofox.perpetrator.account_number |  | keyword |
| zerofox.perpetrator.content |  | keyword |
| zerofox.perpetrator.destination_account_number |  | keyword |
| zerofox.perpetrator.display_name |  | keyword |
| zerofox.perpetrator.id |  | keyword |
| zerofox.perpetrator.image |  | keyword |
| zerofox.perpetrator.name |  | keyword |
| zerofox.perpetrator.network |  | keyword |
| zerofox.perpetrator.parent_post_account_number |  | keyword |
| zerofox.perpetrator.parent_post_number |  | keyword |
| zerofox.perpetrator.parent_post_url |  | keyword |
| zerofox.perpetrator.post_number |  | keyword |
| zerofox.perpetrator.post_type |  | keyword |
| zerofox.perpetrator.timestamp |  | keyword |
| zerofox.perpetrator.type |  | keyword |
| zerofox.perpetrator.url |  | keyword |
| zerofox.perpetrator.username |  | keyword |
| zerofox.protected_account |  | keyword |
| zerofox.protected_locations |  | keyword |
| zerofox.protected_social_object |  | keyword |
| zerofox.reviewed |  | boolean |
| zerofox.reviews |  | keyword |
| zerofox.status |  | keyword |
| zerofox.tags |  | keyword |
