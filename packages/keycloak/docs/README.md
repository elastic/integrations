# Keycloak Integration

The Keycloak integration collects events from the Keycloak log files.

To enable logging of all Keycloak events like logins, user creation/updates/deletions.... add the below 
```
    <logger category="org.keycloak.events">
        <level name="DEBUG"/>
    </logger>
```
to your configuration XML file (ie standalone.xml) under the path below
```
<server>
    <profile>
        <subsystem xmlns="urn:jboss:domain:logging:8.0">
            ....
        </subsystem>
    </profile>
</server>
```
## Logs

### log

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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| group.id | Unique identifier for the group on the system/platform. | keyword |
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
| input.type | Type of Filebeat input. | keyword |
| keycloak.admin.operation | Keycloak admin operation; Add, Update, Delete | keyword |
| keycloak.admin.resource.path | Path to affected resource | keyword |
| keycloak.admin.resource.type | Type of keycloak resource being acted upon; Group, User, Client, Scope... | keyword |
| keycloak.client.id | ID of the Keycloak client | keyword |
| keycloak.event_type | Keycloak event type; Login or Admin | keyword |
| keycloak.login.auth_method | Keycloak authentication method (SAML or OpenID Connect) | keyword |
| keycloak.login.auth_session_parent_id | Parent session ID | keyword |
| keycloak.login.auth_session_tab_id | Session Tab ID | keyword |
| keycloak.login.auth_type | OpenID Connect authentication type (code, implicit...) | keyword |
| keycloak.login.code_id | OpenID Connect Code ID | keyword |
| keycloak.login.redirect_uri | Keycloak redirect URL | keyword |
| keycloak.login.type | Event Type | keyword |
| keycloak.realm.id | Keycloak Realm ID | keyword |
| log.file.path | Path to the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.logger | The name of the logger inside an application. This is usually the name of the class which initialized the logger, or can be a custom name. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| process.thread.name | Thread name. | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.domain | Source domain. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.fragment | Portion of the url after the `#`, such as "top". The `#` is not part of the fragment. | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.path | Path of the request, such as "/search". | wildcard |
| url.port | Port of the request, such as 443. | long |
| url.scheme |  |  |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.target.id | Unique identifier of the user. | keyword |


An example event for `log` looks as following:

```json
{
    "process": {
        "thread": {
            "name": "default task-2"
        }
    },
    "keycloak": {
        "client": {
            "id": "security-admin-console"
        },
        "realm": {
            "id": "test"
        },
        "event_type": "login",
        "login": {
            "auth_method": "openid-connect",
            "auth_type": "code",
            "auth_session_parent_id": "bae6e56e-368f-4809-89f3-48cfb6279f5e",
            "auth_session_tab_id": "Kz_ye2UvP6M",
            "redirect_uri": "https://www.example.com/auth/admin/test/console/#/realms/test/events",
            "type": "LOGIN",
            "code_id": "bae6e56e-368f-4809-89f3-48cfb6279f5e"
        }
    },
    "log": {
        "level": "DEBUG",
        "logger": "org.keycloak.events"
    },
    "source": {
        "address": "10.2.2.156",
        "ip": "10.2.2.156"
    },
    "url": {
        "path": "/auth/admin/test/console/",
        "fragment": "/realms/test/events",
        "original": "https://www.example.com/auth/admin/test/console/#/realms/test/events",
        "scheme": "https",
        "domain": "www.example.com"
    },
    "tags": [
        "preserve_original_event"
    ],
    "@timestamp": "2021-10-22T22:11:31.257-05:00",
    "related": {
        "user": [
            "ce637d23-b89c-4fca-9088-1aea1d053e19"
        ],
        "hosts": [
            "www.example.com"
        ],
        "ip": [
            "10.2.2.156"
        ]
    },
    "event": {
        "ingested": "2021-10-27T01:40:29.824706616Z",
        "original": "2021-10-22 22:11:31,257 DEBUG [org.keycloak.events] (default task-2) type=LOGIN, realmId=test, clientId=security-admin-console, userId=ce637d23-b89c-4fca-9088-1aea1d053e19, ipAddress=10.2.2.156, auth_method=openid-connect, auth_type=code, redirect_uri=https://www.example.com/auth/admin/test/console/#/realms/test/events, consent=no_consent_required, code_id=bae6e56e-368f-4809-89f3-48cfb6279f5e, username=admin, authSessionParentId=bae6e56e-368f-4809-89f3-48cfb6279f5e, authSessionTabId=Kz_ye2UvP6M",
        "timezone": "America/Chicago",
        "kind": "event",
        "action": "LOGIN",
        "category": [
            "authentication"
        ],
        "type": [
            "info",
            "start",
            "allowed"
        ]
    },
    "user": {
        "name": "admin",
        "id": "ce637d23-b89c-4fca-9088-1aea1d053e19"
    }
}
```