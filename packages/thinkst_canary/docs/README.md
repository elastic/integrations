# Thinkst Canary Integration

This integration is for [Thinkst Canary](https://docs.canary.tools/). It currently supports [incident](https://docs.canary.tools/incidents/queries.html) and [audit](https://docs.canary.tools/console/audit-trail.html) logs exposed by the Thinkst Canary API.

## Setup

Blurb

## Compatibility

The `ingest-geoip` and `ingest-user_agent` Elasticsearch plugins are required to run this module.

## Logs

### Audit

Blurb

An example event for `audit` looks as following:

```json
{
    "@timestamp": "2020-04-02T13:11:27.000Z",
    "agent": {
        "ephemeral_id": "df56a661-626d-4ea6-8e71-30dea2261ab5",
        "id": "cebf2bb2-41e9-4a97-a212-38ca4f391f46",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.0"
    },
    "data_stream": {
        "dataset": "thinkst_canary.audit",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "cebf2bb2-41e9-4a97-a212-38ca4f391f46",
        "snapshot": false,
        "version": "8.12.0"
    },
    "event": {
        "action": "device_schedule_reboot",
        "agent_id_status": "verified",
        "category": [
            "configuration"
        ],
        "dataset": "thinkst_canary.audit",
        "ingested": "2024-03-25T23:55:22Z",
        "kind": [
            "event"
        ],
        "original": "{\"action_type\":\"device_schedule_reboot\",\"additional_information\":null,\"flock_id\":\"flock:default\",\"id\":69,\"message\":\"User 'API Token' scheduled the device \\u003cdevice_id\\u003e to be rebooted\",\"timestamp\":\"2020-04-02 13:11:27 UTC+0000\",\"user\":\"admin@company.com\",\"user_browser_agent\":\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36\",\"user_browser_language\":\"\",\"user_ip\":\"81.2.69.144\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "ip": [
            "81.2.69.144"
        ],
        "user": [
            "admin@company.com"
        ]
    },
    "source": {
        "address": "81.2.69.144",
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
        "ip": "81.2.69.144"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "thinkst_canary"
    ],
    "thinkst_canary": {
        "audit": {
            "action_type": "device_schedule_reboot",
            "flock_id": "flock:default",
            "id": "69",
            "message": "User 'API Token' scheduled the device <device_id> to be rebooted",
            "timestamp": "2020-04-02 13:11:27 UTC+0000",
            "user": "admin@company.com",
            "user_browser_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36",
            "user_ip": "81.2.69.144"
        }
    },
    "user": {
        "email": "admin@company.com",
        "id": "admin@company.com"
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
| destination.address | Some event destination addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| destination.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.as.organization.name.text | Multi-field of `destination.as.organization.name`. | match_only_text |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Type of Filebeat input. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |
| thinkst_canary.audit.action_type |  | keyword |
| thinkst_canary.audit.additional_information |  | flattened |
| thinkst_canary.audit.flock_id |  | keyword |
| thinkst_canary.audit.id |  | keyword |
| thinkst_canary.audit.message |  | keyword |
| thinkst_canary.audit.timestamp |  | keyword |
| thinkst_canary.audit.user |  | keyword |
| thinkst_canary.audit.user_browser_agent |  | keyword |
| thinkst_canary.audit.user_browser_language |  | keyword |
| thinkst_canary.audit.user_ip |  | keyword |
| user.email | User email address. | keyword |
| user.id | Unique identifier of the user. | keyword |
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


### Incident

Blurb

An example event for `incident` looks as following:

```json
{
    "@timestamp": "2020-04-07T08:53:43.000Z",
    "agent": {
        "ephemeral_id": "825d78e8-3307-4982-96ae-c7aec4c7c8cb",
        "id": "92a6344a-9a61-4aaa-8755-5b1491e5a70d",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.0"
    },
    "data_stream": {
        "dataset": "thinkst_canary.incident",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "address": "81.2.69.144",
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
        "ip": "81.2.69.144",
        "port": 80
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "92a6344a-9a61-4aaa-8755-5b1491e5a70d",
        "snapshot": false,
        "version": "8.12.0"
    },
    "event": {
        "action": "Canarytoken triggered",
        "agent_id_status": "verified",
        "category": [
            "intrusion_detection"
        ],
        "dataset": "thinkst_canary.incident",
        "ingested": "2024-03-25T23:07:32Z",
        "kind": [
            "alert",
            "event"
        ],
        "original": "{\"description\":{\"acknowledged\":\"False\",\"created\":\"1586249623\",\"created_std\":\"2020-04-07 08:53:43 UTC+0000\",\"description\":\"Canarytoken triggered\",\"dst_host\":\"81.2.69.144\",\"dst_port\":\"80\",\"events\":[{\"canarytoken\":\"\\u003ctoken_code\\u003e\",\"dst_port\":80,\"event_name\":\"\",\"headers\":{\"Accept\":\"*/*\",\"Accept-Encoding\":\"gzip, deflate\",\"Connection\":\"close\",\"User-Agent\":\"\"},\"src_host\":\"\",\"timestamp\":1586249623,\"timestamp_std\":\"2020-04-07 08:53:43 UTC+0000\",\"type\":\"aws-id\"}],\"events_count\":\"1\",\"local_time\":\"2020-04-07 08:53:43 (UTC)\",\"logtype\":\"17012\",\"memo\":\"Example Memo\",\"name\":\"N/A\",\"node_id\":\"\\u003cnode_id\\u003e\",\"notified\":\"False\",\"src_host\":\"216.160.83.56\",\"src_port\":\"0\"},\"feed\":\"All Incidents\",\"hash_id\":\"\\u003chash_id\\u003e\",\"id\":\"\\u003cincident_key\\u003e\",\"max_updated_id\":10,\"summary\":\"Canarytoken triggered\",\"updated\":\"Tue, 07 Apr 2020 08:53:43 GMT\",\"updated_id\":10,\"updated_std\":\"2020-04-07 08:53:43 UTC+0000\",\"updated_time\":\"1586249623\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "ip": [
            "216.160.83.56",
            "81.2.69.144"
        ]
    },
    "source": {
        "address": "216.160.83.56",
        "as": {
            "number": 209
        },
        "geo": {
            "city_name": "Milton",
            "continent_name": "North America",
            "country_iso_code": "US",
            "country_name": "United States",
            "location": {
                "lat": 47.2513,
                "lon": -122.3149
            },
            "region_iso_code": "US-WA",
            "region_name": "Washington"
        },
        "ip": "216.160.83.56",
        "port": 0
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "thinkst_canary"
    ],
    "thinkst_canary": {
        "incident": {
            "description": {
                "acknowledged": "False",
                "created": "1586249623",
                "created_std": "2020-04-07 08:53:43 UTC+0000",
                "description": "Canarytoken triggered",
                "dst_host": "81.2.69.144",
                "dst_port": "80",
                "events": [
                    {
                        "canarytoken": "<token_code>",
                        "dst_port": 80,
                        "headers": {
                            "Accept": "*/*",
                            "Accept-Encoding": "gzip, deflate",
                            "Connection": "close"
                        },
                        "timestamp": 1586249623,
                        "timestamp_std": "2020-04-07 08:53:43 UTC+0000",
                        "type": "aws-id"
                    }
                ],
                "events_count": "1",
                "local_time": "2020-04-07 08:53:43 (UTC)",
                "logtype": "17012",
                "memo": "Example Memo",
                "name": "N/A",
                "node_id": "<node_id>",
                "notified": "False",
                "src_host": "216.160.83.56",
                "src_port": "0"
            },
            "feed": "All Incidents",
            "hash_id": "<hash_id>",
            "id": "<incident_key>",
            "max_updated_id": "10",
            "summary": "Canarytoken triggered",
            "updated": "Tue, 07 Apr 2020 08:53:43 GMT",
            "updated_id": "10",
            "updated_std": "2020-04-07 08:53:43 UTC+0000",
            "updated_time": "1586249623"
        }
    }
}
```

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
| destination.address | Some event destination addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| destination.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.as.organization.name.text | Multi-field of `destination.as.organization.name`. | match_only_text |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Type of Filebeat input. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |
| thinkst_canary.incident.description.acknowledged |  | keyword |
| thinkst_canary.incident.description.created |  | keyword |
| thinkst_canary.incident.description.created_std |  | keyword |
| thinkst_canary.incident.description.description |  | keyword |
| thinkst_canary.incident.description.dst_host |  | keyword |
| thinkst_canary.incident.description.dst_port |  | keyword |
| thinkst_canary.incident.description.events |  | flattened |
| thinkst_canary.incident.description.events_count |  | keyword |
| thinkst_canary.incident.description.local_time |  | keyword |
| thinkst_canary.incident.description.logtype |  | keyword |
| thinkst_canary.incident.description.memo |  | keyword |
| thinkst_canary.incident.description.name |  | keyword |
| thinkst_canary.incident.description.node_id |  | keyword |
| thinkst_canary.incident.description.notified |  | keyword |
| thinkst_canary.incident.description.src_host |  | keyword |
| thinkst_canary.incident.description.src_port |  | keyword |
| thinkst_canary.incident.feed |  | keyword |
| thinkst_canary.incident.hash_id |  | keyword |
| thinkst_canary.incident.id |  | keyword |
| thinkst_canary.incident.max_updated_id |  | keyword |
| thinkst_canary.incident.summary |  | keyword |
| thinkst_canary.incident.updated |  | keyword |
| thinkst_canary.incident.updated_id |  | keyword |
| thinkst_canary.incident.updated_std |  | keyword |
| thinkst_canary.incident.updated_time |  | keyword |

