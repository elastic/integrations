# Audit

Google Cloud services write audit logs that record administrative activities and accesses within your Google Cloud resources.  
More information on the type of data included in the audit logs can be found in the [documentation](https://cloud.google.com/logging/docs/audit)

## Logs

This is the `audit` dataset.

An example event for `audit` looks as following:

```json
{
    "log": {
        "logger": "projects/foo/logs/cloudaudit.googleapis.com%2Factivity"
    },
    "source": {
        "geo": {
            "continent_name": "Europe",
            "region_iso_code": "RU-MOW",
            "city_name": "Moscow",
            "country_iso_code": "RU",
            "country_name": "Russia",
            "region_name": "Moscow",
            "location": {
                "lon": 37.6172,
                "lat": 55.7527
            }
        },
        "ip": "1.2.3.4"
    },
    "cloud": {
        "project": {
            "id": "foo"
        }
    },
    "@timestamp": "2020-08-05T21:59:26.456Z",
    "ecs": {
        "version": "1.8.0"
    },
    "gcp": {
        "audit": {
            "request": {
                "name": "windows-server-2016-v20200805",
                "proto_name": "type.googleapis.com/compute.images.insert"
            },
            "authentication_info": {
                "principal_email": "user@mycompany.com"
            },
            "method_name": "v1.compute.images.insert",
            "request_metadata": {
                "caller_ip": "1.2.3.4",
                "caller_supplied_user_agent": "google-cloud-sdk gcloud/290.0.1 command/gcloud.compute.images.create invocation-id/032752ad0fa44b4ea951951d2deef6a3 environment/None environment-version/None interactive/True from-script/False python/2.7.17 term/xterm-256color (Macintosh; Intel Mac OS X 19.6.0),gzip(gfe)"
            },
            "response": {
                "proto_name": "type.googleapis.com/operation",
                "status": {
                    "value": "RUNNING"
                }
            },
            "service_name": "compute.googleapis.com",
            "type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "authorization_info": [
                {
                    "resource_attributes": {
                        "name": "projects/foo/global/images/windows-server-2016-v20200805",
                        "type": "compute.images",
                        "service": "compute"
                    },
                    "permission": "compute.images.create",
                    "granted": true
                }
            ],
            "resource_name": "projects/foo/global/images/windows-server-2016-v20200805",
            "resource_location": {
                "current_locations": [
                    "eu"
                ]
            }
        }
    },
    "service": {
        "name": "compute.googleapis.com"
    },
    "event": {
        "action": "v1.compute.images.insert",
        "ingested": "2021-02-19T09:19:47.732239800Z",
        "original": "{\"insertId\":\"v2spcwdzmc2\",\"logName\":\"projects/foo/logs/cloudaudit.googleapis.com%2Factivity\",\"operation\":{\"first\":true,\"id\":\"operation-1596664766354-5ac287c395484-fa3923bd-543e018e\",\"producer\":\"compute.googleapis.com\"},\"protoPayload\":{\"@type\":\"type.googleapis.com/google.cloud.audit.AuditLog\",\"authenticationInfo\":{\"principalEmail\":\"user@mycompany.com\"},\"authorizationInfo\":[{\"granted\":true,\"permission\":\"compute.images.create\",\"resourceAttributes\":{\"name\":\"projects/foo/global/images/windows-server-2016-v20200805\",\"service\":\"compute\",\"type\":\"compute.images\"}}],\"methodName\":\"v1.compute.images.insert\",\"request\":{\"@type\":\"type.googleapis.com/compute.images.insert\",\"family\":\"windows-server-2016\",\"guestOsFeatures\":[{\"type\":\"VIRTIO_SCSI_MULTIQUEUE\"},{\"type\":\"WINDOWS\"}],\"name\":\"windows-server-2016-v20200805\",\"rawDisk\":{\"source\":\"https://storage.googleapis.com/storage/v1/b/foo/o/windows-server-2016-v20200805.tar.gz\"},\"sourceType\":\"RAW\"},\"requestMetadata\":{\"callerIp\":\"1.2.3.4\",\"callerSuppliedUserAgent\":\"google-cloud-sdk gcloud/290.0.1 command/gcloud.compute.images.create invocation-id/032752ad0fa44b4ea951951d2deef6a3 environment/None environment-version/None interactive/True from-script/False python/2.7.17 term/xterm-256color (Macintosh; Intel Mac OS X 19.6.0),gzip(gfe)\",\"destinationAttributes\":{},\"requestAttributes\":{\"auth\":{},\"time\":\"2020-08-05T21:59:27.515Z\"}},\"resourceLocation\":{\"currentLocations\":[\"eu\"]},\"resourceName\":\"projects/foo/global/images/windows-server-2016-v20200805\",\"response\":{\"@type\":\"type.googleapis.com/operation\",\"id\":\"44919313\",\"insertTime\":\"2020-08-05T14:59:27.259-07:00\",\"name\":\"operation-1596664766354-5ac287c395484-fa3923bd-543e018e\",\"operationType\":\"insert\",\"progress\":\"0\",\"selfLink\":\"https://www.googleapis.com/compute/v1/projects/foo/global/operations/operation-1596664766354-5ac287c395484-fa3923bd-543e018e\",\"selfLinkWithId\":\"https://www.googleapis.com/compute/v1/projects/foo/global/operations/4491931805423146320\",\"startTime\":\"2020-08-05T14:59:27.274-07:00\",\"status\":\"RUNNING\",\"targetId\":\"12345\",\"targetLink\":\"https://www.googleapis.com/compute/v1/projects/foo/global/images/windows-server-2016-v20200805\",\"user\":\"user@mycompany.com\"},\"serviceName\":\"compute.googleapis.com\"},\"receiveTimestamp\":\"2020-08-05T21:59:27.822546978Z\",\"resource\":{\"labels\":{\"image_id\":\"771879043\",\"project_id\":\"foo\"},\"type\":\"gce_image\"},\"severity\":\"NOTICE\",\"timestamp\":\"2020-08-05T21:59:26.456Z\"}",
        "id": "v2spcwdzmc2",
        "kind": "event",
        "outcome": "success"
    },
    "user": {
        "email": "user@mycompany.com"
    },
    "user_agent": {
        "name": "Other",
        "original": "google-cloud-sdk gcloud/290.0.1 command/gcloud.compute.images.create invocation-id/032752ad0fa44b4ea951951d2deef6a3 environment/None environment-version/None interactive/True from-script/False python/2.7.17 term/xterm-256color (Macintosh; Intel Mac OS X 19.6.0),gzip(gfe)",
        "os": {
            "name": "Mac OS X",
            "version": "19.6.0",
            "full": "Mac OS X 19.6.0"
        },
        "device": {
            "name": "Mac"
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
| container.runtime | Runtime managing this container. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.module | Event module | constant_keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| gcp.audit.authentication_info.authority_selector | The authority selector specified by the requestor, if any. It is not guaranteed  that the principal was allowed to use this authority. | keyword |
| gcp.audit.authentication_info.principal_email | The email address of the authenticated user making the request. | keyword |
| gcp.audit.authorization_info.granted | Whether or not authorization for resource and permission was granted. | boolean |
| gcp.audit.authorization_info.permission | The required IAM permission. | keyword |
| gcp.audit.authorization_info.resource_attributes.name | The name of the resource. | keyword |
| gcp.audit.authorization_info.resource_attributes.service | The name of the service. | keyword |
| gcp.audit.authorization_info.resource_attributes.type | The type of the resource. | keyword |
| gcp.audit.method_name | The name of the service method or operation. For API calls, this  should be the name of the API method.  For example, 'google.datastore.v1.Datastore.RunQuery'. | keyword |
| gcp.audit.num_response_items | The number of items returned from a List or Query API method, if applicable. | long |
| gcp.audit.request.filter | Filter of the request. | keyword |
| gcp.audit.request.name | Name of the request. | keyword |
| gcp.audit.request.proto_name | Type property of the request. | keyword |
| gcp.audit.request.resource_name | Name of the request resource. | keyword |
| gcp.audit.request_metadata.caller_ip | The IP address of the caller. | ip |
| gcp.audit.request_metadata.caller_supplied_user_agent | The user agent of the caller. This information is not authenticated and  should be treated accordingly. | keyword |
| gcp.audit.resource_location.current_locations | Current locations of the resource. | keyword |
| gcp.audit.resource_name | The resource or collection that is the target of the operation.  The name is a scheme-less URI, not including the API service name.  For example, 'shelves/SHELF_ID/books'. | keyword |
| gcp.audit.response.details.group | The name of the group. | keyword |
| gcp.audit.response.details.kind | The kind of the response details. | keyword |
| gcp.audit.response.details.name | The name of the response details. | keyword |
| gcp.audit.response.details.uid | The uid of the response details. | keyword |
| gcp.audit.response.proto_name | Type property of the response. | keyword |
| gcp.audit.response.status.allowed |  | boolean |
| gcp.audit.response.status.reason |  | keyword |
| gcp.audit.response.status.value |  | keyword |
| gcp.audit.service_name | The name of the API service performing the operation.  For example, datastore.googleapis.com. | keyword |
| gcp.audit.status.code | The status code, which should be an enum value of google.rpc.Code. | integer |
| gcp.audit.status.message | A developer-facing error message, which should be in English. Any user-facing  error message should be localized and sent in the google.rpc.Status.details  field, or localized by the client. | keyword |
| gcp.audit.type | Type property. | keyword |
| gcp.destination.instance.project_id | ID of the project containing the VM. | keyword |
| gcp.destination.instance.region | Region of the VM. | keyword |
| gcp.destination.instance.zone | Zone of the VM. | keyword |
| gcp.destination.vpc.project_id | ID of the project containing the VM. | keyword |
| gcp.destination.vpc.subnetwork_name | Subnetwork on which the VM is operating. | keyword |
| gcp.destination.vpc.vpc_name | VPC on which the VM is operating. | keyword |
| gcp.source.instance.project_id | ID of the project containing the VM. | keyword |
| gcp.source.instance.region | Region of the VM. | keyword |
| gcp.source.instance.zone | Zone of the VM. | keyword |
| gcp.source.vpc.project_id | ID of the project containing the VM. | keyword |
| gcp.source.vpc.subnetwork_name | Subnetwork on which the VM is operating. | keyword |
| gcp.source.vpc.vpc_name | VPC on which the VM is operating. | keyword |
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
| input.type | Input type | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.logger | The name of the logger inside an application. This is usually the name of the class which initialized the logger, or can be a custom name. | keyword |
| log.offset | Log offset | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| orchestrator.api_version | API version being used to carry out the action | keyword |
| orchestrator.cluster.name | Name of the cluster. | keyword |
| orchestrator.cluster.url | URL of the API used to manage the cluster. | keyword |
| orchestrator.cluster.version | The version of the cluster. | keyword |
| orchestrator.namespace | Namespace in which the action is taking place. | keyword |
| orchestrator.organization | Organization affected by the event (for multi-tenant orchestrator setups). | keyword |
| orchestrator.resource.name | Name of the resource being acted upon. | keyword |
| orchestrator.resource.type | Type of resource being acted upon. | keyword |
| orchestrator.type | Orchestrator cluster type (e.g. kubernetes, nomad or cloudfoundry). | keyword |
| service.name | Name of the service data is collected from. The name of the service is normally user given. This allows for distributed services that run on multiple hosts to correlate the related instances based on the name. In the case of Elasticsearch the `service.name` could contain the cluster name. For Beats the `service.name` is by default a copy of the `service.type` field if no name is specified. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
| user.email | User email address. | keyword |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.kernel | Operating system kernel version as a raw string. | keyword |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |
