# GuardDuty

## Logs

The `guardduty` dataset collects the findings from AWS GuardDuty. Amazon GuardDuty is a continuous security monitoring service that analyzes and processes the following Data sources: VPC Flow Logs, AWS CloudTrail management event logs, CloudTrail S3 data event logs, and DNS logs. It uses threat intelligence feeds, such as lists of malicious IP addresses and domains, and machine learning to identify unexpected and potentially unauthorized and malicious activity within your AWS environment. This can include issues like escalations of privileges, uses of exposed credentials, or communication with malicious IP addresses, or domains. For example, GuardDuty can detect compromised EC2 instances serving malware or mining bitcoin. It also monitors AWS account access behavior for signs of compromise, such as unauthorized infrastructure deployments, like instances deployed in a Region that has never been used, or unusual API calls, like a password policy change to reduce password strength.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.guardduty.action.affected_resources | List of affected AWS resources | flattened |
| aws.guardduty.action.api | The name of the API operation that was invoked and thus prompted GuardDuty to generate this finding. | keyword |
| aws.guardduty.action.blocked | Indicates whether the targeted port is blocked. | boolean |
| aws.guardduty.action.caller_type |  | keyword |
| aws.guardduty.action.error_code | If the finding was triggered by a failed API call this displays the error code for that call. | keyword |
| aws.guardduty.action.service_name | The DNS name of the service that attempted to make the API call that triggered the finding. | keyword |
| aws.guardduty.action.type | The type of action that triggered the finding | keyword |
| aws.guardduty.archived | Indicates whether this is finding has been archived. | boolean |
| aws.guardduty.arn | AWS ARN of Finding | keyword |
| aws.guardduty.count | The number of times GuardDuty has aggregated an activity matching this pattern to this finding ID. | long |
| aws.guardduty.created_at | the time and date when this finding was first created. If this value differs from Updated at, it indicates that the activity has occurred multiple times and is an ongoing issue. | date |
| aws.guardduty.description |  | keyword |
| aws.guardduty.detector.id | The ID of the GuardDuty Detector | keyword |
| aws.guardduty.first_seen | The first time the event was seen | date |
| aws.guardduty.last_seen | The last time the event was seen | date |
| aws.guardduty.resource.access_key.id | Access key ID of the user engaged in the activity that prompted GuardDuty to generate the finding. | keyword |
| aws.guardduty.resource.access_key.principal.id | The principal ID of the user engaged in the activity that prompted GuardDuty to generate the finding. | keyword |
| aws.guardduty.resource.access_key.user.name | The name of the user engaged in the activity that prompted GuardDuty to generate the finding. | keyword |
| aws.guardduty.resource.access_key.user.type | The type of user engaged in the activity that prompted GuardDuty to generate the finding. For more information, see [CloudTrail userIdentity element](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html#cloudtrail-event-reference-user-identity-fields). | keyword |
| aws.guardduty.resource.instance.iam_instance_profile.arn | The ARN of the IAM profile assigned to the instance | keyword |
| aws.guardduty.resource.instance.iam_instance_profile.id | The ID of the IAM profile assigned to the instance | keyword |
| aws.guardduty.resource.instance.image.description | A description of the ID of the Amazon Machine Image used to build the instance involved in the activity. | keyword |
| aws.guardduty.resource.instance.image.id | The ID of the Amazon Machine Image used to build the instance involved in the activity. | keyword |
| aws.guardduty.resource.instance.launch_time | The time and date the instance was launched. | date |
| aws.guardduty.resource.instance.network_interfaces | Network interface details | nested |
| aws.guardduty.resource.instance.outpost_arn | The Amazon Resource Name (ARN) of the AWS Outposts. Only applicable to AWS Outposts instances. For more information, see [What is AWS Outposts?](https://docs.aws.amazon.com/outposts/latest/userguide/what-is-outposts.html) | keyword |
| aws.guardduty.resource.instance.state | The current state of the targeted instance. | keyword |
| aws.guardduty.resource.instance.tags | A list of tags attached to this resource, listed in the format of key:value. | flattened |
| aws.guardduty.resource.instance.vpc_id | VPC ID | keyword |
| aws.guardduty.resource.role | The role of the AWS resource that triggered the finding. This value can be TARGET or ACTOR, and represents whether your resource was the target of the suspicious activity or the actor that preformed the suspicious activity. | keyword |
| aws.guardduty.resource.type | The type of the affected resource. This value is either AccessKey, S3 bucket or Instance. Depending on the resource type, different finding details are available. Select a resource option tab to learn about the details available for that resource. | keyword |
| aws.guardduty.sample | Indicates whether this is a sample finding | boolean |
| aws.guardduty.title |  | keyword |
| aws.guardduty.type | A formatted string representing the type of activity that triggered the finding. For more information, see [GuardDuty finding format](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-format.html). | keyword |
| aws.guardduty.updated_at | The last time this finding was updated with new activity matching the pattern that prompted GuardDuty to generate this finding. | date |
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
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.address | Some event destination addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| destination.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| dns.question.name | The name being queried. If the name field contains non-printable characters (below 32 or above 126), those characters should be represented as escaped base 10 integers (\DDD). Back slashes and quotes should be escaped. Tabs, carriage returns, and line feeds should be converted to \t, \r, and \n respectively. | keyword |
| dns.question.registered_domain | The highest registered domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| dns.question.subdomain | The subdomain is all of the labels under the registered_domain. If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| dns.question.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
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
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. Learn more at https://github.com/corelight/community-id-spec. | keyword |
| network.direction | Direction of the network traffic. Recommended values are:   \* ingress   \* egress   \* inbound   \* outbound   \* internal   \* external   \* unknown  When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.iana_number | IANA Protocol Number (https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml). Standardized list of protocols. This aligns well with NetFlow and sFlow related logs which use the IANA Protocol Number. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. See the documentation section "Implementing ECS". | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| rule.category | A categorization value keyword used by the entity using the rule for detection of this event. | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| rule.ruleset | Name of the ruleset, policy, group, or parent category in which the rule used to generate this event is a member. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
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
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |


An example event for `guardduty` looks as following:

```json
{
    "@timestamp": "2021-11-25T14:25:25.000Z",
    "data_stream": {
        "namespace": "default",
        "type": "logs",
        "dataset": "aws.waf"
    },
    "rule": {
        "ruleset": "REGULAR",
        "id": "STMTest_SQLi_XSS"
    },
    "source": {
        "geo": {
            "continent_name": "Oceania",
            "country_name": "Australia",
            "location": {
                "lon": 143.2104,
                "lat": -33.494
            },
            "country_iso_code": "AU"
        },
        "as": {
            "number": 13335,
            "organization": {
                "name": "Cloudflare, Inc."
            }
        },
        "ip": "1.1.1.1"
    },
    "tags": [
        "preserve_original_event"
    ],
    "network": {
        "protocol": "http",
        "transport": "tcp"
    },
    "cloud": {
        "region": "ap-southeast-2",
        "provider": "aws",
        "service": {
            "name": "wafv2"
        },
        "account": {
            "id": "12345"
        }
    },
    "ecs": {
        "version": "1.12.0"
    },
    "related": {
        "ip": [
            "1.1.1.1"
        ]
    },
    "http": {
        "request": {
            "method": "POST",
            "id": "null"
        },
        "version": "1.1"
    },
    "event": {
        "action": "BLOCK",
        "ingested": "2021-10-11T15:00:35.544818361Z",
        "original": "{\"timestamp\":1576280412771,\"formatVersion\":1,\"webaclId\":\"arn:aws:wafv2:ap-southeast-2:12345:regional/webacl/test/111\",\"terminatingRuleId\":\"STMTest_SQLi_XSS\",\"terminatingRuleType\":\"REGULAR\",\"action\":\"BLOCK\",\"terminatingRuleMatchDetails\":[{\"conditionType\":\"SQL_INJECTION\",\"location\":\"UNKNOWN\",\"matchedData\":[\"10\",\"AND\",\"1\"]}],\"httpSourceName\":\"ALB\",\"httpSourceId\":\"alb\",\"ruleGroupList\":[],\"rateBasedRuleList\":[],\"nonTerminatingMatchingRules\":[],\"requestHeadersInserted\":null,\"responseCodeSent\":null,\"httpRequest\":{\"clientIp\":\"1.1.1.1\",\"country\":\"AU\",\"headers\":[],\"uri\":\"\",\"args\":\"\",\"httpVersion\":\"HTTP/1.1\",\"httpMethod\":\"POST\",\"requestId\":\"null\"},\"labels\":[{\"name\":\"value\"}]}",
        "category": "web",
        "type": [
            "access",
            "denied"
        ],
        "kind": "event"
    },
    "aws": {
        "waf": {
            "terminating_rule_match_details": [
                {
                    "conditionType": "SQL_INJECTION",
                    "location": "UNKNOWN",
                    "matchedData": [
                        "10",
                        "AND",
                        "1"
                    ]
                }
            ],
            "id": "regional/webacl/test/111",
            "source": {
                "name": "ALB",
                "id": "alb"
            },
            "arn": "arn:aws:wafv2:ap-southeast-2:12345:regional/webacl/test/111"
        }
    }
}
```
