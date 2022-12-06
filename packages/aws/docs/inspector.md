# Inspector

The [AWS Inspector](https://docs.aws.amazon.com/inspector/) integration collects and parses data from AWS Inspector [Findings](https://docs.aws.amazon.com/inspector/v2/APIReference/API_ListFindings.html) REST APIs.

## Compatibility

  1. The minimum compatible version of this module is **Elastic Agent 8.4.0**.
  2. This module is tested against `AWS Inspector API version 2.0`.

## To collect data from AWS Inspector API, users must have an Access Key and a Secret Key. To create API token follow below steps:

  1. Login to https://console.aws.amazon.com/.
  2. Go to https://console.aws.amazon.com/iam/ to access the IAM console.
  3. On the navigation menu, choose Users.
  4. Choose your IAM user name.
  5. Select Create access key from the Security Credentials tab.
  6. To see the new access key, choose Show.

## Note

  - For the current integration package, it is compulsory to add Secret Access Key and Access Key ID.

## Logs

### Inspector

This is the [`Inspector`](https://docs.aws.amazon.com/inspector/v2/APIReference/API_ListFindings.html#inspector2-ListFindings-response-findings) data stream.

An example event for `inspector` looks as following:

```json
{
    "@timestamp": "2022-09-20T19:52:26.405Z",
    "agent": {
        "ephemeral_id": "d1032859-fd44-410c-9960-dde7dcbc3a2e",
        "id": "4a3373c9-b63f-4544-a929-761b42f50054",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.4.0"
    },
    "aws": {
        "inspector": {
            "finding_arn": "arn:aws:s3:::sample",
            "first_observed_at": "2022-09-20T19:52:26.405Z",
            "inspector_score": 1.2,
            "inspector_score_details": {
                "adjusted_cvss": {
                    "adjustments": [
                        {
                            "metric": "Base",
                            "reason": "use Base metric"
                        }
                    ],
                    "cvss_source": "scope1",
                    "score": {
                        "source": "scope2",
                        "value": 8.9
                    },
                    "scoring_vector": "Attack Vector",
                    "version": "v3.1"
                }
            },
            "last_observed_at": "2022-09-20T19:52:26.405Z",
            "network_reachability_details": {
                "network_path": {
                    "steps": [
                        {
                            "component": {
                                "id": "02ce3860-3126-42af-8ac7-c2a661134129",
                                "type": "type"
                            }
                        }
                    ]
                },
                "open_port_range": {
                    "begin": 1234,
                    "end": 4567
                }
            },
            "package_vulnerability_details": {
                "cvss": [
                    {
                        "scoring_vector": "Attack Vector",
                        "source": "scope3"
                    }
                ],
                "related_vulnerabilities": [
                    "security"
                ],
                "source": {
                    "url": {
                        "domain": "cve.mitre.org",
                        "extension": "cgi",
                        "original": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-6111",
                        "path": "/cgi-bin/cvename.cgi",
                        "query": "name=CVE-2019-6111",
                        "scheme": "https"
                    },
                    "value": "example"
                },
                "vendor": {
                    "created_at": "2022-09-20T19:52:26.405Z",
                    "updated_at": "2022-09-20T19:52:26.405Z"
                },
                "vulnerable_packages": [
                    {
                        "arch": "arch",
                        "epoch": 123,
                        "file_path": "/example",
                        "fixed_inversion": "3",
                        "name": "example",
                        "package_manager": "BUNDLER",
                        "release": "release",
                        "source_layer_hash": "50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c",
                        "version": "2.0"
                    }
                ]
            },
            "remediation": {
                "recommendation": {
                    "text": "example",
                    "url": {
                        "domain": "cve.mitre.org",
                        "extension": "cgi",
                        "original": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-6111",
                        "path": "/cgi-bin/cvename.cgi",
                        "query": "name=CVE-2019-6111",
                        "scheme": "https"
                    }
                }
            },
            "resources": [
                {
                    "details": {
                        "aws": {
                            "ec2_instance": {
                                "iam_instance_profile_arn": "arn:aws:s3:::iam",
                                "image_id": "123456789",
                                "ipv4_addresses": [
                                    "89.160.20.128",
                                    "81.2.69.192"
                                ],
                                "ipv6_addresses": [
                                    "2a02:cf40::"
                                ],
                                "key_name": "sample",
                                "launched_at": "2022-09-20T19:52:26.405Z",
                                "platform": "EC2",
                                "subnet_id": "123456",
                                "type": "Instance",
                                "vpc_id": "3265875"
                            },
                            "ecr_container_image": {
                                "architecture": "arch",
                                "author": "example",
                                "image": {
                                    "hash": "50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545d",
                                    "tags": [
                                        "sample"
                                    ]
                                },
                                "platform": "ECR",
                                "pushed_at": "2022-09-20T19:52:26.405Z",
                                "registry": "ecr registry",
                                "repository_name": "sample"
                            }
                        }
                    },
                    "id": "12345678",
                    "partition": "partition",
                    "tags": {
                        "string1": "string1",
                        "string2": "string2"
                    },
                    "type": "AWS_EC2_INSTANCE"
                }
            ],
            "severity": "INFORMATIONAL",
            "status": "ACTIVE",
            "title": "sample findings",
            "type": "NETWORK_REACHABILITY"
        }
    },
    "cloud": {
        "account": {
            "id": "123456789"
        },
        "region": [
            "us-east-1"
        ]
    },
    "data_stream": {
        "dataset": "aws.inspector",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.2.0"
    },
    "elastic_agent": {
        "id": "4a3373c9-b63f-4544-a929-761b42f50054",
        "snapshot": false,
        "version": "8.4.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2022-11-17T13:05:04.253Z",
        "dataset": "aws.inspector",
        "ingested": "2022-11-17T13:05:07Z",
        "kind": "event",
        "original": "{\"awsAccountId\":\"123456789\",\"description\":\"Findins message\",\"findingArn\":\"arn:aws:s3:::sample\",\"firstObservedAt\":\"1.663703546405E9\",\"inspectorScore\":1.2,\"inspectorScoreDetails\":{\"adjustedCvss\":{\"adjustments\":[{\"metric\":\"Base\",\"reason\":\"use Base metric\"}],\"cvssSource\":\"scope1\",\"score\":8.9,\"scoreSource\":\"scope2\",\"scoringVector\":\"Attack Vector\",\"version\":\"v3.1\"}},\"lastObservedAt\":\"1.663703546405E9\",\"networkReachabilityDetails\":{\"networkPath\":{\"steps\":[{\"componentId\":\"02ce3860-3126-42af-8ac7-c2a661134129\",\"componentType\":\"type\"}]},\"openPortRange\":{\"begin\":1234,\"end\":4567},\"protocol\":\"TCP\"},\"packageVulnerabilityDetails\":{\"cvss\":[{\"baseScore\":1.1,\"scoringVector\":\"Attack Vector\",\"source\":\"scope3\",\"version\":\"v3.1\"}],\"referenceUrls\":[\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-6111\"],\"relatedVulnerabilities\":[\"security\"],\"source\":\"example\",\"sourceUrl\":\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-6111\",\"vendorCreatedAt\":\"1.663703546405E9\",\"vendorSeverity\":\"basic\",\"vendorUpdatedAt\":\"1.663703546405E9\",\"vulnerabilityId\":\"123456789\",\"vulnerablePackages\":[{\"arch\":\"arch\",\"epoch\":123,\"filePath\":\"/example\",\"fixedInVersion\":\"3\",\"name\":\"example\",\"packageManager\":\"BUNDLER\",\"release\":\"release\",\"sourceLayerHash\":\"50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c\",\"version\":\"2.0\"}]},\"remediation\":{\"recommendation\":{\"Url\":\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-6111\",\"text\":\"example\"}},\"resources\":[{\"details\":{\"awsEc2Instance\":{\"iamInstanceProfileArn\":\"arn:aws:s3:::iam\",\"imageId\":\"123456789\",\"ipV4Addresses\":[\"89.160.20.128\",\"81.2.69.192\"],\"ipV6Addresses\":[\"2a02:cf40::\"],\"keyName\":\"sample\",\"launchedAt\":\"1.663703546405E9\",\"platform\":\"EC2\",\"subnetId\":\"123456\",\"type\":\"Instance\",\"vpcId\":\"3265875\"},\"awsEcrContainerImage\":{\"architecture\":\"arch\",\"author\":\"example\",\"imageHash\":\"50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545d\",\"imageTags\":[\"sample\"],\"platform\":\"ECR\",\"pushedAt\":\"1.663703546405E9\",\"registry\":\"ecr registry\",\"repositoryName\":\"sample\"}},\"id\":\"12345678\",\"partition\":\"partition\",\"region\":\"us-east-1\",\"tags\":{\"string1\":\"string1\",\"string2\":\"string2\"},\"type\":\"AWS_EC2_INSTANCE\"}],\"severity\":\"INFORMATIONAL\",\"status\":\"ACTIVE\",\"title\":\"sample findings\",\"type\":\"NETWORK_REACHABILITY\",\"updatedAt\":\"1.663703546405E9\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "message": "Findins message",
    "network": {
        "transport": "tcp"
    },
    "related": {
        "hash": [
            "50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c",
            "50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545d"
        ],
        "ip": [
            "89.160.20.128",
            "81.2.69.192",
            "2a02:cf40::"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "aws-inspector"
    ],
    "vulnerability": {
        "id": "123456789",
        "reference": [
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-6111"
        ],
        "score": {
            "base": [
                1.1
            ],
            "version": [
                "v3.1"
            ]
        },
        "severity": "basic"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.inspector.aws_account_id | The AWS account ID associated with the finding. | keyword |
| aws.inspector.description | The description of the finding. | text |
| aws.inspector.finding_arn | The Amazon Resource Number (ARN) of the finding. | keyword |
| aws.inspector.first_observed_at | The date and time that the finding was first observed. | date |
| aws.inspector.fix_available | Details on whether a fix is available through a version update. This value can be YES, NO, or PARTIAL. A PARTIAL fix means that some, but not all, of the packages identified in the finding have fixes available through updated versions. | keyword |
| aws.inspector.inspector_score | The Amazon Inspector score given to the finding. | double |
| aws.inspector.inspector_score_details.adjusted_cvss.adjustments.metric | The metric used to adjust the CVSS score. | keyword |
| aws.inspector.inspector_score_details.adjusted_cvss.adjustments.reason | The reason the CVSS score has been adjustment. | keyword |
| aws.inspector.inspector_score_details.adjusted_cvss.cvss_source | The source of the CVSS data. | keyword |
| aws.inspector.inspector_score_details.adjusted_cvss.score.source | The source for the CVSS score. | keyword |
| aws.inspector.inspector_score_details.adjusted_cvss.score.value | The CVSS score. | double |
| aws.inspector.inspector_score_details.adjusted_cvss.scoring_vector | The vector for the CVSS score. | keyword |
| aws.inspector.inspector_score_details.adjusted_cvss.version | The CVSS version used in scoring. | keyword |
| aws.inspector.last_observed_at | The date and time that the finding was last observed. | date |
| aws.inspector.network_reachability_details.network_path.steps.component.id | The component ID. | keyword |
| aws.inspector.network_reachability_details.network_path.steps.component.type | The component type. | keyword |
| aws.inspector.network_reachability_details.open_port_range.begin | The beginning port in a port range. | long |
| aws.inspector.network_reachability_details.open_port_range.end | The ending port in a port range. | long |
| aws.inspector.network_reachability_details.protocol | The protocol associated with a finding. | keyword |
| aws.inspector.package_vulnerability_details.cvss.base_score | The base CVSS score used for the finding. | double |
| aws.inspector.package_vulnerability_details.cvss.scoring_vector | The vector string of the CVSS score. | keyword |
| aws.inspector.package_vulnerability_details.cvss.source | The source of the CVSS score. | keyword |
| aws.inspector.package_vulnerability_details.cvss.version | The version of CVSS used for the score. | keyword |
| aws.inspector.package_vulnerability_details.reference_urls | One or more URLs that contain details about this vulnerability type. | keyword |
| aws.inspector.package_vulnerability_details.related_vulnerabilities | One or more vulnerabilities related to the one identified in this finding. | keyword |
| aws.inspector.package_vulnerability_details.source.url.domain | A domain to the source url of the vulnerability information. | keyword |
| aws.inspector.package_vulnerability_details.source.url.extension | A extension to the source url of the vulnerability information. | keyword |
| aws.inspector.package_vulnerability_details.source.url.original | A original to the source url of the vulnerability information. | keyword |
| aws.inspector.package_vulnerability_details.source.url.path | A path to the source url of the vulnerability information. | keyword |
| aws.inspector.package_vulnerability_details.source.url.query | A query to the source url of the vulnerability information. | keyword |
| aws.inspector.package_vulnerability_details.source.url.scheme | A scheme to the source url of the vulnerability information. | keyword |
| aws.inspector.package_vulnerability_details.source.value | The source of the vulnerability information. | keyword |
| aws.inspector.package_vulnerability_details.vendor.created_at | The date and time that this vulnerability was first added to the vendor's database. | date |
| aws.inspector.package_vulnerability_details.vendor.severity | The severity the vendor has given to this vulnerability type. | keyword |
| aws.inspector.package_vulnerability_details.vendor.updated_at | The date and time the vendor last updated this vulnerability in their database. | date |
| aws.inspector.package_vulnerability_details.vulnerability_id | The ID given to this vulnerability. | keyword |
| aws.inspector.package_vulnerability_details.vulnerable_packages.arch | The architecture of the vulnerable package. | keyword |
| aws.inspector.package_vulnerability_details.vulnerable_packages.epoch | The epoch of the vulnerable package. | long |
| aws.inspector.package_vulnerability_details.vulnerable_packages.file_path | The file path of the vulnerable package. | keyword |
| aws.inspector.package_vulnerability_details.vulnerable_packages.fixed_inversion | The version of the package that contains the vulnerability fix. | keyword |
| aws.inspector.package_vulnerability_details.vulnerable_packages.name | The name of the vulnerable package. | keyword |
| aws.inspector.package_vulnerability_details.vulnerable_packages.package_manager | The package manager of the vulnerable package. | keyword |
| aws.inspector.package_vulnerability_details.vulnerable_packages.release | The release of the vulnerable package. | keyword |
| aws.inspector.package_vulnerability_details.vulnerable_packages.source_layer_hash | The source layer hash of the vulnerable package. | keyword |
| aws.inspector.package_vulnerability_details.vulnerable_packages.version | The version of the vulnerable package. | keyword |
| aws.inspector.remediation.recommendation.text | The recommended course of action to remediate the finding. | keyword |
| aws.inspector.remediation.recommendation.url.domain | The domain to the CVE remediation url recommendations. | keyword |
| aws.inspector.remediation.recommendation.url.extension | The extension to the CVE remediation url recommendations. | keyword |
| aws.inspector.remediation.recommendation.url.original | The original to the CVE remediation url recommendations. | keyword |
| aws.inspector.remediation.recommendation.url.path | The path to the CVE remediation url recommendations. | keyword |
| aws.inspector.remediation.recommendation.url.query | The query to the CVE remediation url recommendations. | keyword |
| aws.inspector.remediation.recommendation.url.scheme | The scheme to the CVE remediation url recommendations. | keyword |
| aws.inspector.resources.details.aws.ec2_instance.iam_instance_profile_arn | The IAM instance profile ARN of the Amazon EC2 instance. | keyword |
| aws.inspector.resources.details.aws.ec2_instance.image_id | The image ID of the Amazon EC2 instance. | keyword |
| aws.inspector.resources.details.aws.ec2_instance.ipv4_addresses | The IPv4 addresses of the Amazon EC2 instance. | ip |
| aws.inspector.resources.details.aws.ec2_instance.ipv6_addresses | The IPv6 addresses of the Amazon EC2 instance. | ip |
| aws.inspector.resources.details.aws.ec2_instance.key_name | The name of the key pair used to launch the Amazon EC2 instance. | keyword |
| aws.inspector.resources.details.aws.ec2_instance.launched_at | The date and time the Amazon EC2 instance was launched at. | date |
| aws.inspector.resources.details.aws.ec2_instance.platform | The platform of the Amazon EC2 instance. | keyword |
| aws.inspector.resources.details.aws.ec2_instance.subnet_id | The subnet ID of the Amazon EC2 instance. | keyword |
| aws.inspector.resources.details.aws.ec2_instance.type | The type of the Amazon EC2 instance. | keyword |
| aws.inspector.resources.details.aws.ec2_instance.vpc_id | The VPC ID of the Amazon EC2 instance. | keyword |
| aws.inspector.resources.details.aws.ecr_container_image.architecture | The architecture of the Amazon ECR container image. | keyword |
| aws.inspector.resources.details.aws.ecr_container_image.author | The image author of the Amazon ECR container image. | keyword |
| aws.inspector.resources.details.aws.ecr_container_image.image.hash | The image hash of the Amazon ECR container image. | keyword |
| aws.inspector.resources.details.aws.ecr_container_image.image.tags | The image tags attached to the Amazon ECR container image. | keyword |
| aws.inspector.resources.details.aws.ecr_container_image.platform | The platform of the Amazon ECR container image. | keyword |
| aws.inspector.resources.details.aws.ecr_container_image.pushed_at | The date and time the Amazon ECR container image was pushed. | date |
| aws.inspector.resources.details.aws.ecr_container_image.registry | The registry the Amazon ECR container image belongs to. | keyword |
| aws.inspector.resources.details.aws.ecr_container_image.repository_name | The name of the repository the Amazon ECR container image resides in. | keyword |
| aws.inspector.resources.id | The ID of the resource. | keyword |
| aws.inspector.resources.partition | The partition of the resource. | keyword |
| aws.inspector.resources.region | The AWS Region the impacted resource is located in. | keyword |
| aws.inspector.resources.tags | The tags attached to the resource. | flattened |
| aws.inspector.resources.type | The type of resource. | keyword |
| aws.inspector.severity | The severity of the finding. | keyword |
| aws.inspector.status | The status of the finding. | keyword |
| aws.inspector.title | The title of the finding. | keyword |
| aws.inspector.type | The type of the finding. | keyword |
| aws.inspector.updated_at | The date and time the finding was last updated at. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.account.name | The cloud account name or alias used to identify different entities in a multi-tenant environment. Examples: AWS account name, Google Cloud ORG display name. | keyword |
| cloud.availability_zone | Availability zone in which this host, resource, or service is located. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
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
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
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
| host.os.name.text | Multi-field of `host.os.name`. | match_only_text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| tags | List of keywords used to tag each event. | keyword |
| vulnerability.id | The identification (ID) is the number portion of a vulnerability entry. It includes a unique identification number for the vulnerability. For example (https://cve.mitre.org/about/faqs.html#what_is_cve_id)[Common Vulnerabilities and Exposure CVE ID] | keyword |
| vulnerability.reference | A resource that provides additional information, context, and mitigations for the identified vulnerability. | keyword |
| vulnerability.score.base | Scores can range from 0.0 to 10.0, with 10.0 being the most severe. Base scores cover an assessment for exploitability metrics (attack vector, complexity, privileges, and user interaction), impact metrics (confidentiality, integrity, and availability), and scope. For example (https://www.first.org/cvss/specification-document) | float |
| vulnerability.score.version | The National Vulnerability Database (NVD) provides qualitative severity rankings of "Low", "Medium", and "High" for CVSS v2.0 base score ranges in addition to the severity ratings for CVSS v3.0 as they are defined in the CVSS v3.0 specification. CVSS is owned and managed by FIRST.Org, Inc. (FIRST), a US-based non-profit organization, whose mission is to help computer security incident response teams across the world. For example (https://nvd.nist.gov/vuln-metrics/cvss) | keyword |
| vulnerability.severity | The severity of the vulnerability can help with metrics and internal prioritization regarding remediation. For example (https://nvd.nist.gov/vuln-metrics/cvss) | keyword |
