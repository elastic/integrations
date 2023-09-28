# GuardDuty

## Overview

The [Amazon GuardDuty](https://aws.amazon.com/guardduty/) integration collects and parses data from Amazon GuardDuty [Findings](https://docs.aws.amazon.com/guardduty/latest/APIReference/API_GetFindings.html) REST APIs.

The Amazon GuardDuty integration can be used in three different modes to collect data:
- HTTP REST API - Amazon GuardDuty pushes logs directly to an HTTP REST API.
- AWS S3 polling - Amazon GuardDuty writes data to S3 and Elastic Agent polls the S3 bucket by listing its contents and reading new files.
- AWS S3 SQS - Amazon GuardDuty writes data to S3, S3 pushes a new object notification to SQS, Elastic Agent receives the notification from SQS, and then reads the S3 object. Multiple Agents can be used in this mode.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

**Note**: It is recommended to use AWS SQS for Amazon GuardDuty.

## Compatibility

  1. The minimum compatible version of this module is **Elastic Agent 8.6.0**.

  2. Following GuardDuty Resource types have been supported in the current integration version:

     | Sr. No. | Resource types       |
     |---------|----------------------|
     |    1    | accessKeyDetails     |
     |    2    | containerDetails     |
     |    3    | ebsVolumeDetails     |
     |    4    | ecsClusterDetails    |
     |    5    | eksClusterDetails    |
     |    6    | instanceDetails      |
     |    7    | kubernetesDetails    |
     |    8    | s3BucketDetails      |
     |    9    | rdsDbInstanceDetails |
     |   10    | rdsDbUserDetails     |

  3. Following GuardDuty Service action types have been supported in the current integration version:

     | Sr. No. | Service action types     |
     |---------|--------------------------|
     |    1    | awsApiCallAction         |
     |    2    | dnsRequestAction         |
     |    3    | kubernetesApiCallAction  |
     |    4    | networkConnectionAction  |
     |    5    | portProbeAction          |
     |    6    | rdsLoginAttemptAction    |

## Setup

### To collect data from AWS S3 Bucket, follow the steps below:
- Configure the [Data Forwarder](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_exportfindings.html) to ingest data into an AWS S3 bucket. However, the user can set the parameter "Bucket List Prefix" according to the requirement.

### To collect data from AWS SQS, follow the steps below:
1. If data forwarding to an AWS S3 bucket hasn't been configured, then first setup an AWS S3 bucket as mentioned in the documentation above.
2. To setup an SQS queue, follow "Step 1: Create an Amazon SQS queue" mentioned in the [Documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ways-to-add-notification-config-to-bucket.html).
  - While creating an SQS queue, please provide the same bucket ARN that has been generated after creating the AWS S3 bucket.
3. Setup event notification for an S3 bucket. Follow this [guide](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-event-notifications.html).
  - The user has to perform Step 3 for the guardduty data-stream, and the prefix parameter should be set the same as the S3 Bucket List Prefix as created earlier. For example, `logs/` for guardduty data stream.
  - For all the event notifications that have been created, select the event type as s3:ObjectCreated:*, select the destination type SQS Queue, and select the queue that has been created in Step 2.

**Note**:
  - Credentials for the above AWS S3 and SQS input types should be configured according to the [input configuration guide](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html#aws-credentials-config).
  - Data collection via AWS S3 Bucket and AWS SQS are mutually exclusive in this case.

### To collect data from Amazon GuardDuty API, users must have an Access Key and a Secret Key. To create an API token follow the steps below:

  1. Login to https://console.aws.amazon.com/.
  2. Go to https://console.aws.amazon.com/iam/ to access the IAM console.
  3. On the navigation menu, choose Users.
  4. Choose your IAM user name.
  5. Select Create access key from the Security Credentials tab.
  6. To see the new access key, choose Show.

## Note

  - The Secret Access Key and Access Key ID are required for the current integration package.

## Logs

### GuardDuty

This is the [`GuardDuty`](https://docs.aws.amazon.com/guardduty/latest/APIReference/API_GetFindings.html#guardduty-GetFindings-response-findings) data stream.

An example event for `guardduty` looks as following:

```json
{
    "@timestamp": "2022-11-22T12:22:20.938Z",
    "agent": {
        "ephemeral_id": "869cd846-8c49-4002-94b9-891ba6f9cd85",
        "id": "a7b5ed34-8788-4a63-9ec2-cfb7e7c091d3",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.6.0"
    },
    "aws": {
        "guardduty": {
            "account_id": "123412341234",
            "arn": "arn:aws:guardduty:us-east-1:123412341234:detector/12341234e19ce5461eabcd1234abcd1234/finding/43b6abcdeabcdeabcde1234562176924",
            "created_at": "2022-11-17T09:33:19.228Z",
            "description": "Kubernetes API commonly used in Discovery tactics was invoked on cluster GeneratedFindingEKSClusterName from Tor exit node IP address 175.16.199.1.",
            "id": "e0c22973b012f3af67ac593443e920ff",
            "partition": "aws",
            "region": "us-east-1",
            "resource": {
                "access_key_details": {
                    "accesskey_id": "GeneratedFindingAccessKeyId",
                    "principal_id": "GeneratedFindingPrincipalId",
                    "user": {
                        "name": "GeneratedFindingUserName",
                        "type": "Role"
                    }
                },
                "eks_cluster_details": {
                    "arn": "GeneratedFindingEKSClusterArn",
                    "created_at": "2021-11-03T18:00:10.342Z",
                    "name": "GeneratedFindingEKSClusterName",
                    "status": "ACTIVE",
                    "tags": [
                        {
                            "key": "GeneratedFindingEKSClusterTag1",
                            "value": "GeneratedFindingEKSClusterTagValue1"
                        },
                        {
                            "key": "GeneratedFindingEKSClusterTag2",
                            "value": "GeneratedFindingEKSClusterTagValue2"
                        },
                        {
                            "key": "GeneratedFindingEKSClusterTag3",
                            "value": "GeneratedFindingEKSClusterTagValue3"
                        }
                    ],
                    "vpcid": "GeneratedFindingEKSClusterVpcId"
                },
                "kubernetes_details": {
                    "kubernetes_user_details": {
                        "groups": [
                            "GeneratedFindingUserGroup"
                        ],
                        "uid": "GeneratedFindingUID",
                        "user_name": "GeneratedFindingUserName"
                    }
                },
                "type": "EKSCluster"
            },
            "schema_version": "2.0",
            "service": {
                "action": {
                    "kubernetes_api_call_action": {
                        "remote_ip_details": {
                            "city": {
                                "name": "GeneratedFindingCityName"
                            },
                            "country": {
                                "name": "GeneratedFindingCountryName"
                            },
                            "geo_location": {
                                "lat": 0,
                                "lon": 0
                            },
                            "ip_address_v4": "175.16.199.1",
                            "organization": {
                                "asn": "0",
                                "asnorg": "GeneratedFindingASNOrg",
                                "isp": "GeneratedFindingISP",
                                "org": "GeneratedFindingORG"
                            }
                        },
                        "request_uri": "GeneratedFindingRequestURI",
                        "source_ips": [
                            "175.16.199.1"
                        ],
                        "status_code": 200,
                        "verb": "list"
                    },
                    "type": "KUBERNETES_API_CALL"
                },
                "additional_info": {
                    "sample": true,
                    "threatListName": "GeneratedFindingThreatListName",
                    "threatName": "GeneratedFindingThreatName",
                    "type": "default",
                    "value": "{\"threatName\":\"GeneratedFindingThreatName\",\"threatListName\":\"GeneratedFindingThreatListName\",\"sample\":true}"
                },
                "archived": false,
                "count": 2,
                "detector_id": "12341234e19ce5461eabcd1234abcd1234",
                "event": {
                    "first_seen": "2022-11-17T09:33:19.000Z",
                    "last_seen": "2022-11-22T12:22:20.000Z"
                },
                "evidence": {
                    "threat_intelligence_details": [
                        {
                            "threat": {
                                "list_name": "GeneratedFindingThreatListName",
                                "names": [
                                    "GeneratedFindingThreatName"
                                ]
                            }
                        }
                    ]
                },
                "resource_role": "TARGET",
                "service_name": "guardduty"
            },
            "severity": {
                "code": 5,
                "value": "Medium"
            },
            "title": "Kubernetes API commonly used in Discovery tactics invoked from a Tor exit node IP address.",
            "type": "Discovery:Kubernetes/TorIPCaller",
            "updated_at": "2022-11-22T12:22:20.938Z"
        }
    },
    "cloud": {
        "account": {
            "id": "123412341234"
        },
        "provider": "aws",
        "region": "us-east-1",
        "service": {
            "name": "guardduty"
        }
    },
    "data_stream": {
        "dataset": "aws.guardduty",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.2.0"
    },
    "elastic_agent": {
        "id": "a7b5ed34-8788-4a63-9ec2-cfb7e7c091d3",
        "snapshot": false,
        "version": "8.6.0"
    },
    "event": {
        "action": "KUBERNETES_API_CALL",
        "agent_id_status": "verified",
        "created": "2022-11-17T09:33:19.228Z",
        "dataset": "aws.guardduty",
        "end": "2022-11-22T12:22:20.000Z",
        "id": "e0c22973b012f3af67ac593443e920ff",
        "ingested": "2023-01-18T05:29:38Z",
        "kind": [
            "event"
        ],
        "original": "{\"accountId\":\"123412341234\",\"arn\":\"arn:aws:guardduty:us-east-1:123412341234:detector/12341234e19ce5461eabcd1234abcd1234/finding/43b6abcdeabcdeabcde1234562176924\",\"createdAt\":\"2022-11-17T09:33:19.228Z\",\"description\":\"Kubernetes API commonly used in Discovery tactics was invoked on cluster GeneratedFindingEKSClusterName from Tor exit node IP address 175.16.199.1.\",\"id\":\"e0c22973b012f3af67ac593443e920ff\",\"partition\":\"aws\",\"region\":\"us-east-1\",\"resource\":{\"accessKeyDetails\":{\"accessKeyId\":\"GeneratedFindingAccessKeyId\",\"principalId\":\"GeneratedFindingPrincipalId\",\"userName\":\"GeneratedFindingUserName\",\"userType\":\"Role\"},\"eksClusterDetails\":{\"arn\":\"GeneratedFindingEKSClusterArn\",\"createdAt\":1635962410.342,\"name\":\"GeneratedFindingEKSClusterName\",\"status\":\"ACTIVE\",\"tags\":[{\"key\":\"GeneratedFindingEKSClusterTag1\",\"value\":\"GeneratedFindingEKSClusterTagValue1\"},{\"key\":\"GeneratedFindingEKSClusterTag2\",\"value\":\"GeneratedFindingEKSClusterTagValue2\"},{\"key\":\"GeneratedFindingEKSClusterTag3\",\"value\":\"GeneratedFindingEKSClusterTagValue3\"}],\"vpcId\":\"GeneratedFindingEKSClusterVpcId\"},\"kubernetesDetails\":{\"kubernetesUserDetails\":{\"groups\":[\"GeneratedFindingUserGroup\"],\"uid\":\"GeneratedFindingUID\",\"username\":\"GeneratedFindingUserName\"},\"kubernetesWorkloadDetails\":null},\"resourceType\":\"EKSCluster\"},\"schemaVersion\":\"2.0\",\"service\":{\"action\":{\"actionType\":\"KUBERNETES_API_CALL\",\"kubernetesApiCallAction\":{\"remoteIpDetails\":{\"city\":{\"cityName\":\"GeneratedFindingCityName\"},\"country\":{\"countryName\":\"GeneratedFindingCountryName\"},\"geoLocation\":{\"lat\":0,\"lon\":0},\"ipAddressV4\":\"175.16.199.1\",\"organization\":{\"asn\":\"0\",\"asnOrg\":\"GeneratedFindingASNOrg\",\"isp\":\"GeneratedFindingISP\",\"org\":\"GeneratedFindingORG\"}},\"requestUri\":\"GeneratedFindingRequestURI\",\"sourceIPs\":[\"175.16.199.1\"],\"statusCode\":200,\"userAgent\":\"\",\"verb\":\"list\"}},\"additionalInfo\":{\"sample\":true,\"threatListName\":\"GeneratedFindingThreatListName\",\"threatName\":\"GeneratedFindingThreatName\",\"type\":\"default\",\"value\":\"{\\\"threatName\\\":\\\"GeneratedFindingThreatName\\\",\\\"threatListName\\\":\\\"GeneratedFindingThreatListName\\\",\\\"sample\\\":true}\"},\"archived\":false,\"count\":2,\"detectorId\":\"12341234e19ce5461eabcd1234abcd1234\",\"eventFirstSeen\":\"2022-11-17T09:33:19.000Z\",\"eventLastSeen\":\"2022-11-22T12:22:20.000Z\",\"evidence\":{\"threatIntelligenceDetails\":[{\"threatListName\":\"GeneratedFindingThreatListName\",\"threatNames\":[\"GeneratedFindingThreatName\"]}]},\"resourceRole\":\"TARGET\",\"serviceName\":\"guardduty\"},\"severity\":5,\"title\":\"Kubernetes API commonly used in Discovery tactics invoked from a Tor exit node IP address.\",\"type\":\"Discovery:Kubernetes/TorIPCaller\",\"updatedAt\":\"2022-11-22T12:22:20.938Z\"}",
        "severity": 5,
        "start": "2022-11-17T09:33:19.000Z",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "message": "Kubernetes API commonly used in Discovery tactics was invoked on cluster GeneratedFindingEKSClusterName from Tor exit node IP address 175.16.199.1.",
    "related": {
        "ip": [
            "175.16.199.1"
        ],
        "user": [
            "GeneratedFindingPrincipalId",
            "GeneratedFindingUserName",
            "GeneratedFindingUID"
        ]
    },
    "rule": {
        "category": "Discovery",
        "name": "Discovery:Kubernetes/TorIPCaller",
        "ruleset": "Discovery:Kubernetes"
    },
    "source": {
        "address": [
            "175.16.199.1"
        ],
        "as": {
            "number": [
                0
            ],
            "organization": {
                "name": [
                    "GeneratedFindingASNOrg"
                ]
            }
        },
        "geo": {
            "city_name": [
                "GeneratedFindingCityName"
            ],
            "country_name": [
                "GeneratedFindingCountryName"
            ],
            "location": [
                {
                    "lat": 0,
                    "lon": 0
                }
            ]
        },
        "ip": [
            "175.16.199.1"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "aws-guardduty"
    ],
    "user": {
        "id": [
            "GeneratedFindingPrincipalId",
            "GeneratedFindingUID"
        ],
        "name": [
            "GeneratedFindingUserName"
        ],
        "roles": [
            "GeneratedFindingUserGroup"
        ]
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.guardduty.account_id | The ID of the account in which the finding was generated. | keyword |
| aws.guardduty.arn | The ARN of the finding. | keyword |
| aws.guardduty.confidence | The confidence score for the finding. | double |
| aws.guardduty.created_at | The time and date when the finding was created. | date |
| aws.guardduty.description | The description of the finding. | text |
| aws.guardduty.id | The ID of the finding. | keyword |
| aws.guardduty.partition | The partition associated with the finding. | keyword |
| aws.guardduty.region | The Region where the finding was generated. | keyword |
| aws.guardduty.resource.access_key_details.accesskey_id | The access key ID of the user. | keyword |
| aws.guardduty.resource.access_key_details.principal_id | The principal ID of the user. | keyword |
| aws.guardduty.resource.access_key_details.user.name | The name of the user. | keyword |
| aws.guardduty.resource.access_key_details.user.type | The type of the user. | keyword |
| aws.guardduty.resource.container_details.container_runtime | The container runtime (such as, Docker or containerd) used to run the container. | keyword |
| aws.guardduty.resource.container_details.id | Container ID. | keyword |
| aws.guardduty.resource.container_details.image.prefix | Part of the image name before the last slash. For example, imagePrefix for public.ecr.aws/amazonlinux/amazonlinux:latest would be public.ecr.aws/amazonlinux. If the image name is relative and does not have a slash, this field is empty. | keyword |
| aws.guardduty.resource.container_details.image.value | Container image. | keyword |
| aws.guardduty.resource.container_details.name | Container name. | keyword |
| aws.guardduty.resource.container_details.security_context.privileged | Whether the container is privileged. | boolean |
| aws.guardduty.resource.container_details.volume_mounts.mount_path | Volume mount path. | keyword |
| aws.guardduty.resource.container_details.volume_mounts.name | Volume mount name. | keyword |
| aws.guardduty.resource.ebs_volume_details.scanned_volume_details.device_name | The device name for the EBS volume. | keyword |
| aws.guardduty.resource.ebs_volume_details.scanned_volume_details.encryption_type | EBS volume encryption type. | keyword |
| aws.guardduty.resource.ebs_volume_details.scanned_volume_details.kmskey_arn | KMS key Arn used to encrypt the EBS volume. | keyword |
| aws.guardduty.resource.ebs_volume_details.scanned_volume_details.snapshot_arn | Snapshot Arn of the EBS volume. | keyword |
| aws.guardduty.resource.ebs_volume_details.scanned_volume_details.volume.arn | EBS volume Arn information. | keyword |
| aws.guardduty.resource.ebs_volume_details.scanned_volume_details.volume.size_in_gb | EBS volume size in GB. | long |
| aws.guardduty.resource.ebs_volume_details.scanned_volume_details.volume.type | The EBS volume type. | keyword |
| aws.guardduty.resource.ebs_volume_details.skipped_volume_details.device_name | The device name for the EBS volume. | keyword |
| aws.guardduty.resource.ebs_volume_details.skipped_volume_details.encryption_type | EBS volume encryption type. | keyword |
| aws.guardduty.resource.ebs_volume_details.skipped_volume_details.kmskey_arn | KMS key Arn used to encrypt the EBS volume. | keyword |
| aws.guardduty.resource.ebs_volume_details.skipped_volume_details.snapshot_arn | Snapshot Arn of the EBS volume. | keyword |
| aws.guardduty.resource.ebs_volume_details.skipped_volume_details.volume.arn | EBS volume Arn information. | keyword |
| aws.guardduty.resource.ebs_volume_details.skipped_volume_details.volume.size_in_gb | EBS volume size in GB. | long |
| aws.guardduty.resource.ebs_volume_details.skipped_volume_details.volume.type | The EBS volume type. | keyword |
| aws.guardduty.resource.ecs_cluster_details.active_services_count | The number of services that are running on the cluster in an ACTIVE state. | long |
| aws.guardduty.resource.ecs_cluster_details.arn | The Amazon Resource Name (ARN) that identifies the cluster. | keyword |
| aws.guardduty.resource.ecs_cluster_details.name | The name of the ECS Cluster. | keyword |
| aws.guardduty.resource.ecs_cluster_details.registered_container_instances_count | The number of container instances registered into the cluster. | long |
| aws.guardduty.resource.ecs_cluster_details.running_tasks_count | The number of tasks in the cluster that are in the RUNNING state. | long |
| aws.guardduty.resource.ecs_cluster_details.status | The status of the ECS cluster. | keyword |
| aws.guardduty.resource.ecs_cluster_details.tags.key | The EC2 instance tag key. | keyword |
| aws.guardduty.resource.ecs_cluster_details.tags.value | The EC2 instance tag value. | keyword |
| aws.guardduty.resource.ecs_cluster_details.task_details.arn | The Amazon Resource Name (ARN) of the task. | keyword |
| aws.guardduty.resource.ecs_cluster_details.task_details.containers.container_runtime | The container runtime (such as, Docker or containerd) used to run the container. | keyword |
| aws.guardduty.resource.ecs_cluster_details.task_details.containers.id | Container ID. | keyword |
| aws.guardduty.resource.ecs_cluster_details.task_details.containers.image.prefix | Part of the image name before the last slash. For example, imagePrefix for public.ecr.aws/amazonlinux/amazonlinux:latest would be public.ecr.aws/amazonlinux. If the image name is relative and does not have a slash, this field is empty. | keyword |
| aws.guardduty.resource.ecs_cluster_details.task_details.containers.image.value | Container image. | keyword |
| aws.guardduty.resource.ecs_cluster_details.task_details.containers.name | Container name. | keyword |
| aws.guardduty.resource.ecs_cluster_details.task_details.containers.security_context.privileged | Whether the container is privileged. | boolean |
| aws.guardduty.resource.ecs_cluster_details.task_details.containers.volume_mounts.mount_path | Volume mount path. | keyword |
| aws.guardduty.resource.ecs_cluster_details.task_details.containers.volume_mounts.name | Volume mount name. | keyword |
| aws.guardduty.resource.ecs_cluster_details.task_details.created_at | The Unix timestamp for the time when the task was created. | date |
| aws.guardduty.resource.ecs_cluster_details.task_details.definitionarn | The ARN of the task definition that creates the task. | keyword |
| aws.guardduty.resource.ecs_cluster_details.task_details.group | The name of the task group that's associated with the task. | keyword |
| aws.guardduty.resource.ecs_cluster_details.task_details.started_at | The Unix timestamp for the time when the task started. | date |
| aws.guardduty.resource.ecs_cluster_details.task_details.started_by | Contains the tag specified when a task is started. | keyword |
| aws.guardduty.resource.ecs_cluster_details.task_details.tags.key | The EC2 instance tag key. | keyword |
| aws.guardduty.resource.ecs_cluster_details.task_details.tags.value | The EC2 instance tag value. | keyword |
| aws.guardduty.resource.ecs_cluster_details.task_details.version | The version counter for the task. | keyword |
| aws.guardduty.resource.ecs_cluster_details.task_details.volumes.host_path.path | Path of the file or directory on the host that the volume maps to. | keyword |
| aws.guardduty.resource.ecs_cluster_details.task_details.volumes.name | Volume name. | keyword |
| aws.guardduty.resource.eks_cluster_details.arn | EKS cluster ARN. | keyword |
| aws.guardduty.resource.eks_cluster_details.created_at | The timestamp when the EKS cluster was created. | date |
| aws.guardduty.resource.eks_cluster_details.name | EKS cluster name. | keyword |
| aws.guardduty.resource.eks_cluster_details.status | The EKS cluster status. | keyword |
| aws.guardduty.resource.eks_cluster_details.tags.key | The EC2 instance tag key. | keyword |
| aws.guardduty.resource.eks_cluster_details.tags.value | The EC2 instance tag value. | keyword |
| aws.guardduty.resource.eks_cluster_details.vpcid | The VPC ID to which the EKS cluster is attached. | keyword |
| aws.guardduty.resource.instance_details.availability_zone | The Availability Zone of the EC2 instance. | keyword |
| aws.guardduty.resource.instance_details.iaminstance_profile.arn | The profile ARN of the EC2 instance. | keyword |
| aws.guardduty.resource.instance_details.iaminstance_profile.id | The profile ID of the EC2 instance. | keyword |
| aws.guardduty.resource.instance_details.image.description | The image description of the EC2 instance. | keyword |
| aws.guardduty.resource.instance_details.image.id | The image ID of the EC2 instance. | keyword |
| aws.guardduty.resource.instance_details.instance.id | The ID of the EC2 instance. | keyword |
| aws.guardduty.resource.instance_details.instance.state | The state of the EC2 instance. | keyword |
| aws.guardduty.resource.instance_details.instance.type | The type of the EC2 instance. | keyword |
| aws.guardduty.resource.instance_details.launch_time | The launch time of the EC2 instance. | date |
| aws.guardduty.resource.instance_details.network_interfaces.ipv6_addresses | A list of IPv6 addresses for the EC2 instance. | ip |
| aws.guardduty.resource.instance_details.network_interfaces.network_interface_id | The ID of the network interface. | keyword |
| aws.guardduty.resource.instance_details.network_interfaces.private.dns_name | The private DNS name of the EC2 instance. | keyword |
| aws.guardduty.resource.instance_details.network_interfaces.private.ip_address | The private IP address of the EC2 instance. | ip |
| aws.guardduty.resource.instance_details.network_interfaces.private.ip_addresses.private.dns_name | The private DNS name of the EC2 instance. | keyword |
| aws.guardduty.resource.instance_details.network_interfaces.private.ip_addresses.private.ip_address | The private IP address of the EC2 instance. | ip |
| aws.guardduty.resource.instance_details.network_interfaces.public.dns_name | The public DNS name of the EC2 instance. | keyword |
| aws.guardduty.resource.instance_details.network_interfaces.public.ip | The public IP address of the EC2 instance. | ip |
| aws.guardduty.resource.instance_details.network_interfaces.security_groups.group.id | The security group ID of the EC2 instance. | keyword |
| aws.guardduty.resource.instance_details.network_interfaces.security_groups.group.name | The security group name of the EC2 instance. | keyword |
| aws.guardduty.resource.instance_details.network_interfaces.subnet_id | The subnet ID of the EC2 instance. | keyword |
| aws.guardduty.resource.instance_details.network_interfaces.vpc_id | The VPC ID of the EC2 instance. | keyword |
| aws.guardduty.resource.instance_details.outpost_arn | The Amazon Resource Name (ARN) of the AWS Outpost. Only applicable to AWS Outposts instances. | keyword |
| aws.guardduty.resource.instance_details.platform | The platform of the EC2 instance. | keyword |
| aws.guardduty.resource.instance_details.product_codes.product_code.id | The product code information. | keyword |
| aws.guardduty.resource.instance_details.product_codes.product_code.type | The product code type. | keyword |
| aws.guardduty.resource.instance_details.tags.key | The EC2 instance tag key. | keyword |
| aws.guardduty.resource.instance_details.tags.value | The EC2 instance tag value. | keyword |
| aws.guardduty.resource.kubernetes_details.kubernetes_user_details.groups | The groups that include the user who called the Kubernetes API. | keyword |
| aws.guardduty.resource.kubernetes_details.kubernetes_user_details.uid | The user ID of the user who called the Kubernetes API. | keyword |
| aws.guardduty.resource.kubernetes_details.kubernetes_user_details.user_name | The username of the user who called the Kubernetes API. | keyword |
| aws.guardduty.resource.kubernetes_details.kubernetes_workload_details.containers.container_runtime | The container runtime (such as, Docker or containerd) used to run the container. | keyword |
| aws.guardduty.resource.kubernetes_details.kubernetes_workload_details.containers.id | Container ID. | keyword |
| aws.guardduty.resource.kubernetes_details.kubernetes_workload_details.containers.image.prefix | Part of the image name before the last slash. For example, imagePrefix for public.ecr.aws/amazonlinux/amazonlinux:latest would be public.ecr.aws/amazonlinux. If the image name is relative and does not have a slash, this field is empty. | keyword |
| aws.guardduty.resource.kubernetes_details.kubernetes_workload_details.containers.image.value | Container image. | keyword |
| aws.guardduty.resource.kubernetes_details.kubernetes_workload_details.containers.name | Container name. | keyword |
| aws.guardduty.resource.kubernetes_details.kubernetes_workload_details.containers.security_context.privileged | Whether the container is privileged. | boolean |
| aws.guardduty.resource.kubernetes_details.kubernetes_workload_details.containers.volume_mounts.mount_path | Volume mount path. | keyword |
| aws.guardduty.resource.kubernetes_details.kubernetes_workload_details.containers.volume_mounts.name | Volume mount name. | keyword |
| aws.guardduty.resource.kubernetes_details.kubernetes_workload_details.host_network | Whether the hostNetwork flag is enabled for the pods included in the workload. | boolean |
| aws.guardduty.resource.kubernetes_details.kubernetes_workload_details.name | Kubernetes workload name. | keyword |
| aws.guardduty.resource.kubernetes_details.kubernetes_workload_details.name_space | Kubernetes namespace that the workload is part of. | keyword |
| aws.guardduty.resource.kubernetes_details.kubernetes_workload_details.type | Kubernetes workload type (e.g. Pod, Deployment, etc.). | keyword |
| aws.guardduty.resource.kubernetes_details.kubernetes_workload_details.uid | Kubernetes workload ID. | keyword |
| aws.guardduty.resource.kubernetes_details.kubernetes_workload_details.volumes.host_path.path | Path of the file or directory on the host that the volume maps to. | keyword |
| aws.guardduty.resource.kubernetes_details.kubernetes_workload_details.volumes.name | Volume name. | keyword |
| aws.guardduty.resource.rdsdb_instance_details.cluster_identifier |  | keyword |
| aws.guardduty.resource.rdsdb_instance_details.engine |  | keyword |
| aws.guardduty.resource.rdsdb_instance_details.engine_version |  | keyword |
| aws.guardduty.resource.rdsdb_instance_details.instance_arn |  | keyword |
| aws.guardduty.resource.rdsdb_instance_details.instance_identifier |  | keyword |
| aws.guardduty.resource.rdsdb_user_details.application |  | keyword |
| aws.guardduty.resource.rdsdb_user_details.auth_method |  | keyword |
| aws.guardduty.resource.rdsdb_user_details.database |  | keyword |
| aws.guardduty.resource.rdsdb_user_details.ssl |  | keyword |
| aws.guardduty.resource.rdsdb_user_details.user |  | keyword |
| aws.guardduty.resource.s3_bucket_details.arn | The Amazon Resource Name (ARN) of the S3 bucket. | keyword |
| aws.guardduty.resource.s3_bucket_details.created_at | The date and time the bucket was created at. | date |
| aws.guardduty.resource.s3_bucket_details.default_server_side_encryption.encryption_type | The type of encryption used for objects within the S3 bucket. | keyword |
| aws.guardduty.resource.s3_bucket_details.default_server_side_encryption.kms_masterkey_arn | The Amazon Resource Name (ARN) of the KMS encryption key. Only available if the bucket EncryptionType is aws:kms. | keyword |
| aws.guardduty.resource.s3_bucket_details.name | The name of the S3 bucket. | keyword |
| aws.guardduty.resource.s3_bucket_details.owner.id | The canonical user ID of the bucket owner. For information about locating your canonical user ID see Finding Your Account Canonical User ID. | keyword |
| aws.guardduty.resource.s3_bucket_details.public_access | Describes the public access policies that apply to the S3 bucket. | flattened |
| aws.guardduty.resource.s3_bucket_details.tags.key | The EC2 instance tag key. | keyword |
| aws.guardduty.resource.s3_bucket_details.tags.value | The EC2 instance tag value. | keyword |
| aws.guardduty.resource.s3_bucket_details.type | Describes whether the bucket is a source or destination bucket. | keyword |
| aws.guardduty.resource.type | The type of AWS resource. | keyword |
| aws.guardduty.schema_version | The version of the schema used for the finding. | keyword |
| aws.guardduty.service.action.aws_api_call_action.affected_resources | The details of the AWS account that made the API call. This field identifies the resources that were affected by this API call. | flattened |
| aws.guardduty.service.action.aws_api_call_action.api | The AWS API name. | keyword |
| aws.guardduty.service.action.aws_api_call_action.caller_type | The AWS API caller type. | keyword |
| aws.guardduty.service.action.aws_api_call_action.domain_details.domain | The domain information for the AWS API call. | keyword |
| aws.guardduty.service.action.aws_api_call_action.error_code | The error code of the failed AWS API action. | keyword |
| aws.guardduty.service.action.aws_api_call_action.remote_account_details.account_id | The AWS account ID of the remote API caller. | keyword |
| aws.guardduty.service.action.aws_api_call_action.remote_account_details.affiliated | Details on whether the AWS account of the remote API caller is related to your GuardDuty environment. If this value is True the API caller is affiliated to your account in some way. If it is False the API caller is from outside your environment. | boolean |
| aws.guardduty.service.action.aws_api_call_action.remote_ip_details.city.name | The city name of the remote IP address. | keyword |
| aws.guardduty.service.action.aws_api_call_action.remote_ip_details.country.code | The country code of the remote IP address. | keyword |
| aws.guardduty.service.action.aws_api_call_action.remote_ip_details.country.name | The country name of the remote IP address. | keyword |
| aws.guardduty.service.action.aws_api_call_action.remote_ip_details.geo_location | The location information of the remote IP address. | geo_point |
| aws.guardduty.service.action.aws_api_call_action.remote_ip_details.ip_address_v4 | The IPv4 remote address of the connection. | ip |
| aws.guardduty.service.action.aws_api_call_action.remote_ip_details.organization.asn | The Autonomous System Number (ASN) of the internet provider of the remote IP address. | keyword |
| aws.guardduty.service.action.aws_api_call_action.remote_ip_details.organization.asnorg | The organization that registered this ASN. | keyword |
| aws.guardduty.service.action.aws_api_call_action.remote_ip_details.organization.isp | The ISP information for the internet provider. | keyword |
| aws.guardduty.service.action.aws_api_call_action.remote_ip_details.organization.org | The name of the internet provider. | keyword |
| aws.guardduty.service.action.aws_api_call_action.service_name | The name of the AWS service (GuardDuty) that generated a finding. | keyword |
| aws.guardduty.service.action.aws_api_call_action.user_agent | The agent through which the API request was made. | keyword |
| aws.guardduty.service.action.dns_request_action.blocked | Indicates whether the targeted port is blocked. | boolean |
| aws.guardduty.service.action.dns_request_action.domain | The domain information for the API request. | keyword |
| aws.guardduty.service.action.dns_request_action.protocol | The network connection protocol observed in the activity that prompted GuardDuty to generate the finding. | keyword |
| aws.guardduty.service.action.kubernetes_api_call_action.parameters | Parameters related to the Kubernetes API call action. | keyword |
| aws.guardduty.service.action.kubernetes_api_call_action.remote_ip_details.city.name | The city name of the remote IP address. | keyword |
| aws.guardduty.service.action.kubernetes_api_call_action.remote_ip_details.country.code | The country code of the remote IP address. | keyword |
| aws.guardduty.service.action.kubernetes_api_call_action.remote_ip_details.country.name | The country name of the remote IP address. | keyword |
| aws.guardduty.service.action.kubernetes_api_call_action.remote_ip_details.geo_location | The location information of the remote IP address. | geo_point |
| aws.guardduty.service.action.kubernetes_api_call_action.remote_ip_details.ip_address_v4 | The IPv4 remote address of the connection. | ip |
| aws.guardduty.service.action.kubernetes_api_call_action.remote_ip_details.organization.asn | The Autonomous System Number (ASN) of the internet provider of the remote IP address. | keyword |
| aws.guardduty.service.action.kubernetes_api_call_action.remote_ip_details.organization.asnorg | The organization that registered this ASN. | keyword |
| aws.guardduty.service.action.kubernetes_api_call_action.remote_ip_details.organization.isp | The ISP information for the internet provider. | keyword |
| aws.guardduty.service.action.kubernetes_api_call_action.remote_ip_details.organization.org | The name of the internet provider. | keyword |
| aws.guardduty.service.action.kubernetes_api_call_action.request_uri | The Kubernetes API request URI. | keyword |
| aws.guardduty.service.action.kubernetes_api_call_action.source_ips | The IP of the Kubernetes API caller and the IPs of any proxies or load balancers between the caller and the API endpoint. | ip |
| aws.guardduty.service.action.kubernetes_api_call_action.status_code | The resulting HTTP response code of the Kubernetes API call action. | long |
| aws.guardduty.service.action.kubernetes_api_call_action.user_agent | The user agent of the caller of the Kubernetes API. | keyword |
| aws.guardduty.service.action.kubernetes_api_call_action.verb | The Kubernetes API request HTTP verb. | keyword |
| aws.guardduty.service.action.network_connection_action.blocked | Indicates whether EC2 blocked the network connection to your instance. | boolean |
| aws.guardduty.service.action.network_connection_action.connection_direction | The network connection direction. | keyword |
| aws.guardduty.service.action.network_connection_action.local_ip_details.ip_address_v4 | The IPv4 local address of the connection. | keyword |
| aws.guardduty.service.action.network_connection_action.local_port_details.port.name | The port name of the local connection. | keyword |
| aws.guardduty.service.action.network_connection_action.local_port_details.port.value | The port number of the local connection. | long |
| aws.guardduty.service.action.network_connection_action.remote_ip_details.city.name | The city name of the remote IP address. | keyword |
| aws.guardduty.service.action.network_connection_action.remote_ip_details.country.code | The country code of the remote IP address. | keyword |
| aws.guardduty.service.action.network_connection_action.remote_ip_details.country.name | The country name of the remote IP address. | keyword |
| aws.guardduty.service.action.network_connection_action.remote_ip_details.geo_location | The location information of the remote IP address. | geo_point |
| aws.guardduty.service.action.network_connection_action.remote_ip_details.ip_address_v4 | The IPv4 remote address of the connection. | ip |
| aws.guardduty.service.action.network_connection_action.remote_ip_details.organization.asn | The Autonomous System Number (ASN) of the internet provider of the remote IP address. | keyword |
| aws.guardduty.service.action.network_connection_action.remote_ip_details.organization.asnorg | The organization that registered this ASN. | keyword |
| aws.guardduty.service.action.network_connection_action.remote_ip_details.organization.isp | The ISP information for the internet provider. | keyword |
| aws.guardduty.service.action.network_connection_action.remote_ip_details.organization.org | The name of the internet provider. | keyword |
| aws.guardduty.service.action.network_connection_action.remote_port_details.port.name | The port name of the remote connection. | keyword |
| aws.guardduty.service.action.network_connection_action.remote_port_details.port.value | The port number of the remote connection. | long |
| aws.guardduty.service.action.network_connection_action.transport | The network connection protocol. | keyword |
| aws.guardduty.service.action.port_probe_action.blocked | Indicates whether EC2 blocked the port probe to the instance, such as with an ACL. | boolean |
| aws.guardduty.service.action.port_probe_action.port_probe_details.local_ip_details.ip_address_v4 | The IPv4 local address of the connection. | keyword |
| aws.guardduty.service.action.port_probe_action.port_probe_details.local_port_details.port.name | The port name of the local connection. | keyword |
| aws.guardduty.service.action.port_probe_action.port_probe_details.local_port_details.port.value | The port number of the local connection. | long |
| aws.guardduty.service.action.port_probe_action.port_probe_details.remote_ip_details.city.name | The city name of the remote IP address. | keyword |
| aws.guardduty.service.action.port_probe_action.port_probe_details.remote_ip_details.country.code | The country code of the remote IP address. | keyword |
| aws.guardduty.service.action.port_probe_action.port_probe_details.remote_ip_details.country.name | The country name of the remote IP address. | keyword |
| aws.guardduty.service.action.port_probe_action.port_probe_details.remote_ip_details.geo_location | The location information of the remote IP address. | geo_point |
| aws.guardduty.service.action.port_probe_action.port_probe_details.remote_ip_details.ip_address_v4 | The IPv4 remote address of the connection. | ip |
| aws.guardduty.service.action.port_probe_action.port_probe_details.remote_ip_details.organization.asn | The Autonomous System Number (ASN) of the internet provider of the remote IP address. | keyword |
| aws.guardduty.service.action.port_probe_action.port_probe_details.remote_ip_details.organization.asnorg | The organization that registered this ASN. | keyword |
| aws.guardduty.service.action.port_probe_action.port_probe_details.remote_ip_details.organization.isp | The ISP information for the internet provider. | keyword |
| aws.guardduty.service.action.port_probe_action.port_probe_details.remote_ip_details.organization.org | The name of the internet provider. | keyword |
| aws.guardduty.service.action.rds_login_attempt_action.remote_ip_details.city.name | The city name of the remote IP address. | keyword |
| aws.guardduty.service.action.rds_login_attempt_action.remote_ip_details.country.code | The country code of the remote IP address. | keyword |
| aws.guardduty.service.action.rds_login_attempt_action.remote_ip_details.country.name | The country name of the remote IP address. | keyword |
| aws.guardduty.service.action.rds_login_attempt_action.remote_ip_details.geo_location | The location information of the remote IP address. | geo_point |
| aws.guardduty.service.action.rds_login_attempt_action.remote_ip_details.ip_address_v4 | The IPv4 remote address of the connection. | ip |
| aws.guardduty.service.action.rds_login_attempt_action.remote_ip_details.organization.asn | The Autonomous System Number (ASN) of the internet provider of the remote IP address. | keyword |
| aws.guardduty.service.action.rds_login_attempt_action.remote_ip_details.organization.asnorg | The organization that registered this ASN. | keyword |
| aws.guardduty.service.action.rds_login_attempt_action.remote_ip_details.organization.isp | The ISP information for the internet provider. | keyword |
| aws.guardduty.service.action.rds_login_attempt_action.remote_ip_details.organization.org | The name of the internet provider. | keyword |
| aws.guardduty.service.action.type | The GuardDuty finding activity type. | keyword |
| aws.guardduty.service.additional_info | Contains additional information about the generated finding. | flattened |
| aws.guardduty.service.archived | Indicates whether this finding is archived. | boolean |
| aws.guardduty.service.count | The total count of the occurrences of this finding type. | long |
| aws.guardduty.service.detector_id | The detector ID for the GuardDuty service. | keyword |
| aws.guardduty.service.ebs_volume_scan_details.scan.completed_at | Returns the completion date and time of the malware scan. | date |
| aws.guardduty.service.ebs_volume_scan_details.scan.detections.highest_severity_threat_details.count | Total number of infected files with the highest severity threat detected. | long |
| aws.guardduty.service.ebs_volume_scan_details.scan.detections.highest_severity_threat_details.severity | Severity level of the highest severity threat detected. | keyword |
| aws.guardduty.service.ebs_volume_scan_details.scan.detections.highest_severity_threat_details.threat_name | Threat name of the highest severity threat detected as part of the malware scan. | keyword |
| aws.guardduty.service.ebs_volume_scan_details.scan.detections.scanned_item_count.files | Number of files scanned. | long |
| aws.guardduty.service.ebs_volume_scan_details.scan.detections.scanned_item_count.total_gb | Total GB of files scanned for malware. | long |
| aws.guardduty.service.ebs_volume_scan_details.scan.detections.scanned_item_count.volumes | Total number of scanned volumes. | long |
| aws.guardduty.service.ebs_volume_scan_details.scan.detections.threat_detected_by_name.item_count | Total number of infected files identified. | long |
| aws.guardduty.service.ebs_volume_scan_details.scan.detections.threat_detected_by_name.shortened | Flag to determine if the finding contains every single infected file-path and/or every threat. | boolean |
| aws.guardduty.service.ebs_volume_scan_details.scan.detections.threat_detected_by_name.threat_names.file_paths.file.name | File name of the infected file. | keyword |
| aws.guardduty.service.ebs_volume_scan_details.scan.detections.threat_detected_by_name.threat_names.file_paths.file.path | The file path of the infected file. | keyword |
| aws.guardduty.service.ebs_volume_scan_details.scan.detections.threat_detected_by_name.threat_names.file_paths.hash | The hash value of the infected file. | keyword |
| aws.guardduty.service.ebs_volume_scan_details.scan.detections.threat_detected_by_name.threat_names.file_paths.volume_arn | EBS volume Arn details of the infected file. | keyword |
| aws.guardduty.service.ebs_volume_scan_details.scan.detections.threat_detected_by_name.threat_names.item_count | Total number of files infected with given threat. | long |
| aws.guardduty.service.ebs_volume_scan_details.scan.detections.threat_detected_by_name.threat_names.name | The name of the identified threat. | keyword |
| aws.guardduty.service.ebs_volume_scan_details.scan.detections.threat_detected_by_name.threat_names.severity | Severity of threat identified as part of the malware scan. | keyword |
| aws.guardduty.service.ebs_volume_scan_details.scan.detections.threat_detected_by_name.unique_threat_name_count | Total number of unique threats by name identified, as part of the malware scan. | long |
| aws.guardduty.service.ebs_volume_scan_details.scan.detections.threats_detected_item_count.files | Total number of infected files. | long |
| aws.guardduty.service.ebs_volume_scan_details.scan.id | Unique Id of the malware scan that generated the finding. | keyword |
| aws.guardduty.service.ebs_volume_scan_details.scan.started_at | Returns the start date and time of the malware scan. | date |
| aws.guardduty.service.ebs_volume_scan_details.sources | Contains list of threat intelligence sources used to detect threats. | keyword |
| aws.guardduty.service.ebs_volume_scan_details.trigger_finding_id | GuardDuty finding ID that triggered a malware scan. | keyword |
| aws.guardduty.service.event.first_seen | The first-seen timestamp of the activity that prompted GuardDuty to generate this finding. | date |
| aws.guardduty.service.event.last_seen | The last-seen timestamp of the activity that prompted GuardDuty to generate this finding. | date |
| aws.guardduty.service.evidence.threat_intelligence_details.threat.list_name | The name of the threat intelligence list that triggered the finding. | keyword |
| aws.guardduty.service.evidence.threat_intelligence_details.threat.names | A list of names of the threats in the threat intelligence list that triggered the finding. | keyword |
| aws.guardduty.service.feature_name | The name of the feature that generated a finding. | keyword |
| aws.guardduty.service.resource_role | The resource role information for this finding. | keyword |
| aws.guardduty.service.service_name | The AWS service name whose API was invoked. | keyword |
| aws.guardduty.service.user_feedback | Feedback that was submitted about the finding. | keyword |
| aws.guardduty.severity.code | The severity of the finding in double. | double |
| aws.guardduty.severity.value | The severity of the finding. | keyword |
| aws.guardduty.title | The title of the finding. | keyword |
| aws.guardduty.type | The type of finding. | keyword |
| aws.guardduty.updated_at | The time and date when the finding was last updated. | date |
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
| cloud.service.name | The cloud service name is intended to distinguish services running on different platforms within a provider, eg AWS EC2 vs Lambda, GCP GCE vs App Engine, Azure VM vs App Server. Examples: app engine, app service, cloud run, fargate, lambda. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| container.runtime | Runtime managing this container. | keyword |
| container.security_context.privileged | Indicates whether the container is running in privileged mode. | boolean |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.address | Some event destination addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| dns.question.name | The name being queried. If the name field contains non-printable characters (below 32 or above 126), those characters should be represented as escaped base 10 integers (\DDD). Back slashes and quotes should be escaped. Tabs, carriage returns, and line feeds should be converted to \t, \r, and \n respectively. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.end | `event.end` contains the date when the event ended or when the activity was last observed. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.start | `event.start` contains the date when the event started or when the activity was first observed. | date |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host MAC addresses. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |
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
| network.direction | Direction of the network traffic. When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| orchestrator.namespace | Namespace in which the action is taking place. | keyword |
| orchestrator.resource.name | Name of the resource being acted upon. | keyword |
| orchestrator.resource.type | Type of resource being acted upon. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| rule.category | A categorization value keyword used by the entity using the rule for detection of this event. | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| rule.ruleset | Name of the ruleset, policy, group, or parent category in which the rule used to generate this event is a member. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.geo.city_name | City name. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user.roles | Array of user roles at the time of the event. | keyword |

