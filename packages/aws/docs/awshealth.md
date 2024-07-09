# AWS Health

AWS Health metrics provide insights into the health of your AWS environment by monitoring various aspects such as open issues, scheduled maintenance events, security advisories, compliance status, notification counts, and service disruptions. These metrics help you proactively identify and address issues impacting your AWS resources, ensuring the reliability, security, and compliance of your infrastructure.

## Data streams

The AWS Health integration collects one type of data: metrics.

Metrics provide insight into the operational health of your AWS environment, including the status of AWS services, scheduled changes, and notifications about potential issues that could impact your resources. Metrics are gathered with the [AWS Health API](https://docs.aws.amazon.com/health/latest/APIReference/Welcome.html)

See more details in the [Metrics reference](#metrics-reference).


## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Before using any AWS integration you will need:

* **AWS Credentials** to connect with your AWS account.
* **AWS Permissions** to make sure the user you're using to connect has permission to share the relevant data.

For more details about these requirements, please take a look at the [AWS integration documentation](https://docs.elastic.co/integrations/aws#requirements).

To collect AWS Health metrics, you would need specific AWS permissions to access the necessary data. Here's a list of permissions required for an IAM user to collect AWS Health metrics:

- `health:DescribeAffectedEntities`
- `health:DescribeEventDetails`
- `health:DescribeEvents`


## Setup

If you want to collect data from two or more AWS services, consider using the **AWS** integration. When you configure the AWS integration, you can collect data from as many AWS services as you'd like.

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

### Data stream specific configuration notes

`Period`:: (_string_) Reporting interval. Recommended value is `24h`.

## Metrics reference

The `awshealth` data stream collects AWS Health metrics from AWS.

An example event for `awshealth` looks as following:

An example event for `awshealth` looks as following:

```json
{
    "@timestamp": "2024-06-09T07:26:10.847Z",
    "agent": {
        "ephemeral_id": "4c4c2973-500d-46d4-b41f-e6e02bb792e4",
        "id": "f2c63d7a-e4e0-4646-b76b-b6ba80fb1be8",
        "name": "service-integration-dev-idc-1",
        "type": "metricbeat",
        "version": "8.14.0"
    },
    "aws": {
        "awshealth": {
            "affected_entities": [
                {
                    "aws_account_id": "00000000000",
                    "entity_arn": "arn:aws:health:us-west-2:00000000000:entity/g1boW0WfWEdh7qa18fGj5UZaAEFeA_2Ol3YtjyQ1IWcI4=1g",
                    "entity_url": "",
                    "entity_value": "arn:aws:ecs:us-west-2:00000000000:cluster/EC2BasedCluster",
                    "last_updated_time": "2024-06-07T01:53:31.728Z"
                },
                {
                    "aws_account_id": "00000000000",
                    "entity_arn": "arn:aws:health:us-west-2:00000000000:entity/g1ct5TryWpLSufg8DM-B5Wp_lAicG_0BlW9Zuh1m2YZrg=1g",
                    "entity_url": "",
                    "entity_value": "arn:aws:ecs:us-west-2:00000000000:cluster/DEMOGO-ECS",
                    "last_updated_time": "2024-06-07T01:53:31.728Z"
                },
                {
                    "aws_account_id": "00000000000",
                    "entity_arn": "arn:aws:health:us-west-2:00000000000:entity/g1mkYYnoO_cHYLqqY-p5H5owH5HTnTTu3ZmqnieDfbf_o=1g",
                    "entity_url": "",
                    "entity_value": "arn:aws:ecs:us-west-2:00000000000:cluster/elasticAgentCluster",
                    "last_updated_time": "2024-06-07T01:53:31.728Z"
                }
            ],
            "affected_entities_others": 0,
            "affected_entities_pending": 0,
            "affected_entities_resolved": 0,
            "event_arn": "arn:aws:health:us-west-2::event/ECS/AWS_ECS_SECURITY_NOTIFICATION/AWS_ECS_SECURITY_NOTIFICATION_de761fb8c443f11306d764547c7efb11ee0a33361f8f172d0ac6f6c4159cf646",
            "event_description": "We are following up on a previous notification regarding changes to the Docker version used in the Amazon Elastic Container Service (Amazon ECS) Optimized Amazon Machine Imagines (AMI) based on Amazon Linux 2 (AL2). If you are running the Amazon ECS-Optimized AL2023 AMIs, which are on the latest Docker version, you can disregard this message.\n\nDocker version 20.10.25 reached its end-of-life in December 2023 and will not receive any further security updates. We are changing the default version of Docker in the ECS-Optimized AL2 AMI to 25.0.3 with a staged release. This is a major version bump in Docker and contains backwards incompatible changes. Please make sure to test your application after applying this update.\n\nOn June 12, 2024, as communicated previously, we will disable automatic security updates at instance launch for ECS-Optimized AL2 AMIs. On June 19, 2024, we will release Docker 25.0.3 to the Amazon ECS Extras Repository without being tagged as a security advisory. This will allow customers who update in place, to manually update their instances with the command 'yum update docker' to complete any necessary acceptance testing. On July 11, 2024, we will release a new version of the ECS-Optimized AL2 AMI with Docker 25.0.3. For customers that choose not to update in place, we recommend moving to this AMI to get the update. ECS-Optimized AL2 AMI versions released between June 12, 2024 and July 11, 2024 will not receive the new Docker version and your action will be required to receive security updates to Docker. We recommend you update to an ECS-Optimized AL2 AMI released on July 11, 2024 or later.\n\nOn August 28, 2024, we will tag Docker 25.0.3 as a security update. This will trigger AMIs released prior to June 12, 2024 to automatically update the Docker version to Docker 25.0.3 at instance launch unless you have taken steps to disable this functionality [1].\n\nUpdating in place to Docker 25.0.3 will also update the ecs-init package to the latest available. Docker 25.0.3 is only compatible with ecs-init version 1.81 or later. As a best practice, and to ensure you are receiving the latest package versions and updates, we recommend customers update to the latest Amazon ECS-Optimized AMIs, which are released weekly.\n\nA list of your impacted resources can be found in the 'Affected resources' tab.\n\nIf you have any further questions, please contact AWS Support [2].\n\n[1] https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-optimized_AMI.html\n[2] https://aws.amazon.com/support",
            "event_scope_code": "ACCOUNT_SPECIFIC",
            "event_type_category": "accountNotification",
            "event_type_code": "AWS_ECS_SECURITY_NOTIFICATION",
            "last_updated_time": "2024-06-07T05:25:47.913Z",
            "region": "us-west-2",
            "service": "ECS",
            "start_time": "2024-06-06T20:25:00.000Z",
            "status_code": "open"
        }
    },
    "cloud": {
        "account": {
            "id": "elastic-obs-integrations-dev"
        },
        "availability_zone": "asia-south1-c",
        "instance": {
            "id": "000000000000000000",
            "name": "service-integration-dev-idc-1"
        },
        "machine": {
            "type": "n1-standard-8"
        },
        "project": {
            "id": "elastic-obs-integrations-dev"
        },
        "provider": "gcp",
        "region": "asia-south1",
        "service": {
            "name": "GCE"
        }
    },
    "cloud.provider": "aws",
    "data_stream": {
        "dataset": "aws.awshealth",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "f2c63d7a-e4e0-4646-b76b-b6ba80fb1be8",
        "snapshot": false,
        "version": "8.14.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "aws.awshealth",
        "duration": 11035786308,
        "ingested": "2024-06-09T07:26:31Z",
        "module": "aws"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "service-integration-dev-idc-1",
        "id": "1bfc9b2d8959f75a520a3cb94cf035c8",
        "ip": [
            "10.160.0.4",
            "fe80::4001:aff:fea0:4",
            "192.168.0.1",
            "192.168.32.1",
            "fe80::7caf:a6ff:febd:c3a9",
            "172.22.0.1",
            "172.26.0.1",
            "172.20.0.1",
            "172.30.0.1",
            "172.29.0.1",
            "172.17.0.1",
            "fe80::42:a5ff:fe15:d63c",
            "172.1.0.1",
            "172.19.0.1",
            "172.27.0.1",
            "172.31.0.1",
            "192.168.80.1",
            "192.168.224.1",
            "172.23.0.1",
            "192.168.49.1",
            "fe80::42:beff:fe39:f457",
            "fe80::4c7d:f2ff:fece:af8e",
            "fe80::3cbb:3ff:fe9a:20db",
            "fe80::d4d6:36ff:fef2:6468",
            "fe80::cc52:29ff:fe19:ed74",
            "192.168.16.1",
            "fe80::42:2fff:fe16:b2ba",
            "fe80::1c7d:aff:fe87:6f65",
            "fe80::2861:f4ff:fe68:8801",
            "fe80::5c94:eaff:fea6:b831"
        ],
        "mac": [
            "02-42-0D-A6-43-C0",
            "02-42-23-32-CF-25",
            "02-42-27-90-E6-54",
            "02-42-2F-16-B2-BA",
            "02-42-34-10-CA-62",
            "02-42-4F-1D-94-1B",
            "02-42-50-2E-CB-58",
            "02-42-5D-42-F3-1D",
            "02-42-66-9B-25-B2",
            "02-42-99-B7-1B-26",
            "02-42-A5-15-D6-3C",
            "02-42-A6-68-F8-E9",
            "02-42-BE-39-F4-57",
            "02-42-CE-31-B7-A3",
            "02-42-E8-F3-CF-7A",
            "02-42-F1-35-B0-41",
            "02-42-F4-2F-0F-22",
            "1E-7D-0A-87-6F-65",
            "2A-61-F4-68-88-01",
            "3E-BB-03-9A-20-DB",
            "42-01-0A-A0-00-04",
            "4E-7D-F2-CE-AF-8E",
            "5E-94-EA-A6-B8-31",
            "7E-AF-A6-BD-C3-A9",
            "CE-52-29-19-ED-74",
            "D6-D6-36-F2-64-68"
        ],
        "name": "service-integration-dev-idc-1",
        "os": {
            "codename": "bionic",
            "family": "debian",
            "kernel": "5.4.0-1106-gcp",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "18.04.6 LTS (Bionic Beaver)"
        }
    },
    "metricset": {
        "name": "awshealth",
        "period": 86400000
    },
    "service": {
        "type": "aws-health"
    }
}
```

**Exported fields**

| Field | Description | Type | Metric Type |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |  |
| aws.awshealth.affected_entities | Details of the affected entities related to the event. | object |  |
| aws.awshealth.affected_entities.aws_account_id | The Amazon Web Services account number that contains the affected entity. | keyword |  |
| aws.awshealth.affected_entities.entity_arn | The unique identifier for the affected entities. The entity ARN has the format: `arn:aws:health:\<entity-region\>:\<aws-account\>:entity/\<entity-id\>`. For example, `arn:aws:health:us-east-1:111222333444:entity/AVh5GGT7ul1arKr1sE1K`. | keyword |  |
| aws.awshealth.affected_entities.entity_url | The URL of the affected entity. | keyword |  |
| aws.awshealth.affected_entities.entity_value | The ID of the affected entity. | keyword |  |
| aws.awshealth.affected_entities.last_updated_time | The last updated time of entity. | date |  |
| aws.awshealth.affected_entities.status_code | The most recent status of the entity affected by the event. The possible values include `IMPAIRED`, `UNIMPAIRED`, `UNKNOWN`, `PENDING`, `RESOLVED`. | keyword |  |
| aws.awshealth.affected_entities_others | The number of affected resources related to the event whose status cannot be verified. | float | gauge |
| aws.awshealth.affected_entities_pending | The number of affected resources that may require action. | float | gauge |
| aws.awshealth.affected_entities_resolved | The number of affected resources that do not require any action. | float | gauge |
| aws.awshealth.end_time | The date and time when the event ended. Some events may not have an end date. | date |  |
| aws.awshealth.event_arn | The unique identifier for the event. The event ARN has the format `arn:aws:health:\<event-region\>::event/\<SERVICE\>/\<EVENT_TYPE_CODE\>/\<EVENT_TYPE_PLUS_ID\>`. For example, `arn:aws:health:us-east-1::event/EC2/EC2_INSTANCE_RETIREMENT_SCHEDULED/EC2_INSTANCE_RETIREMENT_SCHEDULED_ABC123-DEF456` | keyword |  |
| aws.awshealth.event_description | The detailed description of the event. | text |  |
| aws.awshealth.event_scope_code | This parameter specifies whether the Health event is a public Amazon Web Service event or an account-specific event. Allowed values are `PUBLIC`, `ACCOUNT_SPECIFIC`, or `NONE`." | keyword |  |
| aws.awshealth.event_type_category | The event type category code. Possible values are `issue`, `accountNotification`, `investigation` or `scheduledChange`. | keyword |  |
| aws.awshealth.event_type_code | The unique identifier for the event type. The format is `AWS_\<SERVICE_DESCRIPTION\>`. For example, `AWS_EC2_SYSTEM_MAINTENANCE_EVENT`. | keyword |  |
| aws.awshealth.last_updated_time | The most recent date and time when the event was updated. | date |  |
| aws.awshealth.region | The Amazon Web Services Region name of the event. | keyword |  |
| aws.awshealth.service | The Amazon Web Service affected by the event. For example, EC2 or RDS. | keyword |  |
| aws.awshealth.start_time | The date and time when the event began. | date |  |
| aws.awshealth.status_code | The most recent status of the event. Possible values are `open`, `closed`, and `upcoming`. | keyword |  |
| aws.linked_account.id | ID used to identify linked account. | keyword |  |
| aws.linked_account.name | Name or alias used to identify linked account. | keyword |  |
| aws.tags | Tag key value pairs from aws resources. | flattened |  |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |  |
| cloud.region | Region in which this host, resource, or service is located. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
