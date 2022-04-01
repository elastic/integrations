# AWS Fargate Integration

The AWS Fargate integration provides a method to retrieve metadata, network metrics, and Docker stats about your containers and the tasks they are a part of an [Amazon Elastic Container Service (Amazon ECS)](https://aws.amazon.com/ecs/?pg=ln&sec=hiw) cluster.

## How it works?

The Elastic Agent is executed as container inside your an ECS cluster and it collects metrics using the [Amazon ECS task metadata endpoint](https://docs.aws.amazon.com/AmazonECS/latest/userguide/task-metadata-endpoint-fargate.html).

The ECS task metadata endpoint is an HTTP endpoint available to each container and enabled by default on [AWS Fargate platform version 1.4.0](https://aws.amazon.com/blogs/containers/aws-fargate-launches-platform-version-1-4/) an later. The Elastic Agent uses [Task metadata endpoint version 4](https://docs.aws.amazon.com/AmazonECS/latest/userguide/task-metadata-endpoint-v4-fargate.html).

## Credentials

No AWS credentials are required for this integration. The ECS task metadata endpoint is accessible inside the cluster only.

## Getting Started

This section shows you how to run the Elastic Agent in a ECS cluster, start collecting Fargate on ECS metrics, and send them to an Elastic Stack.

First, we'll see a simple example, setting up a task definition and a service on an existing ECS cluster using the AWS web console; this is the quickest path to have the integration up and running in your existing ECS cluster.

Second, we'll see a complete setup from scratch of a cluster, a service, and a task using a CloudFormation template and the AWS CLI.

Let's get started!

### Using the AWS web console

#### Task Definition

Open the AWS web console and visit the Amazon ECS page. Here you can select "Task Definitions" and then "Create new Task Definition" to start the wizard.

In the step 1 select "Fargate" from the list of available launch types.

In the step 2:

- Add your preferred name for the "Task definition name", for example "elastic-agent-fargate-deployment".
- For the "Task role", select "ecsFargateTaskExecutionRole".
- For the "Operating system family", select "Linux".
- Pick a value for "Task memory (GB)" and "Task CPU (vCPU)"; the lowest values are fine for testing purposes.
- Click on "Add container".

As for the container, you can use the following values:

- Container name: `elastic-agent-container`
- Image: `docker.elastic.co/beats/elastic-agent:8.1.0`
- Environment variables:
  - FLEET_ENROLL: `yes`
  - FLEET_ENROLLMENT_TOKEN: `<enrollment-token>`
  - FLEET_URL: `<fleet-server-url>`
  
Tip: use the AWS Secrets Manager to store the Fleet Server enrollment token.

#### Service

Select an existing ECS cluster and create a new service with launch type "FARGATE". Use the task definition we just created.

As soon as the Elastic Agent is started, open the dashboard named "\[Metricbeat AWS Fargate\]: Fargate Overview" and you will see the metrics show up in few minutes.

### Using the AWS CLI

In this example, we will use the AWS CLI and a CloudFormation template to set up the following resources:

- an ECS cluster,
- a task definition for the Elastic Agent,
- a service to execute the agent task on the cluster.

#### Setup

Prepare you terminal and AWS environment to create the ECS cluster for the testing.

##### Pick a region

Set default AWS region for this session:

```shell
export AWS_DEFAULT_REGION="us-east-1"
```

##### Secrets management

Store the enrollment token and the Fleet Server URL in the AWS Secrets Manager:

```shell
aws secretsmanager create-secret \
    --name FLEET_ENROLLMENT_TOKEN \
    --secret-string <your-fleet-enrollment-token-goes-here>

aws secretsmanager create-secret \
    --name FLEET_URL \
    --secret-string <your-fleet-url>
```

Take note of the Amazon Resource Name (ARN) of both secrets, we'll use them in a moment.

Tip: if you need to update them during your tests, use the following `put-secret-value` to do it:

```shell
aws secretsmanager put-secret-value \
    --secret-id FLEET_ENROLLMENT_TOKEN \
    --secret-string <fleet-enrollment-token>
```

##### Networking

One more thing. You need to pick one subnet where your ECS cluster will be created in. Take note of the subnet ID for the very next step.

#### Deploy the stack

Copy the following CloudFormation template and save it on you computer with the name `cloudformation.yml`:

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  SubnetID:
    Type: String
    Description: Enter the ID of the subnet you want to create the cluster in.
  FleetEnrollmentTokenSecretArn:
    Type: String
    Description: Enter the Amazon Resource Name (ARN) of the secret holding the enrollment token for the Elastic Agent.
  FleetUrlSecretArn:
    Type: String
    Description: Enter the Amazon Resource Name (ARN) of the secret holding the Fleet Server URL.
  ClusterName:
    Type: String
    Default: elastic-agent-fargate
    Description: Enter the name of the Fargate cluster to create.
  RoleName:
    Type: String
    Default: ecsFargateTaskExecutionRole
    Description: Enter the Amazon Resource Name (ARN) of the task execution role that grants the Amazon ECS container agent permission to make AWS API calls on your behalf.
  TaskName:
    Type: String
    Default: elastic-agent-fargate-task
    Description: Enter the name of the task definition to create.
  ServiceName:
    Type: String
    Default: elastic-agent-fargate-service
    Description: Enter the name of the service to create.
  LogGroupName:
    Type: String
    Default: elastic-agent-fargate-log-group
    Description: Enter the name of the log group to create.
Resources:
  Cluster:
    Type: AWS::ECS::Cluster
    Properties:
      ClusterName: !Ref ClusterName
      ClusterSettings:
        - Name: containerInsights
          Value: disabled
  LogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: !Ref LogGroupName
  ExecutionRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Ref RoleName
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: ecs-tasks.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy
      Policies:
        - PolicyName: !Sub 'EcsTaskExecutionRole-${AWS::StackName}'
          PolicyDocument:
            Version: 2012-10-17
            Statement:
              - Effect: Allow
                Action:
                  - secretsmanager:GetSecretValue
                Resource:
                  - !Ref FleetEnrollmentTokenSecretArn
                  - !Ref FleetUrlSecretArn
  TaskDefinition:
    Type: AWS::ECS::TaskDefinition
    Properties:
      Family: !Ref TaskName
      Cpu: 256
      Memory: 512
      NetworkMode: awsvpc
      ExecutionRoleArn: !Ref ExecutionRole
      ContainerDefinitions:
        - Name: elastic-agent-container
          Image: docker.elastic.co/beats/elastic-agent:8.1.0
          Secrets:
            - Name: FLEET_ENROLLMENT_TOKEN
              ValueFrom: !Ref FleetEnrollmentTokenSecretArn
            - Name: FLEET_URL
              ValueFrom: !Ref FleetUrlSecretArn
          LogConfiguration:
            LogDriver: awslogs
            Options:
              awslogs-region: !Ref AWS::Region
              awslogs-group: !Ref LogGroup
              awslogs-stream-prefix: ecs
          Environment:
            - Name: FLEET_ENROLL
              Value: true
              # You migh need to set FLEET_INSECURE to true
              # if you're connecting to a development
              # environment. Use it responsibly.
              # - Name: FLEET_INSECURE
              #   Value: true
      RequiresCompatibilities:
        - EC2
        - FARGATE
  Service:
    Type: AWS::ECS::Service
    Properties:
      ServiceName: !Ref ServiceName
      Cluster: !Ref Cluster
      TaskDefinition: !Ref TaskDefinition
      DesiredCount: 1
      LaunchType: FARGATE
      NetworkConfiguration:
        AwsvpcConfiguration:
          AssignPublicIp: ENABLED
          Subnets:
            - !Ref SubnetID
```

We are now finally ready to deploy the ECS cluster with the Elastic Agent running in its own task.

```shell
aws cloudformation create-stack \
    --stack-name elastic-agent-fargate-deployment \
    --template-body file://./cloudformation.yml \
    --capabilities CAPABILITY_NAMED_IAM \
    --parameters \
        ParameterKey=SubnetID,ParameterValue=<subnet-id> \
        ParameterKey=FleetEnrollmentTokenSecretArn,ParameterValue=arn:aws:secretsmanager:eu-west-1:000123456789:secret:FLEET_ENROLLMENT_TOKEN-ZxsJGw \
        ParameterKey=FleetUrlSecretArn,ParameterValue=arn:aws:secretsmanager:eu-west-1:000123456789:secret:FLEET_URL-mvjF3a \
        ParameterKey=ClusterName,ParameterValue=elastic-agent-fargate \
        ParameterKey=RoleName,ParameterValue=ecsFargateTaskExecutionRole \
        ParameterKey=TaskName,ParameterValue=elastic-agent-fargate-task \
        ParameterKey=ServiceName,ParameterValue=elastic-agent-fargate-service \
        ParameterKey=LogGroupName,ParameterValue=elastic-agent-fargate-log-group
```

The AWS CLI will return a `StackId`:

```json
{
    "StackId": "arn:aws:cloudformation:eu-west-1:000123456789:stack/elastic-agent-deployment/fc324160-b0f9-11ec-9c45-0643aa7239c3"
}
```

Check the stack status until it has reached the `CREATE_COMPLETE` status. Use the AWS web console or the AWS CLI (requires the tool [jq](https://stedolan.github.io/jq/)):

```shell
$ aws cloudformation list-stacks | jq '.StackSummaries[] | .StackName + " " + .StackStatus'

"elastic-agent-fargate-deployment CREATE_COMPLETE"
```

That's it!

#### Clean up

Once you're done with experimenting, you can remove all the resources (ECS cluster, task, service, etc) with the following command:

```shell
aws cloudformation delete-stack --stack-name elastic-agent-fargate-deployment
```

## References

If you want to learn more about how Metricbeat works behind the scenes:

- [AWS Fargate module](https://www.elastic.co/guide/en/beats/metricbeat/current/metricbeat-metricset-awsfargate-task_stats.html)
- [How to monitor Amazon ECS with Elastic Observability](https://www.elastic.co/blog/how-to-monitor-amazon-ecs-with-elastic-observability)

## Metrics

### Task Stats

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| awsfargate.task_stats.cpu.kernel.norm.pct | Percentage of time in kernel space normalized by the number of CPU cores. | scaled_float |
| awsfargate.task_stats.cpu.kernel.pct | Percentage of time in kernel space. | scaled_float |
| awsfargate.task_stats.cpu.kernel.ticks | CPU ticks in kernel space. | long |
| awsfargate.task_stats.cpu.system.norm.pct | Percentage of total CPU time in the system normalized by the number of CPU cores. | scaled_float |
| awsfargate.task_stats.cpu.system.pct | Percentage of total CPU time in the system. | scaled_float |
| awsfargate.task_stats.cpu.system.ticks | CPU system ticks. | long |
| awsfargate.task_stats.cpu.total.norm.pct | Total CPU usage normalized by the number of CPU cores. | scaled_float |
| awsfargate.task_stats.cpu.total.pct | Total CPU usage. | scaled_float |
| awsfargate.task_stats.cpu.user.norm.pct | Percentage of time in user space normalized by the number of CPU cores. | scaled_float |
| awsfargate.task_stats.cpu.user.pct | Percentage of time in user space. | scaled_float |
| awsfargate.task_stats.cpu.user.ticks | CPU ticks in user space. | long |
| awsfargate.task_stats.diskio.read.bytes | Bytes read during the life of the container | long |
| awsfargate.task_stats.diskio.read.ops | Number of reads during the life of the container | long |
| awsfargate.task_stats.diskio.read.queued | Total number of queued requests | long |
| awsfargate.task_stats.diskio.read.rate | Number of current reads per second | long |
| awsfargate.task_stats.diskio.read.reads | Number of current reads per second | scaled_float |
| awsfargate.task_stats.diskio.read.service_time | Total time to service IO requests, in nanoseconds | long |
| awsfargate.task_stats.diskio.read.summary.bytes | Bytes read and written during the life of the container | long |
| awsfargate.task_stats.diskio.read.summary.ops | Number of I/O operations during the life of the container | long |
| awsfargate.task_stats.diskio.read.summary.queued | Total number of queued requests | long |
| awsfargate.task_stats.diskio.read.summary.rate | Number of current operations per second | long |
| awsfargate.task_stats.diskio.read.summary.service_time | Total time to service IO requests, in nanoseconds | long |
| awsfargate.task_stats.diskio.read.summary.wait_time | Total time requests spent waiting in queues for service, in nanoseconds | long |
| awsfargate.task_stats.diskio.read.total | Number of reads and writes per second | scaled_float |
| awsfargate.task_stats.diskio.read.wait_time | Total time requests spent waiting in queues for service, in nanoseconds | long |
| awsfargate.task_stats.diskio.read.write.bytes | Bytes written during the life of the container | long |
| awsfargate.task_stats.diskio.read.write.ops | Number of writes during the life of the container | long |
| awsfargate.task_stats.diskio.read.write.queued | Total number of queued requests | long |
| awsfargate.task_stats.diskio.read.write.rate | Number of current writes per second | long |
| awsfargate.task_stats.diskio.read.write.service_time | Total time to service IO requests, in nanoseconds | long |
| awsfargate.task_stats.diskio.read.write.wait_time | Total time requests spent waiting in queues for service, in nanoseconds | long |
| awsfargate.task_stats.diskio.read.writes | Number of current writes per second | scaled_float |
| awsfargate.task_stats.identifier | Container identifier across tasks and clusters, which equals to container.name + '/' + container.id. | keyword |
| awsfargate.task_stats.memory.stats.\*.commit.peak | Peak committed bytes on Windows | long |
| awsfargate.task_stats.memory.stats.\*.commit.total | Total bytes | long |
| awsfargate.task_stats.memory.stats.\*.fail.count | Fail counter. | scaled_float |
| awsfargate.task_stats.memory.stats.\*.limit | Memory limit. | long |
| awsfargate.task_stats.memory.stats.\*.private_working_set.total | private working sets on Windows | long |
| awsfargate.task_stats.memory.stats.\*.rss.pct | Memory resident set size percentage. | scaled_float |
| awsfargate.task_stats.memory.stats.\*.rss.total | Total memory resident set size. | long |
| awsfargate.task_stats.memory.stats.\*.rss.usage.max | Max memory usage. | long |
| awsfargate.task_stats.memory.stats.\*.rss.usage.pct | Memory usage percentage. | scaled_float |
| awsfargate.task_stats.memory.stats.\*.rss.usage.total | Total memory usage. | long |
| awsfargate.task_stats.network.inbound.bytes | Total number of incoming bytes. | long |
| awsfargate.task_stats.network.inbound.dropped | Total number of dropped incoming packets. | long |
| awsfargate.task_stats.network.inbound.errors | Total errors on incoming packets. | long |
| awsfargate.task_stats.network.inbound.packets | Total number of incoming packets. | long |
| awsfargate.task_stats.network.interface | Network interface name. | keyword |
| awsfargate.task_stats.network.outbound.bytes | Total number of outgoing bytes. | long |
| awsfargate.task_stats.network.outbound.dropped | Total number of dropped outgoing packets. | long |
| awsfargate.task_stats.network.outbound.errors | Total errors on outgoing packets. | long |
| awsfargate.task_stats.network.outbound.packets | Total number of outgoing packets. | long |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |


An example event for `task_stats` looks as following:

```json
{
    "@timestamp": "2022-03-29T17:12:37.593Z",
    "service": {
        "type": "awsfargate"
    },
    "container": {
        "id": "c2469245446140748978d75427f2733a-947972811",
        "image": {
            "name": "docker.elastic.co/beats/metricbeat:8.0.1"
        },
        "name": "metricbeat-container",
        "labels": {
            "com_amazonaws_ecs_cluster": "arn:aws:ecs:eu-west-1:627286350134:cluster/fargate-cluster-mbranca",
            "com_amazonaws_ecs_container-name": "metricbeat-container",
            "com_amazonaws_ecs_task-arn": "arn:aws:ecs:eu-west-1:627286350134:task/fargate-cluster-mbranca/c2469245446140748978d75427f2733a",
            "com_amazonaws_ecs_task-definition-family": "metricbeat-mbranca",
            "com_amazonaws_ecs_task-definition-version": "5"
        }
    },
    "host": {
        "name": "ip-172-31-4-254.eu-west-1.compute.internal"
    },
    "agent": {
        "ephemeral_id": "9f822bc1-6406-487d-8a2c-d93da8fb90ff",
        "id": "a241110c-d125-4129-84c8-dc7b6aad2a02",
        "name": "ip-172-31-4-254.eu-west-1.compute.internal",
        "type": "metricbeat",
        "version": "8.0.1"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "awsfargate": {
        "task_stats": {
            "diskio": {
                "write": {
                    "wait_time": 0,
                    "queued": 0,
                    "ops": 3,
                    "bytes": 12288,
                    "rate": 0,
                    "service_time": 0
                },
                "summary": {
                    "queued": 0,
                    "ops": 3,
                    "bytes": 12288,
                    "rate": 0,
                    "service_time": 0,
                    "wait_time": 0
                },
                "reads": 0,
                "writes": 0,
                "total": 0,
                "read": {
                    "service_time": 0,
                    "wait_time": 0,
                    "queued": 0,
                    "ops": 0,
                    "bytes": 0,
                    "rate": 0
                }
            },
            "cluster_name": "fargate-cluster-mbranca",
            "task_name": "metricbeat-mbranca",
            "identifier": "metricbeat-container/c2469245446140748978d75427f2733a-947972811",
            "cpu": {
                "user": {
                    "ticks": 2610000000,
                    "pct": 0,
                    "norm": {
                        "pct": 0
                    }
                },
                "system": {
                    "norm": {
                        "pct": 1
                    },
                    "ticks": 6944980000000,
                    "pct": 2
                },
                "core": {},
                "total": {
                    "pct": 0.0003370733935742972,
                    "norm": {
                        "pct": 0.0001685366967871486
                    }
                },
                "kernel": {
                    "ticks": 720000000,
                    "pct": 0.001004016064257028,
                    "norm": {
                        "pct": 0.000502008032128514
                    }
                }
            },
            "memory": {
                "limit": 0,
                "rss": {
                    "total": 56008704,
                    "pct": 6.072475855489759e-12
                },
                "usage": {
                    "total": 59355136,
                    "pct": 6.435296739937261e-12,
                    "max": 86831104
                },
                "stats": {
                    "hierarchical_memory_limit": 536870912,
                    "pgfault": 82038,
                    "total_pgfault": 82038,
                    "inactive_anon": 0,
                    "pgmajfault": 0,
                    "rss_huge": 0,
                    "writeback": 0,
                    "dirty": 0,
                    "total_active_anon": 56160256,
                    "total_dirty": 0,
                    "total_inactive_file": 28672,
                    "total_mapped_file": 0,
                    "total_pgmajfault": 0,
                    "pgpgout": 56172,
                    "active_file": 36864,
                    "cache": 0,
                    "rss": 56008704,
                    "total_unevictable": 0,
                    "total_writeback": 0,
                    "active_anon": 56160256,
                    "mapped_file": 0,
                    "pgpgin": 69927,
                    "total_cache": 0,
                    "total_inactive_anon": 0,
                    "total_pgpgout": 56172,
                    "inactive_file": 28672,
                    "total_pgpgin": 69927,
                    "total_rss": 56008704,
                    "total_rss_huge": 0,
                    "unevictable": 0,
                    "hierarchical_memsw_limit": 9223372036854772000,
                    "total_active_file": 36864
                },
                "fail": {
                    "count": 0
                }
            },
            "network": {
                "eth1": {
                    "inbound": {
                        "packets": 86949,
                        "bytes": 120475632,
                        "dropped": 0,
                        "errors": 0
                    },
                    "outbound": {
                        "bytes": 6726350,
                        "dropped": 0,
                        "errors": 0,
                        "packets": 17857
                    }
                }
            }
        }
    },
    "cloud": {
        "region": "eu-west-1"
    },
    "event": {
        "dataset": "awsfargate.task_stats",
        "module": "awsfargate",
        "duration": 2110532
    },
    "metricset": {
        "name": "task_stats",
        "period": 10000
    }
}
```
