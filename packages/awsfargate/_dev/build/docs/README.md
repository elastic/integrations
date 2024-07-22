# AWS Fargate Integration

## Overview

The AWS Fargate integration helps to retrieve metadata, network metrics, and Docker stats about your containers and the tasks that are part of an [Amazon Elastic Container Service (Amazon ECS)](https://aws.amazon.com/ecs/?pg=ln&sec=hiw) cluster.

## Credentials

No AWS credentials are required for this integration. The ECS task metadata endpoint is accessible inside the cluster only.

## Setup

To start collecting AWS Fargate metrics, you must run the Elastic Agent as a [sidecar](https://www.oreilly.com/library/view/designing-distributed-systems/9781491983638/ch02.html) container alongside your application container in the same task definition.

Each task definition must run an Agent because task metadata information is only available to containers running in the task.

Here's an example of an Elastic Agent running as a sidecar with an application container:

```yaml
TaskDefinition:
    Type: AWS::ECS::TaskDefinition
    Properties:
      Family: !Ref TaskName
      Cpu: 256
      Memory: 512
      NetworkMode: awsvpc
      ExecutionRoleArn: !Ref ExecutionRole
      ContainerDefinitions:
        - Name: <application-container>              << ===== Application container
          Image: <application-container-image>
          <application-container-settings>
        - Name: elastic-agent-container              << ===== Elastic Agent container
          Image: docker.elastic.co/beats/elastic-agent:8.12.0
```

The Elastic Agent collects metrics using the [Amazon ECS task metadata endpoint](https://docs.aws.amazon.com/AmazonECS/latest/userguide/task-metadata-endpoint-fargate.html).

The Amazon ECS task metadata endpoint is an HTTP endpoint available to each container and enabled by default on [AWS Fargate platform version 1.4.0](https://aws.amazon.com/blogs/containers/aws-fargate-launches-platform-version-1-4/) and later. The Elastic Agent uses [Task metadata endpoint version 4](https://docs.aws.amazon.com/AmazonECS/latest/userguide/task-metadata-endpoint-v4-fargate.html).

## Getting started using the AWS Management Console

This section shows you how to run the Elastic Agent in a ECS cluster, start collecting Fargate on ECS metrics, and send them to an Elastic Stack.

To quickly deploy on your existing ECS cluster, follow these steps.

### Task Definition

Open the AWS Management Console and visit the Amazon ECS page. Here you can select "Task Definitions" and then "Create new Task Definition" to start the wizard.

Step 1:
- Select "Fargate" from the list of available launch types.

Step 2:
- Add your preferred name for the "Task definition name", for example "elastic-agent-fargate-deployment".
- For the "Task role", select "ecsFargateTaskExecutionRole".
- For the "Operating system family", select "Linux".
- Pick a value for "Task memory (GB)" and "Task CPU (vCPU)"; the lowest values are fine for testing purposes.
- Click on "Add container".

As for the container, you can use the following values:

- Container name: `elastic-agent-container`
- Image: `docker.elastic.co/beats/elastic-agent:8.12.0`
- Environment variables:
  - FLEET_ENROLL: `yes`
  - FLEET_ENROLLMENT_TOKEN: `<enrollment-token>`
  - FLEET_URL: `<fleet-server-url>`
  
Tip: use the AWS Secrets Manager to store the Fleet Server enrollment token.

### Service

Select an existing ECS cluster and create a new service with launch type "FARGATE". Use the task definition we just created.

As soon as the Elastic Agent is started, open the dashboard "\[AWS Fargate\] Fargate Overview" and you will see the metrics show up in few minutes.

## Getting started using the AWS CLI

In this example, we will use the AWS CLI and a CloudFormation template to set up the following resources:

- an ECS cluster,
- a task definition for the Elastic Agent,
- a service to execute the agent task on the cluster.

### Setup

Prepare you terminal and AWS environment to create the ECS cluster for the testing.

#### Pick a region

Set default AWS region for this session:

```shell
export AWS_DEFAULT_REGION="us-east-1"
```

#### Secrets management

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

#### Networking

One more thing. You need to pick one subnet where your ECS cluster will be created in. Take note of the subnet ID for the very next step.

### Deploy the stack

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
          Image: docker.elastic.co/beats/elastic-agent:8.12.0
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

Check the stack status until it has reached the `CREATE_COMPLETE` status. Use the AWS Management Console or the AWS CLI (requires the tool [jq](https://stedolan.github.io/jq/)):

```shell
$ aws cloudformation list-stacks | jq '.StackSummaries[] | .StackName + " " + .StackStatus'

"elastic-agent-fargate-deployment CREATE_COMPLETE"
```

That's it!

### Clean up

Once you're done with experimenting, you can remove all the resources (ECS cluster, task, service, etc) with the following command:

```shell
aws cloudformation delete-stack --stack-name elastic-agent-fargate-deployment
```

## Further Readings

If you want to learn more about Amazon ECS metrics, take a look at the blog post [How to monitor Amazon ECS with Elastic Observability](https://www.elastic.co/blog/how-to-monitor-amazon-ecs-with-elastic-observability).

## Metrics

### Task Stats

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "task_stats"}}

{{event "task_stats"}}
