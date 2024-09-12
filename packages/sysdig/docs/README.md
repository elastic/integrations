# Sysdig Integration
This integration allows for the shipping of [Sysdig](https://sysdig.com/) alerts to Elastic for observability and organizational awareness. Alerts can then be analyzed by using either the dashboard included with the integration or via the creation of custom dashboards within Kibana.

## Data Streams
The Sysdig integration collects one type of data stream: alerts.

**Alerts** The Alerts data stream collected by the Sysdig integration is comprised of Sysdig Alerts. See more details about Sysdig Alerts in [Sysdig's Alerts Documentation](https://docs.sysdig.com/en/docs/sysdig-monitor/alerts/). A complete list of potential fields used by this integration can be found in the [Logs reference](#logs-reference)

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Sysdig must be configured to output alerts to a supported output channel as defined in [Setup](#setup). The system will only receive common fields output by Sysdig's rules, meaning that if a rule does not include a desired field the rule must be edited in Sysdig to add the field.

## Setup

For step-by-step instructions on how to set up an integration, see the [Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

In order to capture alerts from Sysdig you **must** configure Sysdig to output Alerts as JSON via [HTTP](#http-input).

### HTTP Input

The HTTP input allows the Elastic Agent to receive Sysdig Alerts via HTTP webhook.

**Required:** To configure Sysdig to output JSON, you must set up as webhook notification channel as outlined in the [Sysdig Documentation](https://docs.sysdig.com/en/docs/administration/administration-settings/outbound-integrations/notifications-management/set-up-notification-channels/configure-a-webhook-channel/).

## Logs Reference

### alerts

Sysdig alerts can contain a multitude of various fields pertaining to the type of activity on the host machine.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp with nanos. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Data stream / event dataset. | constant_keyword |
| event.module | The module the event belongs to. | constant_keyword |
| input.type |  | constant_keyword |
| sysdig.actions |  | flattened |
| sysdig.agentId | Agent identifier | integer |
| sysdig.category | Event category from Sysdig | keyword |
| sysdig.containerId | Identifier of the container | text |
| sysdig.content.fields.container.image.tag | Tag for the container image | text |
| sysdig.content.fields.container.name | Name of the container | text |
| sysdig.content.fields.proc.cmdline | Command line args for the process | text |
| sysdig.content.fields.proc.cwd | Current working directory for the current process | text |
| sysdig.content.fields.proc.exepath | Path for the current process | text |
| sysdig.content.fields.proc.name | Name of the process | text |
| sysdig.content.fields.proc.pcmdline | Command line args for the parent process | text |
| sysdig.content.fields.proc.pid | Identifier for the process | text |
| sysdig.content.fields.proc.pname | Name of the parent process | text |
| sysdig.content.fields.proc.ppid | Identifier for the parent process | text |
| sysdig.content.fields.user.name | Name of the user | text |
| sysdig.content.fields.user.uid | Identifier for the user | text |
| sysdig.content.output | The raw event output | text |
| sysdig.content.policyOrigin | Originator of the rule associated with an event | text |
| sysdig.content.policyVersion | Version of the rule associated with an event | integer |
| sysdig.content.ruleName | Name of the rule associated with an event | text |
| sysdig.content.ruleTags | Tags associated with an event rule | text |
| sysdig.content.ruleType | Category of the rule associated with an event | text |
| sysdig.description | Description of the event policy | text |
| sysdig.event.category |  | text |
| sysdig.event.description |  | text |
| sysdig.event.type |  | text |
| sysdig.hostMac | MAC address of the host machine | text |
| sysdig.id | Event identifier | text |
| sysdig.labels.azure.instanceId | Instance identifier for the azure instance | text |
| sysdig.labels.azure.instanceName | Instance name for the azure instance | text |
| sysdig.labels.azure.instanceSize | Size for the azure instance | text |
| sysdig.labels.cloudProvider.account.id | Account identifier for the cloud provider | text |
| sysdig.labels.cloudProvider.name | Name for the cloud provider | text |
| sysdig.labels.cloudProvider.region | Region for the cloud provider | text |
| sysdig.labels.gcp.availabilityZone | AZ for the gcp instance | text |
| sysdig.labels.gcp.instanceId | Instance identifier for the gcp instance | text |
| sysdig.labels.gcp.instanceName | Instance name for the gcp instance | text |
| sysdig.labels.gcp.machineType | Machine type for the gcp instance | text |
| sysdig.labels.gcp.projectId | Project identifier for the gcp instance | text |
| sysdig.labels.gcp.projectName | Project name for the gcp instance | text |
| sysdig.labels.host.hostName | Name of the current host | keyword |
| sysdig.labels.kubernetes.cluster.name | Name of the k8s cluster | text |
| sysdig.labels.kubernetes.namespace.name | Namespace of the k8s cluster | text |
| sysdig.labels.kubernetes.pod.name | Name of the k8s pod | text |
| sysdig.labels.kubernetes.workload.type | Type of k8s resource | text |
| sysdig.machineId | Identifier of the host machine | text |
| sysdig.name | Name of the event policy | text |
| sysdig.originator |  | text |
| sysdig.severity | Numerical severity value associated with an event | integer |
| sysdig.source | Event source | text |
| sysdig.timestamp | Timestamp of the event | date |
| sysdig.timestampRFC3339Nano |  | date |
| sysdig.type | In the case of policies, value should come through as "policy" | text |


**Example event**

An example event for `alerts` looks as following:

```json
{
    "@timestamp": "2024-09-12T13:06:12.675Z",
    "agent": {
        "ephemeral_id": "fe172d2f-7b14-4b87-bc5a-acc14684e4c5",
        "id": "58014837",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.14.1"
    },
    "cloud": {
        "account": {
            "id": "289645096542"
        },
        "availability_zone": "us-central1-c",
        "instance": {
            "id": "648229130641697246",
            "name": "gke-cluster-gcp-demo-san-default-pool-66250c41-vd1o"
        },
        "machine": {
            "type": "e2-standard-4"
        },
        "project": {
            "id": "289645096542",
            "name": "alliances-chronicle"
        },
        "provider": "gcp",
        "region": "us-central1"
    },
    "container": {
        "id": "6949e5f10829"
    },
    "data_stream": {
        "dataset": "sysdig.alerts",
        "namespace": "15372",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "a2d71da8-f67f-43fa-a895-0251c4a68bb0",
        "snapshot": false,
        "version": "8.14.1"
    },
    "event": {
        "agent_id_status": "mismatch",
        "dataset": "sysdig.alerts",
        "id": "17dec715376910362c8c3f62a4ceda2e",
        "ingested": "2024-09-12T13:06:22Z",
        "kind": "alert",
        "provider": "syscall",
        "severity": 7,
        "timezone": "+00:00"
    },
    "host": {
        "id": "42:01:0a:80:00:05",
        "mac": [
            "42-01-0A-80-00-05"
        ],
        "name": "gke-cluster-gcp-demo-san-default-pool-66250c41-vd1o"
    },
    "input": {
        "type": "http_endpoint"
    },
    "log": {
        "syslog": {
            "severity": {
                "code": 7,
                "name": "debug"
            }
        }
    },
    "message": "Users management command userdel tmp_suid_user launched by pwsh on threatgen under user root (proc.name=userdel proc.args=tmp_suid_user fd.name=<NA> proc.cmdline=pwsh -c (./RunTests.ps1 STDIN.NETWORK DEV.SHM.EXEC T1048 RECON.FIND.SUID T1611.002 CONTAINER.ESCAPE.NSENTER CREDS.DUMP.MEMORY KILL.MALICIOUS.PROC LOAD.BPF.PROG Base64.PYTHON BASE64.CLI CONNECT.UNEXPECTED RECON.GPG SUBTERFUGE.LASTLOG LD.LINUX.EXEC LD.SO.PRELOAD USERFAULTFD.HANDLER RECON.LINPEAS PROOT.EXEC) proc.pname=pwsh gparent=containerd-shim ggparent=<NA> gggparent=<NA> container=container_id=6949e5f10829 container_name=threatgen evt.type=execve evt.arg.request=<NA> proc.pid=2140169 proc.cwd=/tmp/ proc.ppid=2140088 proc.pcmdline=pwsh -c (./RunTests.ps1 STDIN.NETWORK DEV.SHM.EXEC T1048 RECON.FIND.SUID T1611.002 CONTAINER.ESCAPE.NSENTER CREDS.DUMP.MEMORY KILL.MALICIOUS.PROC LOAD.BPF.PROG Base64.PYTHON BASE64.CLI CONNECT.UNEXPECTED RECON.GPG SUBTERFUGE.LASTLOG LD.LINUX.EXEC LD.SO.PRELOAD USERFAULTFD.HANDLER RECON.LINPEAS PROOT.EXEC) proc.sid=1 proc.exepath=/usr/sbin/userdel user.uid=0 user.loginuid=-1 user.loginname=<NA> user.name=root group.gid=0 group.name=root container.id=6949e5f10829 container.name=threatgen image=docker.io/dockerbadboy/art)",
    "orchestrator": {
        "cluster": {
            "name": "gke-alliances-demo-6"
        },
        "namespace": "default",
        "resource": {
            "name": "threatgen-c65cf6446-5s8kk",
            "parent": {
                "type": "deployment"
            }
        },
        "type": "kubernetes"
    },
    "rule": {
        "author": [
            "Sysdig"
        ],
        "category": "RULE_TYPE_FALCO",
        "name": "User Management Event Detected",
        "ruleset": "Sysdig Runtime Activity Logs",
        "version": "35"
    },
    "sysdig": {
        "agentId": 58014837,
        "category": "runtime",
        "containerId": "6949e5f10829",
        "content": {
            "fields": {
                "container.name": "threatgen",
                "proc.cmdline": "userdel tmp_suid_user",
                "proc.cwd": "/tmp/",
                "proc.exepath": "/usr/sbin/userdel",
                "proc.name": "userdel",
                "proc.pcmdline": "pwsh -c (./RunTests.ps1 STDIN.NETWORK DEV.SHM.EXEC T1048 RECON.FIND.SUID T1611.002 CONTAINER.ESCAPE.NSENTER CREDS.DUMP.MEMORY KILL.MALICIOUS.PROC LOAD.BPF.PROG Base64.PYTHON BASE64.CLI CONNECT.UNEXPECTED RECON.GPG SUBTERFUGE.LASTLOG LD.LINUX.EXEC LD.SO.PRELOAD USERFAULTFD.HANDLER RECON.LINPEAS PROOT.EXEC)",
                "proc.pid": "2140169",
                "proc.pname": "pwsh",
                "proc.ppid": "2140088",
                "user.name": "root",
                "user.uid": "0"
            },
            "output": "Users management command userdel tmp_suid_user launched by pwsh on threatgen under user root (proc.name=userdel proc.args=tmp_suid_user fd.name=<NA> proc.cmdline=pwsh -c (./RunTests.ps1 STDIN.NETWORK DEV.SHM.EXEC T1048 RECON.FIND.SUID T1611.002 CONTAINER.ESCAPE.NSENTER CREDS.DUMP.MEMORY KILL.MALICIOUS.PROC LOAD.BPF.PROG Base64.PYTHON BASE64.CLI CONNECT.UNEXPECTED RECON.GPG SUBTERFUGE.LASTLOG LD.LINUX.EXEC LD.SO.PRELOAD USERFAULTFD.HANDLER RECON.LINPEAS PROOT.EXEC) proc.pname=pwsh gparent=containerd-shim ggparent=<NA> gggparent=<NA> container=container_id=6949e5f10829 container_name=threatgen evt.type=execve evt.arg.request=<NA> proc.pid=2140169 proc.cwd=/tmp/ proc.ppid=2140088 proc.pcmdline=pwsh -c (./RunTests.ps1 STDIN.NETWORK DEV.SHM.EXEC T1048 RECON.FIND.SUID T1611.002 CONTAINER.ESCAPE.NSENTER CREDS.DUMP.MEMORY KILL.MALICIOUS.PROC LOAD.BPF.PROG Base64.PYTHON BASE64.CLI CONNECT.UNEXPECTED RECON.GPG SUBTERFUGE.LASTLOG LD.LINUX.EXEC LD.SO.PRELOAD USERFAULTFD.HANDLER RECON.LINPEAS PROOT.EXEC) proc.sid=1 proc.exepath=/usr/sbin/userdel user.uid=0 user.loginuid=-1 user.loginname=<NA> user.name=root group.gid=0 group.name=root container.id=6949e5f10829 container.name=threatgen image=docker.io/dockerbadboy/art)",
            "policyOrigin": "Sysdig",
            "policyVersion": 35,
            "ruleName": "User Management Event Detected",
            "ruleTags": [
                "host",
                "container",
                "MITRE",
                "MITRE_TA0003_persistence",
                "MITRE_T1136_create_account",
                "MITRE_T1136.001_create_account_local_account",
                "MITRE_T1070_indicator_removal",
                "MITRE_TA0005_defense_evasion",
                "MITRE_TA0040_impact",
                "MITRE_T1531_account_access_removal",
                "MITRE_T1098_account_manipulation"
            ],
            "ruleType": "RULE_TYPE_FALCO"
        },
        "description": "This policy contains rules which provide a greater insight into general activities occuring on the system. They are very noisy, but useful in threat hunting situations if you are looking for specific actions being taken during runtime. It is not recommended to use this policy for detection purposes unless tuning is enabled.  Additional manual tuning will likely be required.",
        "event": {
            "category": "runtime",
            "description": "This policy contains rules which provide a greater insight into general activities occuring on the system. They are very noisy, but useful in threat hunting situations if you are looking for specific actions being taken during runtime. It is not recommended to use this policy for detection purposes unless tuning is enabled.  Additional manual tuning will likely be required.",
            "type": "policy"
        },
        "hostMac": "42:01:0a:80:00:05",
        "id": "17dec715376910362c8c3f62a4ceda2e",
        "labels": {
            "cloudProvider": {
                "account": {
                    "id": "289645096542"
                },
                "name": "gcp",
                "region": "us-central1"
            },
            "gcp": {
                "availabilityZone": "us-central1-c",
                "instanceId": "648229130641697246",
                "instanceName": "gke-cluster-gcp-demo-san-default-pool-66250c41-vd1o",
                "machineType": "e2-standard-4",
                "projectId": "289645096542",
                "projectName": "alliances-chronicle"
            },
            "host": {
                "hostName": "gke-cluster-gcp-demo-san-default-pool-66250c41-vd1o"
            },
            "kubernetes": {
                "cluster": {
                    "name": "gke-alliances-demo-6"
                },
                "namespace": {
                    "name": "default"
                },
                "pod": {
                    "name": "threatgen-c65cf6446-5s8kk"
                },
                "workload": {
                    "type": "deployment"
                }
            }
        },
        "machineId": "42:01:0a:80:00:05",
        "name": "Sysdig Runtime Activity Logs",
        "originator": "policy",
        "severity": 7,
        "source": "syscall",
        "timestamp": 1720031001639981000,
        "timestampRFC3339Nano": "2024-07-03T18:23:21.63998111Z",
        "type": "policy"
    },
    "tags": [
        "host",
        "container",
        "MITRE",
        "MITRE_TA0003_persistence",
        "MITRE_T1136_create_account",
        "MITRE_T1136.001_create_account_local_account",
        "MITRE_T1070_indicator_removal",
        "MITRE_TA0005_defense_evasion",
        "MITRE_TA0040_impact",
        "MITRE_T1531_account_access_removal",
        "MITRE_T1098_account_manipulation"
    ],
    "threat.technique.id": [
        "T1136"
    ]
}
```