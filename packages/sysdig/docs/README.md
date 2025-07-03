# Sysdig Integration
This integration allows for the shipping of [Sysdig](https://sysdig.com/) logs to Elastic for security, observability and organizational awareness. Logs can then be analyzed by using either the dashboard included with the integration or via the creation of custom dashboards within Kibana.

## Data Streams
The Sysdig integration collects two type of logs:

**Alerts** The Alerts data stream collected by the Sysdig integration is comprised of Sysdig Alerts. See more details about Sysdig Alerts in [Sysdig's Alerts Documentation](https://docs.sysdig.com/en/docs/sysdig-monitor/alerts/). A complete list of potential fields used by this integration can be found in the [Logs reference](#logs-reference)

**Event** The event data stream collected through the Sysdig integration consists of Sysdig Security Events. See more details about Security Events in [Sysdig's Events Feed Documentation](https://docs.sysdig.com/en/docs/sysdig-secure/threats/activity/events-feed/).

## Requirements

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

Sysdig must be configured to output alerts to a supported output channel as defined in [Setup](#setup). The system will only receive common fields output by Sysdig's rules, meaning that if a rule does not include a desired field the rule must be edited in Sysdig to add the field.

## Setup

For step-by-step instructions on how to set up an integration, see the [Getting started](https://www.elastic.co/guide/en/starting-with-the-elasticsearch-platform-and-its-solutions/current/getting-started-observability.html) guide.

In order to capture alerts from Sysdig you **must** configure Sysdig to output Alerts as JSON via [HTTP](#http-input).

### HTTP Input

The HTTP input allows the Elastic Agent to receive Sysdig Alerts via HTTP webhook.

**Required:** To configure Sysdig to output JSON, you must set up as webhook notification channel as outlined in the [Sysdig Documentation](https://docs.sysdig.com/en/docs/administration/administration-settings/outbound-integrations/notifications-management/set-up-notification-channels/configure-a-webhook-channel/).

### To collect data from the Sysdig Next Gen API:

- Retrieve the API Token by following [Sysdig's API Token Guide](https://docs.sysdig.com/en/retrieve-the-sysdig-api-token).

### Enabling the integration in Elastic:

1. In Kibana navigate to Management > Integrations.
2. In "Search for integrations" top bar, search for `Sysdig`.
3. Select the "Sysdig" integration from the search results.
4. Select "Add Sysdig" to add the integration.
5. Add all the required integration configuration parameters, including the URL, API Token, Interval, and Initial Interval, to enable data collection.
6. Select "Save and continue" to save the integration.

**Note**:
  - The URL may vary depending on your region. Please refer to the [Documentation](https://docs.sysdig.com/en/developer-tools/sysdig-api/#access-the-sysdig-api-using-the-regional-endpoints) to find the correct URL for your region.
  - If you see an error saying `exceeded maximum number of CEL executions` during data ingestion, it usually means a large volume of data is being processed for the selected time interval. To fix this, try increasing the `Maximum Pages Per Interval` setting in the configuration.

## Logs Reference

### Alerts

Sysdig alerts can contain a multitude of various fields pertaining to the type of activity on the host machine.

#### Example

An example event for `alerts` looks as following:

```json
{
    "@timestamp": "2025-05-15T20:55:10.950Z",
    "agent": {
        "ephemeral_id": "d1edefb2-dd7d-40f4-bc12-f3e8e0e8a0c8",
        "id": "58014837",
        "name": "elastic-agent-68303",
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
        "namespace": "85290",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "e5c61bf4-097f-42fe-90df-25e8ef080bd8",
        "snapshot": false,
        "version": "8.14.1"
    },
    "event": {
        "agent_id_status": "mismatch",
        "dataset": "sysdig.alerts",
        "id": "17dec715376910362c8c3f62a4ceda2e",
        "ingested": "2025-05-15T20:55:12Z",
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


### Event

This is the `event` dataset.

#### Example

An example event for `event` looks as following:

```json
{
    "@timestamp": "2025-04-05T03:00:01.1159286Z",
    "agent": {
        "ephemeral_id": "9c2740ce-0231-4f1c-9b03-ba17c5430743",
        "id": "57e0981b-86e9-4bda-a293-dde14ffd115d",
        "name": "elastic-agent-91842",
        "type": "filebeat",
        "version": "8.14.1"
    },
    "cloud": {
        "account": {
            "id": "012345678912"
        },
        "project": {
            "id": "012345678912"
        },
        "provider": "gcp",
        "region": "us-central1"
    },
    "container": {
        "image": {
            "hash": {
                "all": [
                    "sha256:aa7b73608abcfb021247bbb4c111435234a0459298a6da610681097a54ca2c2a"
                ]
            },
            "name": "docker.io/library/python"
        },
        "name": "shell-scripting"
    },
    "data_stream": {
        "dataset": "sysdig.event",
        "namespace": "31832",
        "type": "logs"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "57e0981b-86e9-4bda-a293-dde14ffd115d",
        "snapshot": false,
        "version": "8.14.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "process"
        ],
        "dataset": "sysdig.event",
        "id": "1a334cdef0060123456789abcdef64a9",
        "ingested": "2025-05-19T08:53:26Z",
        "kind": "event",
        "original": "{\"category\":\"runtime\",\"content\":{\"fields\":{\"container.image.repository\":\"docker.io/library/python\",\"container.name\":\"shell-scripting\",\"evt.res\":\"SUCCESS\",\"evt.type\":\"execve\",\"group.gid\":\"0\",\"group.name\":\"root\",\"proc.args\":\"\",\"proc.cmdline\":\"sh\",\"proc.cwd\":\"/\",\"proc.exepath\":\"/usr/bin/dash\",\"proc.hash.sha256\":\"f5adb8bf0100ed0f8c7782ca5f92814e9229525a4b4e0d401cf3bea09ac960a6\",\"proc.name\":\"sh\",\"proc.pcmdline\":\"bash -c echo IyEvYmluL2Jhc2gKYXB0IHVwZGF0ZSAteTsgYXB0IGluc3RhbGwgLXkgbmNhdApuYyAtbHYgMTMzNyAmCg== | base64 -d | sh; echo cHl0aG9uMyAtYyAnaW1wb3J0IG9zLHB0eSxzb2NrZXQ7cz1zb2NrZXQuc29ja2V0KCk7cy5jb25uZWN0KCgiMC4wLjAuMCIsMTMzNykpO1tvcy5kdXAyKHMuZmlsZW5vKCksZilmb3IgZiBpbigwLDEsMildO3B0eS5zcGF3bihbInNoIiwgIi1jIiwgInNsZWVwIDU7bHMgLWE7IGV4aXQgMCJdKScK | base64 -d | sh\",\"proc.pid\":\"1372469\",\"proc.pid.ts\":\"1743822001115100312\",\"proc.pname\":\"bash\",\"proc.ppid\":\"1372453\",\"proc.ppid.ts\":\"1743822000952432134\",\"proc.sid\":\"1\",\"user.loginname\":\"\\u003cNA\\u003e\",\"user.loginuid\":\"-1\",\"user.name\":\"root\",\"user.uid\":\"0\"},\"origin\":\"Secure UI\",\"output\":\"Custom rule. The shell-scripting with image docker.io/library/python by parent bash under user root (proc.name=sh proc.exepath-custom=/usr/bin/dash proc.pname=bash gparent=runc ggparent=containerd-shim gggparent=systemd image=docker.io/library/python user.uid=0 proc.cmdline=sh proc.pcmdline=bash -c echo IyEvYmluL2Jhc2gKYXB0IHVwZGF0ZSAteTsgYXB0IGluc3RhbGwgLXkgbmNhdApuYyAtbHYgMTMzNyAmCg== | base64 -d | sh; echo cHl0aG9uMyAtYyAnaW1wb3J0IG9zLHB0eSxzb2NrZXQ7cz1zb2NrZXQuc29ja2V0KCk7cy5jb25uZWN0KCgiMC4wLjAuMCIsMTMzNykpO1tvcy5kdXAyKHMuZmlsZW5vKCksZilmb3IgZiBpbigwLDEsMildO3B0eS5zcGF3bihbInNoIiwgIi1jIiwgInNsZWVwIDU7bHMgLWE7IGV4aXQgMCJdKScK | base64 -d | sh user.name=root user.loginuid=-1 proc.args= container.name=shell-scripting evt.type=execve evt.res=SUCCESS proc.pid=1372469 proc.cwd=/ proc.ppid=1372453 proc.sid=1 proc.exepath=/usr/bin/dash user.loginname=\\u003cNA\\u003e group.gid=0 group.name=root proc.pid.ts=1743822001115100312 proc.ppid.ts=1743822000952432134 proc.hash.sha256=f5adb8bf0100ed0f8c7782ca5f92814e9229525a4b4e0d401cf3bea09ac960a6)\",\"policyId\":10569534,\"ruleName\":\"My test rule custom\",\"ruleSubType\":0,\"ruleTags\":[\"My-tag-custom-1-hello-world\",\"MITTRE-WHATEVER\"],\"ruleType\":6,\"type\":\"workloadRuntimeDetection\"},\"description\":\"This is just a dumb policy to test custom policies\",\"engine\":\"falco\",\"id\":\"1a334cdef0060123456789abcdef64a9\",\"labels\":{\"cloudProvider.account.id\":\"012345678912\",\"cloudProvider.name\":\"gcp\",\"cloudProvider.region\":\"us-central1\",\"container.image.digest\":\"sha256:aa7b73608abcfb021247bbb4c111435234a0459298a6da610681097a54ca2c2a\",\"container.image.id\":\"ef0f72a55bd2\",\"container.image.repo\":\"docker.io/library/python\",\"container.image.tag\":\"3.9.18-slim\",\"container.label.io.kubernetes.container.name\":\"shell-scripting\",\"container.label.io.kubernetes.pod.name\":\"shell-scripting-29063700-123ab\",\"container.label.io.kubernetes.pod.namespace\":\"default\",\"container.name\":\"shell-scripting\",\"gcp.location\":\"us-central1\",\"gcp.projectId\":\"012345678912\",\"host.hostName\":\"gke-cluster-gcp-demo-san-default-pool-11234abc-abcd\",\"host.mac\":\"01:00:5e:90:10:00\",\"kubernetes.cluster.name\":\"gke-alliances-demo-6\",\"kubernetes.cronJob.name\":\"shell-scripting\",\"kubernetes.job.name\":\"shell-scripting-29063700\",\"kubernetes.namespace.name\":\"default\",\"kubernetes.node.name\":\"gke-cluster-gcp-demo-san-default-pool-12345678-abcd\",\"kubernetes.pod.name\":\"shell-scripting-12345678-123ab\",\"kubernetes.workload.name\":\"shell-scripting\",\"kubernetes.workload.type\":\"cronjob\"},\"name\":\"Manuel test policy\",\"originator\":\"policy\",\"rawEventCategory\":\"runtime\",\"rawEventOriginator\":\"linuxAgent\",\"severity\":4,\"source\":\"syscall\",\"sourceDetails\":{\"subType\":\"container\",\"type\":\"workload\"},\"timestamp\":1743822001115928600}",
        "outcome": "success",
        "provider": "syscall",
        "severity": 4,
        "type": [
            "info"
        ]
    },
    "host": {
        "hostname": "gke-cluster-gcp-demo-san-default-pool-11234abc-abcd",
        "mac": [
            "01-00-5E-90-10-00"
        ],
        "name": "gke-cluster-gcp-demo-san-default-pool-11234abc-abcd"
    },
    "input": {
        "type": "cel"
    },
    "message": "Custom rule. The shell-scripting with image docker.io/library/python by parent bash under user root (proc.name=sh proc.exepath-custom=/usr/bin/dash proc.pname=bash gparent=runc ggparent=containerd-shim gggparent=systemd image=docker.io/library/python user.uid=0 proc.cmdline=sh proc.pcmdline=bash -c echo IyEvYmluL2Jhc2gKYXB0IHVwZGF0ZSAteTsgYXB0IGluc3RhbGwgLXkgbmNhdApuYyAtbHYgMTMzNyAmCg== | base64 -d | sh; echo cHl0aG9uMyAtYyAnaW1wb3J0IG9zLHB0eSxzb2NrZXQ7cz1zb2NrZXQuc29ja2V0KCk7cy5jb25uZWN0KCgiMC4wLjAuMCIsMTMzNykpO1tvcy5kdXAyKHMuZmlsZW5vKCksZilmb3IgZiBpbigwLDEsMildO3B0eS5zcGF3bihbInNoIiwgIi1jIiwgInNsZWVwIDU7bHMgLWE7IGV4aXQgMCJdKScK | base64 -d | sh user.name=root user.loginuid=-1 proc.args= container.name=shell-scripting evt.type=execve evt.res=SUCCESS proc.pid=1372469 proc.cwd=/ proc.ppid=1372453 proc.sid=1 proc.exepath=/usr/bin/dash user.loginname=<NA> group.gid=0 group.name=root proc.pid.ts=1743822001115100312 proc.ppid.ts=1743822000952432134 proc.hash.sha256=f5adb8bf0100ed0f8c7782ca5f92814e9229525a4b4e0d401cf3bea09ac960a6)",
    "observer": {
        "product": "Sysdig Secure",
        "vendor": "Sysdig"
    },
    "orchestrator": {
        "cluster": {
            "name": "gke-alliances-demo-6"
        },
        "namespace": "default",
        "resource": {
            "name": "shell-scripting-12345678-123ab",
            "parent": {
                "type": "cronjob"
            }
        }
    },
    "process": {
        "command_line": "sh",
        "executable": "/usr/bin/dash",
        "hash": {
            "sha256": "f5adb8bf0100ed0f8c7782ca5f92814e9229525a4b4e0d401cf3bea09ac960a6"
        },
        "name": "sh",
        "parent": {
            "command_line": "bash -c echo IyEvYmluL2Jhc2gKYXB0IHVwZGF0ZSAteTsgYXB0IGluc3RhbGwgLXkgbmNhdApuYyAtbHYgMTMzNyAmCg== | base64 -d | sh; echo cHl0aG9uMyAtYyAnaW1wb3J0IG9zLHB0eSxzb2NrZXQ7cz1zb2NrZXQuc29ja2V0KCk7cy5jb25uZWN0KCgiMC4wLjAuMCIsMTMzNykpO1tvcy5kdXAyKHMuZmlsZW5vKCksZilmb3IgZiBpbigwLDEsMildO3B0eS5zcGF3bihbInNoIiwgIi1jIiwgInNsZWVwIDU7bHMgLWE7IGV4aXQgMCJdKScK | base64 -d | sh",
            "name": "bash",
            "pid": 1372453,
            "start": "2025-04-05T03:00:00.952432134Z"
        },
        "pid": 1372469,
        "start": "2025-04-05T03:00:01.115100312Z",
        "working_directory": "/"
    },
    "related": {
        "hash": [
            "f5adb8bf0100ed0f8c7782ca5f92814e9229525a4b4e0d401cf3bea09ac960a6",
            "aa7b73608abcfb021247bbb4c111435234a0459298a6da610681097a54ca2c2a"
        ],
        "hosts": [
            "gke-cluster-gcp-demo-san-default-pool-11234abc-abcd"
        ],
        "user": [
            "root",
            "0"
        ]
    },
    "rule": {
        "description": "This is just a dumb policy to test custom policies",
        "name": "My test rule custom",
        "ruleset": "Manuel test policy"
    },
    "sysdig": {
        "event": {
            "category": "runtime",
            "content": {
                "fields": {
                    "evt": {
                        "res": "SUCCESS",
                        "type": "execve"
                    },
                    "proc": {
                        "sid": "1"
                    }
                },
                "origin": "Secure UI",
                "policy_id": "10569534",
                "rule_sub_type": 0,
                "rule_tags": [
                    "My-tag-custom-1-hello-world",
                    "MITTRE-WHATEVER"
                ],
                "rule_type": 6,
                "type": "workloadRuntimeDetection"
            },
            "engine": "falco",
            "labels": {
                "container": {
                    "image": {
                        "id": "ef0f72a55bd2",
                        "repo": "docker.io/library/python",
                        "tag": "3.9.18-slim"
                    },
                    "label": {
                        "io": {
                            "kubernetes": {
                                "container": {
                                    "name": "shell-scripting"
                                },
                                "pod": {
                                    "name": "shell-scripting-29063700-123ab",
                                    "namespace": "default"
                                }
                            }
                        }
                    },
                    "name": "shell-scripting"
                },
                "gcp": {
                    "location": "us-central1",
                    "project_id": "012345678912"
                },
                "kubernetes": {
                    "cron_job": {
                        "name": "shell-scripting"
                    },
                    "job": {
                        "name": "shell-scripting-29063700"
                    },
                    "node": {
                        "name": "gke-cluster-gcp-demo-san-default-pool-12345678-abcd"
                    },
                    "workload": {
                        "name": "shell-scripting"
                    }
                }
            },
            "originator": "policy",
            "raw_event_category": "runtime",
            "raw_event_originator": "linuxAgent",
            "severity_value": "Medium",
            "source_details": {
                "sub_type": "container",
                "type": "workload"
            }
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "sysdig-event"
    ],
    "user": {
        "group": {
            "id": "0",
            "name": "root"
        },
        "id": "0",
        "name": "root"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| sysdig.event.actions.after_event_ns | Duration after the event that the capture spans in nanoseconds. | long |
| sysdig.event.actions.before_event_ns | Duration before the event that the capture spans in nanoseconds. | long |
| sysdig.event.actions.err_msg | When isSuccessful is false, details on why the action failed. | keyword |
| sysdig.event.actions.is_successful | Whether or not the Capture was taken successfully. | boolean |
| sysdig.event.actions.token | Token to retrieve the related capture. | keyword |
| sysdig.event.actions.type | Action type. | keyword |
| sysdig.event.category | The event category. Possible values are runtime, remote, admissionController, cloudtrail, okta, github, falcocloud, miner. | keyword |
| sysdig.event.content.cluster_name | Kubernetes cluster name. | keyword |
| sysdig.event.content.command | The command name. | keyword |
| sysdig.event.content.detected_class_probability | The detected class probability (confidence score). | double |
| sysdig.event.content.exe | The command path. | keyword |
| sysdig.event.content.fields.aws.account_id |  | keyword |
| sysdig.event.content.fields.aws.event_name |  | keyword |
| sysdig.event.content.fields.aws.region |  | keyword |
| sysdig.event.content.fields.aws.source_ip |  | ip |
| sysdig.event.content.fields.aws.user |  | keyword |
| sysdig.event.content.fields.container.id |  | keyword |
| sysdig.event.content.fields.container.image.repository |  | keyword |
| sysdig.event.content.fields.container.image.tag |  | keyword |
| sysdig.event.content.fields.container.label.io.kubernetes.container.name |  | keyword |
| sysdig.event.content.fields.container.label.io.kubernetes.pod.name |  | keyword |
| sysdig.event.content.fields.container.label.io.kubernetes.pod.namespace |  | keyword |
| sysdig.event.content.fields.container.mounts |  | keyword |
| sysdig.event.content.fields.container.name |  | keyword |
| sysdig.event.content.fields.container.name.text | Multi-field of `sysdig.event.content.fields.container.name`. | match_only_text |
| sysdig.event.content.fields.container.privileged |  | boolean |
| sysdig.event.content.fields.ct.id |  | keyword |
| sysdig.event.content.fields.ct.name |  | keyword |
| sysdig.event.content.fields.ct.region |  | keyword |
| sysdig.event.content.fields.ct.request.functionname |  | keyword |
| sysdig.event.content.fields.ct.request.host |  | keyword |
| sysdig.event.content.fields.ct.shortsrc |  | keyword |
| sysdig.event.content.fields.ct.srcdomain |  | keyword |
| sysdig.event.content.fields.ct.srcip |  | ip |
| sysdig.event.content.fields.ct.user.accountid |  | keyword |
| sysdig.event.content.fields.ct.user.arn |  | keyword |
| sysdig.event.content.fields.ct.user.identitytype |  | keyword |
| sysdig.event.content.fields.ct.user.principalid |  | keyword |
| sysdig.event.content.fields.ct.user.value |  | keyword |
| sysdig.event.content.fields.ct.useragent |  | keyword |
| sysdig.event.content.fields.evt.arg.request |  | keyword |
| sysdig.event.content.fields.evt.dir |  | keyword |
| sysdig.event.content.fields.evt.res |  | keyword |
| sysdig.event.content.fields.evt.type |  | keyword |
| sysdig.event.content.fields.fd.directory |  | keyword |
| sysdig.event.content.fields.fd.name |  | keyword |
| sysdig.event.content.fields.fd.sip |  | ip |
| sysdig.event.content.fields.fd.sport |  | long |
| sysdig.event.content.fields.fd.type |  | keyword |
| sysdig.event.content.fields.group.gid |  | keyword |
| sysdig.event.content.fields.group.name |  | keyword |
| sysdig.event.content.fields.proc.acmdline_2 |  | wildcard |
| sysdig.event.content.fields.proc.acmdline_2.text | Multi-field of `sysdig.event.content.fields.proc.acmdline_2`. | match_only_text |
| sysdig.event.content.fields.proc.acmdline_3 |  | wildcard |
| sysdig.event.content.fields.proc.acmdline_3.text | Multi-field of `sysdig.event.content.fields.proc.acmdline_3`. | match_only_text |
| sysdig.event.content.fields.proc.acmdline_4 |  | wildcard |
| sysdig.event.content.fields.proc.acmdline_4.text | Multi-field of `sysdig.event.content.fields.proc.acmdline_4`. | match_only_text |
| sysdig.event.content.fields.proc.aexepath_2 |  | keyword |
| sysdig.event.content.fields.proc.aexepath_2.text | Multi-field of `sysdig.event.content.fields.proc.aexepath_2`. | match_only_text |
| sysdig.event.content.fields.proc.aexepath_3 |  | keyword |
| sysdig.event.content.fields.proc.aexepath_3.text | Multi-field of `sysdig.event.content.fields.proc.aexepath_3`. | match_only_text |
| sysdig.event.content.fields.proc.aexepath_4 |  | keyword |
| sysdig.event.content.fields.proc.aexepath_4.text | Multi-field of `sysdig.event.content.fields.proc.aexepath_4`. | match_only_text |
| sysdig.event.content.fields.proc.aname_2 |  | keyword |
| sysdig.event.content.fields.proc.aname_2.text | Multi-field of `sysdig.event.content.fields.proc.aname_2`. | match_only_text |
| sysdig.event.content.fields.proc.aname_3 |  | keyword |
| sysdig.event.content.fields.proc.aname_3.text | Multi-field of `sysdig.event.content.fields.proc.aname_3`. | match_only_text |
| sysdig.event.content.fields.proc.aname_4 |  | keyword |
| sysdig.event.content.fields.proc.aname_4.text | Multi-field of `sysdig.event.content.fields.proc.aname_4`. | match_only_text |
| sysdig.event.content.fields.proc.args |  | keyword |
| sysdig.event.content.fields.proc.cmdline |  | wildcard |
| sysdig.event.content.fields.proc.cmdline.text | Multi-field of `sysdig.event.content.fields.proc.cmdline`. | match_only_text |
| sysdig.event.content.fields.proc.cwd |  | keyword |
| sysdig.event.content.fields.proc.cwd.text | Multi-field of `sysdig.event.content.fields.proc.cwd`. | match_only_text |
| sysdig.event.content.fields.proc.exepath |  | keyword |
| sysdig.event.content.fields.proc.exepath.text | Multi-field of `sysdig.event.content.fields.proc.exepath`. | match_only_text |
| sysdig.event.content.fields.proc.hash.sha256 |  | keyword |
| sysdig.event.content.fields.proc.name |  | keyword |
| sysdig.event.content.fields.proc.name.text | Multi-field of `sysdig.event.content.fields.proc.name`. | match_only_text |
| sysdig.event.content.fields.proc.pcmdline |  | wildcard |
| sysdig.event.content.fields.proc.pcmdline.text | Multi-field of `sysdig.event.content.fields.proc.pcmdline`. | match_only_text |
| sysdig.event.content.fields.proc.pexepath |  | keyword |
| sysdig.event.content.fields.proc.pexepath.text | Multi-field of `sysdig.event.content.fields.proc.pexepath`. | match_only_text |
| sysdig.event.content.fields.proc.pid |  | long |
| sysdig.event.content.fields.proc.pid_ts |  | date |
| sysdig.event.content.fields.proc.pname |  | keyword |
| sysdig.event.content.fields.proc.pname.text | Multi-field of `sysdig.event.content.fields.proc.pname`. | match_only_text |
| sysdig.event.content.fields.proc.ppid |  | long |
| sysdig.event.content.fields.proc.ppid_ts |  | date |
| sysdig.event.content.fields.proc.sid |  | keyword |
| sysdig.event.content.fields.proc.stderr.name |  | keyword |
| sysdig.event.content.fields.proc.stdin.name |  | keyword |
| sysdig.event.content.fields.proc.stdout.name |  | keyword |
| sysdig.event.content.fields.user.loginname |  | keyword |
| sysdig.event.content.fields.user.loginuid |  | keyword |
| sysdig.event.content.fields.user.name |  | keyword |
| sysdig.event.content.fields.user.uid |  | keyword |
| sysdig.event.content.integration_id | The unique identifier of the integration that generated the event. | keyword |
| sysdig.event.content.integration_type | The type of integration that generated the event. Possible values are cloudtrail, okta, github, gcp, azure. | keyword |
| sysdig.event.content.namespace | Kubernetes namespace. | keyword |
| sysdig.event.content.origin |  | keyword |
| sysdig.event.content.output | Event output, generated after the configured rule. | match_only_text |
| sysdig.event.content.policy_id | ID of the policy that generated the event. | keyword |
| sysdig.event.content.policy_notification_channel_ids | The list of notification channels where an alert is sent after event is generated. Doesn't account for aggregations and eventual thresholds. | keyword |
| sysdig.event.content.policy_origin | The policy author. Possible values are Sysdig, Sysdig UI, Tuner. | keyword |
| sysdig.event.content.policy_version |  | keyword |
| sysdig.event.content.priority | Rule priority. Possible values are emergency, alert, critical, error, warning, informational, notice, debug. | keyword |
| sysdig.event.content.resource_kind | Kubernetes resource kind | keyword |
| sysdig.event.content.resource_name | Kubernetes resource name. | keyword |
| sysdig.event.content.rule_name | Name of the rule the event is generated after. | keyword |
| sysdig.event.content.rule_sub_type |  | long |
| sysdig.event.content.rule_tags | The tags attached to the rule. | keyword |
| sysdig.event.content.rule_type | Rule type. | long |
| sysdig.event.content.run_book | The runbook URL as configured in the policy. | keyword |
| sysdig.event.content.scan_result |  | object |
| sysdig.event.content.sequence.event_id | The unique identifier of the log event. | keyword |
| sysdig.event.content.sequence.event_name | The name of the event. | keyword |
| sysdig.event.content.sequence.event_time | The time when the event occurred. | date |
| sysdig.event.content.sequence.ingestion_id | The unique identifier of the ingestion. | keyword |
| sysdig.event.content.sequence.region | The region where the event occurred. | keyword |
| sysdig.event.content.sequence.source | The source of the event. | keyword |
| sysdig.event.content.sequence.source_ip_address | The IP address of the source. | ip |
| sysdig.event.content.sequence.sub_ingestion_id | The unique identifier of the sub ingestion. | keyword |
| sysdig.event.content.stats.api |  | keyword |
| sysdig.event.content.stats.count |  | long |
| sysdig.event.content.type | The type of the event content. | keyword |
| sysdig.event.content.zones.id | Zone ID. | keyword |
| sysdig.event.content.zones.name | Zone name. | keyword |
| sysdig.event.description | Description of the policy the event is generated after. | match_only_text |
| sysdig.event.engine | The engine used to generate the event out of the raw signal. Possible values are drift, falco, list, machineLearning, malware. | keyword |
| sysdig.event.id | The event id. | keyword |
| sysdig.event.labels.aws.account_id |  | keyword |
| sysdig.event.labels.aws.region |  | keyword |
| sysdig.event.labels.aws.user |  | keyword |
| sysdig.event.labels.azure.instance_id |  | keyword |
| sysdig.event.labels.azure.instance_name |  | keyword |
| sysdig.event.labels.azure.instance_size |  | keyword |
| sysdig.event.labels.azure.location |  | keyword |
| sysdig.event.labels.azure.subscription_id |  | keyword |
| sysdig.event.labels.cloud_provider.account.id |  | keyword |
| sysdig.event.labels.cloud_provider.name |  | keyword |
| sysdig.event.labels.cloud_provider.region |  | keyword |
| sysdig.event.labels.cloud_provider.user |  | keyword |
| sysdig.event.labels.container.image.digest |  | keyword |
| sysdig.event.labels.container.image.id |  | keyword |
| sysdig.event.labels.container.image.repo |  | keyword |
| sysdig.event.labels.container.image.tag |  | keyword |
| sysdig.event.labels.container.label.io.kubernetes.container.name |  | keyword |
| sysdig.event.labels.container.label.io.kubernetes.pod.name |  | keyword |
| sysdig.event.labels.container.label.io.kubernetes.pod.namespace |  | keyword |
| sysdig.event.labels.container.name |  | keyword |
| sysdig.event.labels.gcp.availability_zone |  | keyword |
| sysdig.event.labels.gcp.instance_id |  | keyword |
| sysdig.event.labels.gcp.instance_name |  | keyword |
| sysdig.event.labels.gcp.location |  | keyword |
| sysdig.event.labels.gcp.machine_type |  | keyword |
| sysdig.event.labels.gcp.project_id |  | keyword |
| sysdig.event.labels.gcp.project_name |  | keyword |
| sysdig.event.labels.host.host_name |  | keyword |
| sysdig.event.labels.host.mac |  | keyword |
| sysdig.event.labels.kubernetes.cluster.name |  | keyword |
| sysdig.event.labels.kubernetes.cron_job.name |  | keyword |
| sysdig.event.labels.kubernetes.daemon_set.name |  | keyword |
| sysdig.event.labels.kubernetes.job.name |  | keyword |
| sysdig.event.labels.kubernetes.namespace.name |  | keyword |
| sysdig.event.labels.kubernetes.node.name |  | keyword |
| sysdig.event.labels.kubernetes.pod.name |  | keyword |
| sysdig.event.labels.kubernetes.service.name |  | keyword |
| sysdig.event.labels.kubernetes.workload.name |  | keyword |
| sysdig.event.labels.kubernetes.workload.type |  | keyword |
| sysdig.event.labels.source.ip |  | ip |
| sysdig.event.name | Name of the policy the event is generated after. | keyword |
| sysdig.event.originator | Type of event. Possible values are policy, profilingDetection, falcocloud, admissionController. | keyword |
| sysdig.event.raw_event_category | The semantic category (area) of the event in the Sysdig product. Possible values are kspm, runtime. | keyword |
| sysdig.event.raw_event_originator | The agent type, hosting the engine, that generated the event after the raw event. Possilble values are admissionController, agentless, cloudConnector, linuxAgent, serverlessAgent, windowsAgent. | keyword |
| sysdig.event.severity | The policy severity. | long |
| sysdig.event.severity_value | The policy severity. | keyword |
| sysdig.event.source | Source of the event. Possible values are syscall, windows, profiling, K8SAdmissionController, k8s_audit, aws_cloudtrail, awscloudtrail, agentless-aws-ml, gcp_auditlog, azure_platformlogs, okta, agentless-okta-ml, github. | keyword |
| sysdig.event.source_details.sub_type | A deeper particularization for the type of component that generated the raw event. Possible values are auditlogs, auditWebhooks, caas, dynamicAdmissionControl, host, container, workforce. | keyword |
| sysdig.event.source_details.type | The type of component that generated the raw event. Possible values are cloud, git, iam, kubernetes, workload. | keyword |
| sysdig.event.timestamp | The event timestamp in nanoseconds. | date |

