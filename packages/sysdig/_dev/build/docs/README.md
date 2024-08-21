# Sysdig Integration
This integration allows for the shipping of [Sysdig](https://sysdig.com/) alerts to Elastic for observability and organizational awareness. Alerts can then be analyzed by using either the dashboard included with the integration or via the creation of custom dashboards within Kibana.

## Data Streams
The Sysdig integration collects one type of data stream: logs.

**Logs** The Logs data stream collected by the Sysdig integration is comprised of Sysdig Alerts. See more details about Sysdig Alerts in [Sysdig's Alerts Documentation](https://docs.sysdig.com/en/docs/sysdig-monitor/alerts/). A complete list of potential fields used by this integration can be found in the [Logs reference](#logs-reference)

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

| Field | Description | Type | |
|-------|-------------|------|---|
| sysdig | Namespace for Sysdig-specific fields. | group | |
| sysdig.actions |  | flattened | |
| sysdig.agentId | Agent identifier  | integer | |
| sysdig.category | Event category from Sysdig | keyword | |
| sysdig.containerId | Identifier of the container | text | |
| sysdig.content | Preserved Sysdig fields | group | |
| sysdig.fields |  | group | |
| sysdig.container.image.tag | Tag for the container image | text | |
| sysdig.container.name | Name of the container | text | |
| sysdig.proc.exepath | Path for the current process | text | |
| sysdig.proc.cwd | Current working directory for the current process | text | |
| sysdig.proc.pid | Identifier for the process | text | |
| sysdig.proc.name | Name of the process | text | |
| sysdig.proc.cmdline | Command line args for the process | text | |
| sysdig.proc.ppid | Identifier for the parent process | text | |
| sysdig.proc.pname | Name of the parent process | text | |
| sysdig.proc.pcmdline | Command line args for the parent process | text | |
| sysdig.user.uid | Identifier for the user | text | |
| sysdig.user.name | Name of the user | text | |
| sysdig.output | The raw event output | text | |
| sysdig.policyOrigin | Originator of the rule associated with an event | text | |
| sysdig.policyVersion | Version of the rule associated with an event | integer | |
| sysdig.ruleName | Name of the rule associated with an event | text | |
| sysdig.ruleTags | Tags associated with an event rule | text | |
| sysdig.ruleType | Category of the rule associated with an event | text | |
| sysdig.description | Description of the event policy| text | |
| sysdig.hostMac | MAC address of the host machine | text | |
| sysdig.id | Event identifier | text | |
| sysdig.labels |  | group | |
| sysdig.azure.instanceId | Instance identifier for the azure instance | text | |
| sysdig.azure.instanceName | Instance name for the azure instance | text | |
| sysdig.azure.instanceSize | Size for the azure instance | text | |
| sysdig.cloudProvider.account.id | Account identifier for the cloud provider | text | |
| sysdig.cloudProvider.name | Account identifier for the cloud provider | text | |
| sysdig.cloudProvider.region | Region for the cloud provider | text | |
| sysdig.gcp.availabilityZone | AZ for the gcp instance | text | |
| sysdig.gcp.instanceId | Instance identifier for the gcp instance | text | |
| sysdig.gcp.instanceName | Instance name for the gcp instance | text | |
| sysdig.gcp.machineType | Machine type for the gcp instance | text | |
| sysdig.gcp.projectId | Project identifier for the gcp instance | text | |
| sysdig.gcp.projectName | Project name for the gcp instance | text | |
| sysdig.kubernetes.cluster.name | Name of the k8s cluster | text | |
| sysdig.kubernetes.namespace.name | Namespace of the k8s cluster | text | |
| sysdig.kubernetes.pod.name | Name of the k8s pod | text | |
| sysdig.kubernetes.workload.type | Type of k8s resource | text | |
| sysdig.machineId | Identifier of the host machine | text | |
| sysdig.name | Name of the event policy | text | |
| sysdig.originator | No description available | text | |
| sysdig.severity | Numerical severity value associated with an event | integer | |
| sysdig.source | Event source | text | |
| sysdig.timestamp | Timestamp of the event | date | |
| sysdig.timestampRFC3339Nano | Timestamp of the event | date | |
| sysdig.type | No description available | text | |
| SysdigEvent | In the case of policies, value should come through as "policy" | group | |
| SysdigEvent.category | Incoming field parent | text | |
| SysdigEvent.description | No description available | text | |
| SysdigEvent.type | No description available  | text | |



An example event for `alerts` looks as following:

```json
{
    "@timestamp": "2024-08-20T16:36:35.163Z",
    "agent": {
        "ephemeral_id": "52430758-651f-44dd-a22b-2b5e78fc9203",
        "id": "3e950939-c5ec-4fc4-bf61-df778a2bbce1",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.14.1"
    },
    "data_stream": {
        "dataset": "sysdig.alerts",
        "namespace": "66756",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "3e950939-c5ec-4fc4-bf61-df778a2bbce1",
        "snapshot": false,
        "version": "8.14.1"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "sysdig.alerts",
        "ingested": "2024-08-20T16:36:45Z",
        "kind": "alert",
        "original": "{\"agentId\":58014837,\"category\":\"runtime\",\"containerId\":\"6949e5f10829\",\"content\":{\"baselineId\":\"\",\"falsePositive\":false,\"fields\":{\"container.id\":\"6949e5f10829\",\"container.image.repository\":\"docker.io/dockerbadboy/art\",\"container.name\":\"threatgen\",\"evt.arg.request\":\"\\u003cNA\\u003e\",\"evt.type\":\"execve\",\"falco.rule\":\"User Management Event Detected\",\"fd.name\":\"\\u003cNA\\u003e\",\"group.gid\":\"0\",\"group.name\":\"root\",\"proc.aname[2]\":\"containerd-shim\",\"proc.aname[3]\":\"\\u003cNA\\u003e\",\"proc.aname[4]\":\"\\u003cNA\\u003e\",\"proc.args\":\"tmp_suid_user\",\"proc.cmdline\":\"userdel tmp_suid_user\",\"proc.cwd\":\"/tmp/\",\"proc.exepath\":\"/usr/sbin/userdel\",\"proc.name\":\"userdel\",\"proc.pcmdline\":\"pwsh -c (./RunTests.ps1 STDIN.NETWORK DEV.SHM.EXEC T1048 RECON.FIND.SUID T1611.002 CONTAINER.ESCAPE.NSENTER CREDS.DUMP.MEMORY KILL.MALICIOUS.PROC LOAD.BPF.PROG Base64.PYTHON BASE64.CLI CONNECT.UNEXPECTED RECON.GPG SUBTERFUGE.LASTLOG LD.LINUX.EXEC LD.SO.PRELOAD USERFAULTFD.HANDLER RECON.LINPEAS PROOT.EXEC)\",\"proc.pid\":\"2140169\",\"proc.pname\":\"pwsh\",\"proc.ppid\":\"2140088\",\"proc.sid\":\"1\",\"user.loginname\":\"\\u003cNA\\u003e\",\"user.loginuid\":\"-1\",\"user.name\":\"root\",\"user.uid\":\"0\"},\"matchedOnDefault\":false,\"output\":\"Users management command userdel tmp_suid_user launched by pwsh on threatgen under user root (proc.name=userdel proc.args=tmp_suid_user fd.name=\\u003cNA\\u003e proc.cmdline=pwsh -c (./RunTests.ps1 STDIN.NETWORK DEV.SHM.EXEC T1048 RECON.FIND.SUID T1611.002 CONTAINER.ESCAPE.NSENTER CREDS.DUMP.MEMORY KILL.MALICIOUS.PROC LOAD.BPF.PROG Base64.PYTHON BASE64.CLI CONNECT.UNEXPECTED RECON.GPG SUBTERFUGE.LASTLOG LD.LINUX.EXEC LD.SO.PRELOAD USERFAULTFD.HANDLER RECON.LINPEAS PROOT.EXEC) proc.pname=pwsh gparent=containerd-shim ggparent=\\u003cNA\\u003e gggparent=\\u003cNA\\u003e container=container_id=6949e5f10829 container_name=threatgen evt.type=execve evt.arg.request=\\u003cNA\\u003e proc.pid=2140169 proc.cwd=/tmp/ proc.ppid=2140088 proc.pcmdline=pwsh -c (./RunTests.ps1 STDIN.NETWORK DEV.SHM.EXEC T1048 RECON.FIND.SUID T1611.002 CONTAINER.ESCAPE.NSENTER CREDS.DUMP.MEMORY KILL.MALICIOUS.PROC LOAD.BPF.PROG Base64.PYTHON BASE64.CLI CONNECT.UNEXPECTED RECON.GPG SUBTERFUGE.LASTLOG LD.LINUX.EXEC LD.SO.PRELOAD USERFAULTFD.HANDLER RECON.LINPEAS PROOT.EXEC) proc.sid=1 proc.exepath=/usr/sbin/userdel user.uid=0 user.loginuid=-1 user.loginname=\\u003cNA\\u003e user.name=root group.gid=0 group.name=root container.id=6949e5f10829 container.name=threatgen image=docker.io/dockerbadboy/art)\",\"policyId\":10011704,\"policyOrigin\":\"Sysdig\",\"policyVersion\":35,\"ruleName\":\"User Management Event Detected\",\"ruleTags\":[\"host\",\"container\",\"MITRE\",\"MITRE_TA0003_persistence\",\"MITRE_T1136_create_account\",\"MITRE_T1136.001_create_account_local_account\",\"MITRE_T1070_indicator_removal\",\"MITRE_TA0005_defense_evasion\",\"MITRE_TA0040_impact\",\"MITRE_T1531_account_access_removal\",\"MITRE_T1098_account_manipulation\"],\"ruleType\":\"RULE_TYPE_FALCO\"},\"description\":\"This policy contains rules which provide a greater insight into general activities occuring on the system. They are very noisy, but useful in threat hunting situations if you are looking for specific actions being taken during runtime. It is not recommended to use this policy for detection purposes unless tuning is enabled.  Additional manual tuning will likely be required.\",\"hostMac\":\"42:01:0a:80:00:05\",\"id\":\"17dec715376910362c8c3f62a4ceda2e\",\"labels\":{\"cloudProvider.account.id\":\"289645096542\",\"cloudProvider.name\":\"gcp\",\"cloudProvider.region\":\"us-central1\",\"container.image.digest\":\"sha256:26928291789494be49b14bf90b0c50950e9e802c86c2a9dd245b88032d6c9c07\",\"container.image.id\":\"15a18c24b1ee\",\"container.image.repo\":\"docker.io/dockerbadboy/art\",\"container.image.tag\":\"latest\",\"container.label.io.kubernetes.container.name\":\"threatgen\",\"container.label.io.kubernetes.pod.name\":\"threatgen-c65cf6446-5s8kk\",\"container.label.io.kubernetes.pod.namespace\":\"default\",\"container.name\":\"threatgen\",\"gcp.availabilityZone\":\"us-central1-c\",\"gcp.image\":\"projects/gke-node-images/global/images/gke-1289-gke1000000-cos-109-17800-147-54-c-pre\",\"gcp.instanceId\":\"648229130641697246\",\"gcp.instanceName\":\"gke-cluster-gcp-demo-san-default-pool-66250c41-vd1o\",\"gcp.machineType\":\"e2-standard-4\",\"gcp.projectId\":\"289645096542\",\"gcp.projectName\":\"alliances-chronicle\",\"gcp.region\":\"us-central1\",\"host.hostName\":\"gke-cluster-gcp-demo-san-default-pool-66250c41-vd1o\",\"host.mac\":\"42:01:0a:80:00:05\",\"kubernetes.cluster.name\":\"gke-alliances-demo-6\",\"kubernetes.deployment.name\":\"threatgen\",\"kubernetes.namespace.name\":\"default\",\"kubernetes.node.name\":\"gke-cluster-gcp-demo-san-default-pool-66250c41-vd1o\",\"kubernetes.pod.name\":\"threatgen-c65cf6446-5s8kk\",\"kubernetes.replicaSet.name\":\"threatgen-c65cf6446\",\"kubernetes.workload.name\":\"threatgen\",\"kubernetes.workload.type\":\"deployment\",\"process.name\":\"userdel tmp_suid_user\"},\"machineId\":\"42:01:0a:80:00:05\",\"name\":\"Sysdig Runtime Activity Logs\",\"originator\":\"policy\",\"severity\":7,\"source\":\"syscall\",\"timestamp\":1720031001639981110,\"timestampRFC3339Nano\":\"2024-07-03T18:23:21.63998111Z\",\"type\":\"policy\"}",
        "timezone": "+00:00"
    },
    "input": {
        "type": "http_endpoint"
    },
    "json": {
        "agentId": 58014837,
        "category": "runtime",
        "containerId": "6949e5f10829",
        "content": {
            "baselineId": "",
            "falsePositive": false,
            "fields": {
                "container.id": "6949e5f10829",
                "container.image.repository": "docker.io/dockerbadboy/art",
                "container.name": "threatgen",
                "evt.arg.request": "<NA>",
                "evt.type": "execve",
                "falco.rule": "User Management Event Detected",
                "fd.name": "<NA>",
                "group.gid": "0",
                "group.name": "root",
                "proc.aname[2]": "containerd-shim",
                "proc.aname[3]": "<NA>",
                "proc.aname[4]": "<NA>",
                "proc.args": "tmp_suid_user",
                "proc.cmdline": "userdel tmp_suid_user",
                "proc.cwd": "/tmp/",
                "proc.exepath": "/usr/sbin/userdel",
                "proc.name": "userdel",
                "proc.pcmdline": "pwsh -c (./RunTests.ps1 STDIN.NETWORK DEV.SHM.EXEC T1048 RECON.FIND.SUID T1611.002 CONTAINER.ESCAPE.NSENTER CREDS.DUMP.MEMORY KILL.MALICIOUS.PROC LOAD.BPF.PROG Base64.PYTHON BASE64.CLI CONNECT.UNEXPECTED RECON.GPG SUBTERFUGE.LASTLOG LD.LINUX.EXEC LD.SO.PRELOAD USERFAULTFD.HANDLER RECON.LINPEAS PROOT.EXEC)",
                "proc.pid": "2140169",
                "proc.pname": "pwsh",
                "proc.ppid": "2140088",
                "proc.sid": "1",
                "user.loginname": "<NA>",
                "user.loginuid": "-1",
                "user.name": "root",
                "user.uid": "0"
            },
            "matchedOnDefault": false,
            "output": "Users management command userdel tmp_suid_user launched by pwsh on threatgen under user root (proc.name=userdel proc.args=tmp_suid_user fd.name=<NA> proc.cmdline=pwsh -c (./RunTests.ps1 STDIN.NETWORK DEV.SHM.EXEC T1048 RECON.FIND.SUID T1611.002 CONTAINER.ESCAPE.NSENTER CREDS.DUMP.MEMORY KILL.MALICIOUS.PROC LOAD.BPF.PROG Base64.PYTHON BASE64.CLI CONNECT.UNEXPECTED RECON.GPG SUBTERFUGE.LASTLOG LD.LINUX.EXEC LD.SO.PRELOAD USERFAULTFD.HANDLER RECON.LINPEAS PROOT.EXEC) proc.pname=pwsh gparent=containerd-shim ggparent=<NA> gggparent=<NA> container=container_id=6949e5f10829 container_name=threatgen evt.type=execve evt.arg.request=<NA> proc.pid=2140169 proc.cwd=/tmp/ proc.ppid=2140088 proc.pcmdline=pwsh -c (./RunTests.ps1 STDIN.NETWORK DEV.SHM.EXEC T1048 RECON.FIND.SUID T1611.002 CONTAINER.ESCAPE.NSENTER CREDS.DUMP.MEMORY KILL.MALICIOUS.PROC LOAD.BPF.PROG Base64.PYTHON BASE64.CLI CONNECT.UNEXPECTED RECON.GPG SUBTERFUGE.LASTLOG LD.LINUX.EXEC LD.SO.PRELOAD USERFAULTFD.HANDLER RECON.LINPEAS PROOT.EXEC) proc.sid=1 proc.exepath=/usr/sbin/userdel user.uid=0 user.loginuid=-1 user.loginname=<NA> user.name=root group.gid=0 group.name=root container.id=6949e5f10829 container.name=threatgen image=docker.io/dockerbadboy/art)",
            "policyId": 10011704,
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
        "hostMac": "42:01:0a:80:00:05",
        "id": "17dec715376910362c8c3f62a4ceda2e",
        "labels": {
            "cloudProvider.account.id": "289645096542",
            "cloudProvider.name": "gcp",
            "cloudProvider.region": "us-central1",
            "container.image.digest": "sha256:26928291789494be49b14bf90b0c50950e9e802c86c2a9dd245b88032d6c9c07",
            "container.image.id": "15a18c24b1ee",
            "container.image.repo": "docker.io/dockerbadboy/art",
            "container.image.tag": "latest",
            "container.label.io.kubernetes.container.name": "threatgen",
            "container.label.io.kubernetes.pod.name": "threatgen-c65cf6446-5s8kk",
            "container.label.io.kubernetes.pod.namespace": "default",
            "container.name": "threatgen",
            "gcp.availabilityZone": "us-central1-c",
            "gcp.image": "projects/gke-node-images/global/images/gke-1289-gke1000000-cos-109-17800-147-54-c-pre",
            "gcp.instanceId": "648229130641697246",
            "gcp.instanceName": "gke-cluster-gcp-demo-san-default-pool-66250c41-vd1o",
            "gcp.machineType": "e2-standard-4",
            "gcp.projectId": "289645096542",
            "gcp.projectName": "alliances-chronicle",
            "gcp.region": "us-central1",
            "host.hostName": "gke-cluster-gcp-demo-san-default-pool-66250c41-vd1o",
            "host.mac": "42:01:0a:80:00:05",
            "kubernetes.cluster.name": "gke-alliances-demo-6",
            "kubernetes.deployment.name": "threatgen",
            "kubernetes.namespace.name": "default",
            "kubernetes.node.name": "gke-cluster-gcp-demo-san-default-pool-66250c41-vd1o",
            "kubernetes.pod.name": "threatgen-c65cf6446-5s8kk",
            "kubernetes.replicaSet.name": "threatgen-c65cf6446",
            "kubernetes.workload.name": "threatgen",
            "kubernetes.workload.type": "deployment",
            "process.name": "userdel tmp_suid_user"
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
    "rule": {
        "author": [
            ""
        ]
    },
    "tags": [
        "forwarded",
        "preserve_original_event"
    ]
}
```