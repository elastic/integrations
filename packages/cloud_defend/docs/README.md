# Overview

Elastic Defend for Containers (D4C) provides cloud-native runtime protections for containerized environments by identifying and/or blocking unexpected system behavior in Kubernetes environments.

As a general principle, cloud-native containers are ‘[immutable](https://kubernetes.io/docs/concepts/containers/)’, meaning that changes to the container file system are unexpected during the course of normal operations. Leveraging this principle allows application and security teams the ability to detect unusual system behavior with a high degree of accuracy— without relying on more techniques like memory scanning or attack signatures which can consume more system resources.

When this integration is used alongside containers built with this philosophy, security teams can enjoy
* **Restricted lateral movement**: LSM blocking does not rely on system call interpolation. This means that this integration is not subject to scaling limitations in multiprocessor systems nor [TOCTOU](https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use) race conditions.
* **Reduced attack surface**: Leaner containers give attackers less room to maneuver and hide. File system blocking makes containers protected by D4C hostile to attackers.
* **Easily identify unauthorized operations**: When a properly configured system alerts, the policy protecting the system either needs to be updated, or unauthorized behavior has been identified.
* **Enforce cloud-native security posture**: Enforcing the principle of immutability isn’t something that can be easily achieved without enforcing read-only file systems, which can be too restrictive for many customers.  D4C allows teams the ability to enforce immutability centrally, but allow for enough flexbility to enable productivity.

# Features

## Drift Prevention

The Drift Prevention feature of D4C is enabled via YAML drift prevention policies. These policies specify which containers, system operations and portions of the container file system that a specified action(s) should be taken on.

The system is controlled via a powerful and flexible policy engine which allows users to specify system and Kubernetes attributes as `selectors` (specific `operations` and portions of the system that a policy is applied to) and `responses` (actions the user would like to take when a selector is matched with attempted system operations).

## Deployment

The system is deployed using the Elastic Agent, as a daemonset on each node in a Kubernetes cluster.

Policies that are unique to a given environment are crafted and applied to a given agent policy. This agent policy can be unique to a nodes in a specific Kubernetes cluster, or can apply to nodes spanning multiple Kubernetes clusters.

Policies can be applied to subsets of containers deployed on a given node using policy selectors.

## Drift Prevention Policy

A drift prevention YAML policy governs allowable system behaviors and responses for both `process` and `file` operations across a number of nodes within an Elastic agent policy.

A given policy must contain at least one `selector` (file or process) and one `response`.
```
  file:
    selectors:
      - name: exampleFile
        operation: [createFile, modifyFile]
    responses:
      - match: [exampleFile]
        actions: [block, alert]
  process:
    selectors:
      - name: exampleProcess
        operation: [fork, exec]
    responses:
      - match: [exampleProcess]
        actions: [log]
```

> Due to the fact that `file` and `process` operations happen asynchronously, their `selectors` and `responses` must be managed as separate entities. A file selector cannot be used to trigger a process response and vice versa.

# Selectors

A selector tells the system what system operations to match on and has a number of conditions that can be grouped together (using a logical AND operation) to provide precise control.
```
  - name: exampleFileSelector
    operation: [createExecutable, modifyExecutable]
    containerImageName: [nginx]
    containerImageTag: [latest]
    targetFilePath: [/usr/bin/**]
    orchestratorClusterId: [cluster1]
    orchestratorClusterName: [stagingCluster]
    orchestratorNamespace: [default]
    orchestratorResourceLabel: [‘production:*’]
    orchestratorResourceName: [‘nginx-pod-*’]
    orchestratorType: [kubernetes]
    ignoreVolumeMounts: true
```

A selector MUST contain a name and at least one of the following conditions.

## Common Conditions *(available for both file and process selectors)*

| Name      | Description |
| --------- | ----------- |
| **containerImageName** | A list of container image names to match on. Substrings of container image names are supported using wildcards (for example `containerImageName: elastic-a*` will match on `elastic-agent` as well as `elastic-agent-complete`) |
| **containerImageTag** | A list of container image tags to match on. Wildcards are allowed. |
| **fullContainerImageName** | A list of container image names with tag to match on. Wildcards are allowed.
| **orchestratorClusterId** | A list of cluster IDs to match on.
| **orchestratorClusterName** | A list of cluster names to match on.
| **orchestratorNamespace** | A list of cluster namespaces to match on. Wildcards are supported.
| **orchestratorResourceName** | A list of resource names that the selector will match on. TBD. |
| **orchestratorType** | A list defining which orchestrator engine type the policy and operation should match on. `kubernetes` is the only supported orchestratorType at this time. |
| **orchestratorResourceLabel** | A list of resource labels. Wildcards are supported on label values, but not on label keys. |

&nbsp;

> For example, the following selector will match attempts to create executables on any portion of a file system, in any container as long as those containers are annotated with the `environment` key,  and have the  `owner:drohan` label fully defined:
```
- name:
  operation: [createExecutable]
  orchestratorResourceLabel: [environment:*, owner:drohan]
```

## File Specific Conditions

| Name      | Description |
| --------- | ----------- |
| **operation** | The list of system operations to match on. Options include `createExecutable`, `modifyExecutable`, `createFile`, `modifyFile`, `deleteFile`.
| **ignoreVolumeMounts** | If set, ignores file operations on ALL volume mounts.
| **ignoreVolumeFiles** | If set, ignores operations on file mounts only. e.g. mounted files, configMaps, secrets etc...
| **targetFilePath** | A list of file paths to include.  Paths are absolute and wildcards are supported.

&nbsp;

> Consider the following selector example:
```
- name:
  targetFilePath: [/usr/bin/echo, /usr/sbin*, /usr/local/**]
```

In this example,
-  `/usr/bin/echo` will match on the `echo` binary, and only this binary
-  `/usr/local/**` will match on everything recursively under `/usr/local` including `/usr/local/bin/something`
-  `/usr/bin/*` includes everything that’s a direct child of /usr/bin

## Process Specific Conditions

| Name      | Description |
| --------- | ----------- |
| **operation** | The list of system operations to match on. Options include `fork` and `exec`.
| **processExecutable** | A list of executables (full path included) to match on. Wildcards are supported.
| **processName** | A list of process names (executable basename) to match on. e.g. 'bash or vi'.
| **processUserName** | A list of process user names to match on. e.g. 'root'.
| **processUserId** | A list of process user ids to match on. e.g. '0'.
| **sessionLeaderInteractive** | If set to true, will only match on interactive sessions (i.e. sessions with a controlling TTY)
| **sessionLeaderExecutable** | A list of session leader executables (full path included) to match on. e.g. `/bin/bash, /bin/zsh...`. **(coming soon)**

# Responses

Responses instruct the system on what `actions` to take when system operations match `selectors`.

A policy can contain one or more responses. Each response is comprised of the following:
```
responses:
  - match: [allProcesses] exclude: [excludeSystemDServices]
    actions: [log]
  - match: [nefariousActivity]
    actions: [alert, block]
```

| Response Field | Description |
| --------- | ----------- |
| **match** | An array of one or more selectors of the same type (`file` or `process`). Evaluated as a logical OR operation |
| **exclude** | An **optional** array of selectors exceptions of the same type. Evaluated as a logical OR operation |
| **actions** | An array of actions to perform. Options include `log`, `alert` and `block`. |

&nbsp;

| Action | Description |
| --------- | ----------- |
| `log`  | Sends events to the `logs-cloud_defend.file-*` data stream for `file` responses, and the `logs-cloud_defend.process-*` data stream for `process` responses. |
| `alert` | Writes events (file or process) to the `logs-cloud_defend.alerts-*` data stream. |
| `block` | Prevents the system operation from proceeding. This blocking action happens *prior* to the execution of the event. It is required that the `alert` action be set if `block` is enabled. *Note: Currently `block` is only supported on file operations. Process blocking coming soon!* |

# Process Events

| Field | Examples |
| --------- | ----------- |
| @timestamp | '2023-03-20T16:03:59.520Z' |
| agent.id  | '7829f26d-c2d1-4eaf-a1ac-cd9cb9e12f75' |
| agent.type | 'cloud-defend' |
| agent.version | '8.8.0' |
| cloud.account.id | '1234567abc' |
| cloud.account.name | 'elastic-dev' |
| cloud.availability_zone | us-east-1c |
| cloud.project.id | '123456abc' |
| cloud.project.name | 'staging' |
| cloud.provider | aws |
| cloud.region | 'us-east-1' |
| cloud_defend.matched_selectors | ['interactiveSessions'] |
| cloud_defend.package_policy_id | 4c9cbba0-c812-11ed-a8dd-91ec403e4f03 |
| cloud_defend.package_policy_version | 2 |
| cloud_defend.trace_point | ... |
| container.id | nginx_1
| container.image.name | nginx |
| container.image.tag | latest |
| data_stream.dataset | 'cloud_defend.process' |
| data_stream.namespace | 'default' |
| data_stream.type | 'logs' |
| ecs.version | 8.7.0 |
| event.action | 'fork', 'exec', 'end' |
| event.agent_id_status | 'verified' |
| event.category | 'process' |
| event.created | '2023-03-20T16:03:59.520Z' |
| event.dataset | 'cloud_defend.process' |
| event.id | '3ee85eee-72d9-4e9d-934f-3787952ca830' |
| event.ingested | '2023-03-20T16:04:12Z' |
| event.kind | 'event', 'alert' |
| event.type | 'start', 'end', 'denied' |
| group.id | '0' |
| group.name | 'root' |
| host.architecture | 'amd64' |
| host.boot.id | '815a760f-8153-49e1-9d0b-da0d3b2a468c' |
| host.id | '1bb9e6a948dfb1c3cd38d1fdc8de4481' |
| host.ip | ['127.0.0.1', '172.20.0.2', '172.18.0.6'] |
| host.hostname | 'docker-custom-agent' |
| host.mac | ['32:a9:cc:26:4c:e5', '7a:ec:f0:3e:29:ee'] |
| host.name | 'docker-custom-agent' |
| host.os.family | 'ubuntu' |
| host.os.full | 'Ubuntu 20.04.5' |
| host.os.kernel | '5.10.161+ #1 SMP Thu Jan 5 22:49:42 UTC 2023' |
| host.os.name | 'Linux |
| host.os.platform | 'ubuntu' |
| host.os.type | 'linux' |
| host.os.version | '20.04.5' |
| host.pid_ns_ino | 4026531836 |
| message | 'cloud-defend process event' |
| orchestrator.cluster.id | '12345' |
| orchestrator.cluster.name | 'website' |
| orchestrator.namespace | default |
| orchestrator.resource.ip | '172.18.0.6' |
| orchestrator.resource.name | webapp-proxy |
| orchestrator.resource.parent.type | ... |
| orchestrator.resource.type | pod |
| process.args | ['ls', '--color=auto'] |
| process.end | '2023-03-20T16:04:12Z' |
| process.entity_id | 'NzgyOWYyNmQtYzJkMS00ZWFmLWExYWMtY2Q5Y2I5ZTEyZjc1LTE5MTU1MzUtMTY3OTMyODIzOQ==' |
| process.entry_leader.args | ['bash'] |
| process.entry_leader.entity_id | 'NzgyOWYyNmQtYzJkMS00ZWFmLWExYWMtY2Q5Y2I5ZTEyZjc1LTE5MTU1MzUtMTY3OTMyODIzOQ==' |
| process.entry_leader.entry_meta.type | 'container' |
| process.entry_leader.executable | '/bin/bash' |
| process.entry_leader.group.id | '0' |
| process.entry_leader.group.name | 'root' |
| process.entry_leader.interactive | true |
| process.entry_leader.name | 'bash' |
| process.entry_leader.pid | 1915529 |
| process.entry_leader.same_as_process | false |
| process.entry_leader.start | '2023-03-20T16:03:59.520Z' |
| process.entry_leader.user.id | '0' |
| process.entry_leader.user.name | 'root' |
| process.entry_leader.working_directory | '/usr/share/elastic-agent'
| process.executable | '/usr/bin/ls' |
| process.group_leader.args | ['ls', '--color=auto'] |
| process.group_leader.entity_id | 'NzgyOWYyNmQtYzJkMS00ZWFmLWExYWMtY2Q5Y2I5ZTEyZjc1LTE5MTU1MzUtMTY3OTMyODIzOQ==' |
| process.group_leader.executable | '/usr/bin/ls' |
| process.group_leader.group.id | '0' |
| process.group_leader.group.name | 'root' |
| process.group_leader.interactive | true |
| process.group_leader.name | 'ls' |
| process.group_leader.pid | 1915529 |
| process.group_leader.same_as_process | true |
| process.group_leader.start | '2023-03-20T16:03:59.520Z' |
| process.group_leader.user.id | '0' |
| process.group_leader.user.name | 'root' |
| process.group_leader.working_directory | '/usr/share/elastic-agent'
| process.interactive | true |
| process.name | 'ls' |
| process.parent.args | ['bash'] |
| process.parent.entity_id | 'NzgyOWYyNmQtYzJkMS00ZWFmLWExYWMtY2Q5Y2I5ZTEyZjc1LTE5MTU1MzUtMTY3OTMyODIzOQ==' |
| process.parent.executable | '/bin/bash' |
| process.parent.group.id | '0' |
| process.parent.group.name | 'root' |
| process.parent.interactive | true |
| process.parent.name | 'bash' |
| process.parent.pid | 1915529 |
| process.parent.same_as_process | false |
| process.parent.start | '2023-03-20T16:03:59.520Z' |
| process.parent.user.id | '0' |
| process.parent.user.name | 'root' |
| process.parent.working_directory | '/usr/share/elastic-agent'
| process.pid | 1916234 |
| process.previous | [{ args: ['bash'], executable: '/bin/bash'}] |
| process.previous.args | ['bash']
| process.previous.executable | '/bin/bash' |
| process.session_leader.args | ['bash'] |
| process.session_leader.entity_id | 'NzgyOWYyNmQtYzJkMS00ZWFmLWExYWMtY2Q5Y2I5ZTEyZjc1LTE5MTU1MzUtMTY3OTMyODIzOQ==' |
| process.session_leader.entry_meta.type | 'container' |
| process.session_leader.executable | '/bin/bash' |
| process.session_leader.group.id | '0' |
| process.session_leader.group.name | 'root' |
| process.session_leader.interactive | true |
| process.session_leader.name | 'bash' |
| process.session_leader.pid | 1915529 |
| process.session_leader.same_as_process | false |
| process.session_leader.start | '2023-03-20T16:03:59.520Z' |
| process.session_leader.user.id | '0' |
| process.session_leader.user.name | 'root' |
| process.session_leader.working_directory | '/usr/share/elastic-agent'
| process.start | '2023-03-20T16:03:59.520Z' |
| process.working_directory | '/usr/share/elastic-agent' |
| user.id | '0' |
| user.name | 'root' |

# File Events

| Field | Examples |
| --------- | ----------- |
| @timestamp | '2023-03-20T16:03:59.520Z' |
| agent.id  | '7829f26d-c2d1-4eaf-a1ac-cd9cb9e12f75' |
| agent.type | 'cloud-defend' |
| agent.version | '8.8.0' |
| cloud.account.id | '1234567abc' |
| cloud.account.name | 'elastic-dev' |
| cloud.availability_zone | us-east-1c |
| cloud.project.id | '123456abc' |
| cloud.project.name | 'staging' |
| cloud.provider | aws |
| cloud.region | 'us-east-1' |
| cloud_defend.matched_selectors | ['binModifications'] |
| cloud_defend.package_policy_id | 4c9cbba0-c812-11ed-a8dd-91ec403e4f03 |
| cloud_defend.package_policy_version | 2 |
| cloud_defend.trace_point | One of: lsm__path_chmod, lsm__path_mknod, lsm__file_open, lsm__path_truncate, lsm__path_rename, lsm__path_link, lsm__path_unlink |
| container.id | nginx_1
| container.image.name | nginx |
| container.image.tag | latest |
| data_stream.dataset | 'cloud_defend.process' |
| data_stream.namespace | 'default' |
| data_stream.type | 'logs' |
| ecs.version | 8.7.0 |
| event.action | 'creation', 'modification', 'deletion', 'rename', 'link', 'open' |
| event.agent_id_status | 'verified' |
| event.category | 'process' |
| event.created | '2023-03-20T16:03:59.520Z' |
| event.dataset | 'cloud_defend.process' |
| event.id | '3ee85eee-72d9-4e9d-934f-3787952ca830' |
| event.ingested | '2023-03-20T16:04:12Z' |
| event.kind | 'event', 'alert' |
| event.type | 'start', 'end', 'denied' |
| file.extension | ts |
| file.name | script.ts |
| file.path | /home/workspace/project/script.ts |
| group.id | '0' |
| group.name | 'root' |
| host.architecture | 'amd64' |
| host.boot.id | '815a760f-8153-49e1-9d0b-da0d3b2a468c' |
| host.id | '1bb9e6a948dfb1c3cd38d1fdc8de4481' |
| host.ip | ['127.0.0.1', '172.20.0.2', '172.18.0.6'] |
| host.hostname | 'docker-custom-agent' |
| host.mac | ['32:a9:cc:26:4c:e5', '7a:ec:f0:3e:29:ee'] |
| host.name | 'docker-custom-agent' |
| host.os.family | 'ubuntu' |
| host.os.full | 'Ubuntu 20.04.5' |
| host.os.kernel | '5.10.161+ #1 SMP Thu Jan 5 22:49:42 UTC 2023' |
| host.os.name | 'Linux |
| host.os.platform | 'ubuntu' |
| host.os.type | 'linux' |
| host.os.version | '20.04.5' |
| host.pid_ns_ino | 4026531836 |
| message | 'cloud-defend file event' |
| orchestrator.cluster.id | '12345' |
| orchestrator.cluster.name | 'website' |
| orchestrator.namespace | default |
| orchestrator.resource.ip | '172.18.0.6' |
| orchestrator.resource.name | webapp-proxy |
| orchestrator.resource.parent.type | ... |
| orchestrator.resource.type | pod |
| process.entity_id | 'NzgyOWYyNmQtYzJkMS00ZWFmLWExYWMtY2Q5Y2I5ZTEyZjc1LTE5MTU1MzUtMTY3OTMyODIzOQ==' |
| process.entry_leader.entity_id | 'NzgyOWYyNmQtYzJkMS00ZWFmLWExYWMtY2Q5Y2I5ZTEyZjc1LTE5MTU1MzUtMTY3OTMyODIzOQ==' |
| process.executable | '/usr/bin/vi' |
| process.group_leader.entity_id | 'NzgyOWYyNmQtYzJkMS00ZWFmLWExYWMtY2Q5Y2I5ZTEyZjc1LTE5MTU1MzUtMTY3OTMyODIzOQ==' |
| process.interactive | true |
| process.name | 'vi' |
| process.parent.entity_id | 'NzgyOWYyNmQtYzJkMS00ZWFmLWExYWMtY2Q5Y2I5ZTEyZjc1LTE5MTU1MzUtMTY3OTMyODIzOQ==' |
| process.pid | 1916234 |
| process.session_leader.entity_id | 'NzgyOWYyNmQtYzJkMS00ZWFmLWExYWMtY2Q5Y2I5ZTEyZjc1LTE5MTU1MzUtMTY3OTMyODIzOQ==' |
| process.user.id | '0' |
| process.user.name | 'root' |
| user.id | '0' |
| user.name | 'root' |
