> This integration is currently **Beta**

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

The service is controlled via a powerful and flexible policy engine which allows users to specify system and Kubernetes attributes as `selectors` (specific `operations` and portions of the system that a policy is applied to) and `responses` (actions the user would like to take when a selector is matched with attempted system operations).

## Deployment

The service can be deployed in two ways: declaratively using Elastic Agent in standalone mode, or as a managed D4C integration through Fleet. With the former, teams have the flexibility to integrate their policies into Git for an infrastructure-as-code (IoC) approach, streamlining the deployment process and enabling easier management.

## Drift Prevention Policy

A drift prevention YAML policy governs allowable system behaviors and responses for both `process` and `file` operations across a number of nodes within an Elastic agent policy.

A given policy must contain at least one `selector` (file or process) and one `response`.
```
  process:
    selectors:
      - name: allProcesses
        operation: [fork, exec]
      - name: interactiveProcesses
        operation: [fork, exec]
        sessionLeaderInteractive: true
    responses:
      - match: [allProcesses]
        actions: [log]
      - match: [interactiveProcesses]
        actions: [alert]
  file:
    selectors:
      - name: executableChanges
        operation: [createExecutable, modifyExecutable]
    responses:
      - match: [executableChanges]
        actions: [alert]
```

> Due to the fact that `file` and `process` operations happen asynchronously, their `selectors` and `responses` must be managed as separate entities. A file selector cannot be used to trigger a process response and vice versa.

# Selectors

A selector tells the service what system operations to match on and has a number of conditions that can be grouped together (using a logical AND operation) to provide precise control.
```
  - name: exampleFileSelector
    operation: [createExecutable, modifyExecutable]
    containerImageName: [nginx]
    containerImageTag: [latest]
    targetFilePath: [/usr/bin/**]
    kubernetesClusterId: [cluster1]
    kubernetesClusterName: [stagingCluster]
    kubernetesNamespace: [default]
    kubernetesPodLabel: [‘production:*’]
    kubernetesPodName: [‘nginx-pod-*’]
    ignoreVolumeMounts: true
```

A selector MUST contain a name and at least one of the following conditions.

## Common Conditions *(available for both file and process selectors)*

| Name      | Description |
| --------- | ----------- |
| **containerImageFullName** | A list of container full image names to match on. e.g. "docker.io/nginx". |
| **containerImageName** | A list of container image names to match on. e.g. nginx |
| **containerImageTag** | A list of container image tags to match on. e.g. latest |
| **kubernetesClusterId** | A list of kubernetes cluster IDs to match on. For consistency with KSPM, the 'kube-system' namespace uid is used as a cluster ID. |
| **kubernetesClusterName** | A list of kubernetes cluster names to match on. |
| **kubernetesNamespace** | A list of kubernetes namespaces to match on. |
| **kubernetesPodId** | A list of kubernetes pod names to match on. |
| **kubernetesPodName** | A list of kubernetes pod names to match on. Trailing wildcards supported. |
| **kubernetesPodLabel** | A list of resource labels. Trailing wildcards supported (value only). e.g. `key1:val*` |

&nbsp;

> For example, the following selector will match attempts to create executables on any portion of a file system, in any container as long as those containers are annotated with the `environment` key,  and have the  `owner:drohan` label fully defined:
```
- name:
  operation: [createExecutable]
  kubernetesPodLabel: [environment:*, owner:drohan]
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
| **processExecutable** | A list of executables (full path included) to match on. e.g. /usr/bin/cat. Wildcard support is same as targetFilePath above.
| **processName** | A list of process names (executable basename) to match on. e.g. 'bash', 'vi', 'cat' etc...
| **processUserId** | A list of process user ids to match on. e.g. '0'.
| **sessionLeaderInteractive** | If set to true, will only match on interactive sessions (i.e. sessions with a controlling TTY)
| **sessionLeaderName** | A list of session leader executables basenames to match on. e.g. `bash, zsh, csh, cron etc`**

# Responses

Responses instruct the system on what `actions` to take when system operations match `selectors`.

A policy can contain one or more responses. Each response is comprised of the following:
```
responses:
  - match: [allProcesses]
    exclude: [excludeSystemDServices]
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
| [@timestamp](https://www.elastic.co/guide/en/ecs/current/ecs-base.html#field-timestamp) | '2023-03-20T16:03:59.520Z' |
| [agent.id](https://www.elastic.co/guide/en/ecs/current/ecs-agent.html#field-agent-id) | '7829f26d-c2d1-4eaf-a1ac-cd9cb9e12f75' |
| [agent.type](https://www.elastic.co/guide/en/ecs/current/ecs-agent.html#field-agent-type) | 'cloud-defend' |
| [agent.version](https://www.elastic.co/guide/en/ecs/current/ecs-agent.html#field-agent-version) | '8.8.0' |
| [cloud.account.id](https://www.elastic.co/guide/en/ecs/current/ecs-cloud.html#field-cloud-account-id) | '1234567abc' |
| [cloud.account.name](https://www.elastic.co/guide/en/ecs/current/ecs-cloud.html#field-cloud-account-name) | 'elastic-dev' |
| [cloud.availability_zone](https://www.elastic.co/guide/en/ecs/current/ecs-cloud.html#field-cloud-availability-zone) | us-east-1c |
| [cloud.project.id](https://www.elastic.co/guide/en/ecs/current/ecs-cloud.html#field-cloud-project-id) | '123456abc' |
| [cloud.project.name](https://www.elastic.co/guide/en/ecs/current/ecs-cloud.html#field-cloud-project-name) | 'staging' |
| [cloud.provider](https://www.elastic.co/guide/en/ecs/current/ecs-cloud.html#field-cloud-provider) | aws |
| [cloud.region](https://www.elastic.co/guide/en/ecs/current/ecs-cloud.html#field-cloud-region) | 'us-east-1' |
| cloud_defend.matched_selectors | ['interactiveSessions'] |
| cloud_defend.package_policy_id | '4c9cbba0-c812-11ed-a8dd-91ec403e4f03' |
| cloud_defend.package_policy_revision | 2 |
| cloud_defend.trace_point | ... |
| [container.id](https://www.elastic.co/guide/en/ecs/current/ecs-container.html#field-container-id) | nginx_1
| [container.image.name](https://www.elastic.co/guide/en/ecs/current/ecs-container.html#field-container-image-name) | nginx |
| [container.image.tag](https://www.elastic.co/guide/en/ecs/current/ecs-container.html#field-container-image-tag) | latest |
| [data_stream.dataset](https://www.elastic.co/guide/en/ecs/current/ecs-data_stream.html#field-data-stream-dataset) | 'cloud_defend.process' |
| [data_stream.namespace](https://www.elastic.co/guide/en/ecs/current/ecs-data_stream.html#field-data-stream-namespace) | 'default' |
| [data_stream.type](https://www.elastic.co/guide/en/ecs/current/ecs-data_stream.html#field-data-stream-type) | 'logs' |
| [ecs.version](https://www.elastic.co/guide/en/ecs/current/ecs-ecs.html#field-ecs-version) | 8.7.0 |
| [event.action](https://www.elastic.co/guide/en/ecs/current/ecs-event.html#field-event-action) | 'fork', 'exec', 'end' |
| [event.agent_id_status](https://www.elastic.co/guide/en/ecs/current/ecs-event.html#field-event-agent-id-status) | 'verified' |
| [event.category](https://www.elastic.co/guide/en/ecs/current/ecs-event.html#field-event-category) | 'process' |
| [event.created](https://www.elastic.co/guide/en/ecs/current/ecs-event.html#field-event-created) | '2023-03-20T16:03:59.520Z' |
| [event.dataset](https://www.elastic.co/guide/en/ecs/current/ecs-event.html#field-event-dataset) | 'cloud_defend.process' |
| [event.id](https://www.elastic.co/guide/en/ecs/current/ecs-event.html#field-event-id) | '3ee85eee-72d9-4e9d-934f-3787952ca830' |
| [event.ingested](https://www.elastic.co/guide/en/ecs/current/ecs-event.html#field-event-ingested) | '2023-03-20T16:04:12Z' |
| [event.kind](https://www.elastic.co/guide/en/ecs/current/ecs-event.html#field-event-kind) | 'event', 'alert' |
| [event.type](https://www.elastic.co/guide/en/ecs/current/ecs-event.html#field-event-type) | 'start', 'end', 'denied' |
| [group.id](https://www.elastic.co/guide/en/ecs/current/ecs-group.html#field-group-id) | '0' |
| [host.architecture](https://www.elastic.co/guide/en/ecs/current/ecs-host.html#field-host-architecture) | 'amd64' |
| [host.boot.id](https://www.elastic.co/guide/en/ecs/current/ecs-host.html#field-host-boot-id) | '815a760f-8153-49e1-9d0b-da0d3b2a468c' |
| [host.id](https://www.elastic.co/guide/en/ecs/current/ecs-host.html#field-host-id) | '1bb9e6a948dfb1c3cd38d1fdc8de4481' |
| [host.ip](https://www.elastic.co/guide/en/ecs/current/ecs-host.html#field-host-ip) | ['127.0.0.1', '172.20.0.2', '172.18.0.6'] |
| [host.hostname](https://www.elastic.co/guide/en/ecs/current/ecs-host.html#field-host-hostname) | 'docker-custom-agent' |
| [host.mac](https://www.elastic.co/guide/en/ecs/current/ecs-host.html#field-host-mac) | ['32:a9:cc:26:4c:e5', '7a:ec:f0:3e:29:ee'] |
| [host.name](https://www.elastic.co/guide/en/ecs/current/ecs-host.html#field-host-name) | 'docker-custom-agent' |
| [host.os.family](https://www.elastic.co/guide/en/ecs/current/ecs-host.html#field-host-os-family) | 'ubuntu' |
| [host.os.full](https://www.elastic.co/guide/en/ecs/current/ecs-host.html#field-host-os-full) | 'Ubuntu 20.04.5' |
| [host.os.kernel](https://www.elastic.co/guide/en/ecs/current/ecs-host.html#field-host-os-kernel) | '5.10.161+ #1 SMP Thu Jan 5 22:49:42 UTC 2023' |
| [host.os.name](https://www.elastic.co/guide/en/ecs/current/ecs-host.html#field-host-os-name) | 'Linux |
| [host.os.platform](https://www.elastic.co/guide/en/ecs/current/ecs-host.html#field-host-os-platform) | 'ubuntu' |
| [host.os.type](https://www.elastic.co/guide/en/ecs/current/ecs-host.html#field-host-os-type) | 'linux' |
| [host.os.version](https://www.elastic.co/guide/en/ecs/current/ecs-host.html#field-host-os-version) | '20.04.5' |
| [host.pid_ns_ino](https://www.elastic.co/guide/en/ecs/current/ecs-host.html#field-host-pid-ns-ino) | 4026531836 |
| [orchestrator.cluster.id](https://www.elastic.co/guide/en/ecs/current/ecs-orchestrator.html#field-orchestrator-cluster-id) | '12345' |
| [orchestrator.cluster.name](https://www.elastic.co/guide/en/ecs/current/ecs-orchestrator.html#field-orchestrator-cluster-name) | 'website' |
| [orchestrator.namespace](https://www.elastic.co/guide/en/ecs/current/ecs-orchestrator.html#field-orchestrator-namespace) | default |
| [orchestrator.resource.ip](https://www.elastic.co/guide/en/ecs/current/ecs-orchestrator.html#field-orchestrator-resource-ip) | '172.18.0.6' |
| [orchestrator.resource.annotation](https://www.elastic.co/guide/en/ecs/current/ecs-orchestrator.html#field-orchestrator-resource-annotation) | ['test one two'] |
| [orchestrator.resource.label](https://www.elastic.co/guide/en/ecs/current/ecs-orchestrator.html#field-orchestrator-resource-label) | ['service:webapp'] |
| [orchestrator.resource.name](https://www.elastic.co/guide/en/ecs/current/ecs-orchestrator.html#field-orchestrator-resource-name) | webapp-proxy |
| [orchestrator.resource.parent.type](https://www.elastic.co/guide/en/ecs/current/ecs-orchestrator.html#field-orchestrator-resource-parent-type) | 'DaemonSet', 'ReplicaSet' etc... |
| [orchestrator.resource.type](https://www.elastic.co/guide/en/ecs/current/ecs-orchestrator.html#field-orchestrator-resource-type) | pod |
| [process.args](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-args) | ['ls', '--color=auto'] |
| [process.end](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-end) | '2023-03-20T16:04:12Z' |
| [process.entity_id](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-entity-id) | 'NzgyOWYyNmQtYzJkMS00ZWFmLWExYWMtY2Q5Y2I5ZTEyZjc1LTE5MTU1MzUtMTY3OTMyODIzOQ==' |
| [process.entry_leader.args](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-args) | ['bash'] |
| [process.entry_leader.entity_id](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-entity-id) | 'NzgyOWYyNmQtYzJkMS00ZWFmLWExYWMtY2Q5Y2I5ZTEyZjc1LTE5MTU1MzUtMTY3OTMyODIzOQ==' |
| [process.entry_leader.entry_meta.type](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-entry-meta-type) | 'container' |
| [process.entry_leader.executable](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-executable) | '/bin/bash' |
| [process.entry_leader.group.id](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-group-id) | '0' |
| [process.entry_leader.interactive](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-interactive) | true |
| [process.entry_leader.name](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-name) | 'bash' |
| [process.entry_leader.pid](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-pid) | 1915529 |
| [process.entry_leader.same_as_process](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-same-as-process) | false |
| [process.entry_leader.start](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-start) | '2023-03-20T16:03:59.520Z' |
| [process.entry_leader.user.id](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-user-id) | '0' |
| [process.entry_leader.working_directory](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-working-directory) | '/usr/share/elastic-agent'
| [process.executable](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-executable) | '/usr/bin/ls' |
| [process.group_leader.args](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-args) | ['ls', '--color=auto'] |
| [process.group_leader.entity_id](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-entity-id) | 'NzgyOWYyNmQtYzJkMS00ZWFmLWExYWMtY2Q5Y2I5ZTEyZjc1LTE5MTU1MzUtMTY3OTMyODIzOQ==' |
| [process.group_leader.executable](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-executable) | '/usr/bin/ls' |
| [process.group_leader.group.id](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-group-id) | '0' |
| [process.group_leader.interactive](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-interactive) | true |
| [process.group_leader.name](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-name) | 'ls' |
| [process.group_leader.pid](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-pid) | 1915529 |
| [process.group_leader.same_as_process](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-same-as-process) | true |
| [process.group_leader.start](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-start) | '2023-03-20T16:03:59.520Z' |
| [process.group_leader.user.id](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-user-id) | '0' |
| [process.group_leader.working_directory](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-working-directory) | '/usr/share/elastic-agent'
| [process.interactive](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-interactive) | true |
| [process.name](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-name) | 'ls' |
| [process.parent.args](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-args) | ['bash'] |
| [process.parent.entity_id](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-entity-id) | 'NzgyOWYyNmQtYzJkMS00ZWFmLWExYWMtY2Q5Y2I5ZTEyZjc1LTE5MTU1MzUtMTY3OTMyODIzOQ==' |
| [process.parent.executable](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-executable) | '/bin/bash' |
| [process.parent.group.id](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-group-id) | '0' |
| [process.parent.interactive](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-interactive) | true |
| [process.parent.name](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-name) | 'bash' |
| [process.parent.pid](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-pid) | 1915529 |
| [process.parent.same_as_process](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-same-as-process) | false |
| [process.parent.start](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-start) | '2023-03-20T16:03:59.520Z' |
| [process.parent.user.id](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-user-id) | '0' |
| [process.parent.working_directory](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-working-directory) | '/usr/share/elastic-agent'
| [process.pid](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-pid) | 1916234 |
| [process.previous](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-previous) | [{ args: ['bash'], executable: '/bin/bash'}] |
| [process.previous.args](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-previous-args) | ['bash']
| [process.previous.executable](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-previous-executable) | '/bin/bash' |
| [process.session_leader.args](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-args) | ['bash'] |
| [process.session_leader.entity_id](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-entity-id) | 'NzgyOWYyNmQtYzJkMS00ZWFmLWExYWMtY2Q5Y2I5ZTEyZjc1LTE5MTU1MzUtMTY3OTMyODIzOQ==' |
| [process.session_leader.entry_meta.type](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-entry-meta-type) | 'container' |
| [process.session_leader.executable](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-executable) | '/bin/bash' |
| [process.session_leader.group.id](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-group-id) | '0' |
| [process.session_leader.interactive](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-interactive) | true |
| [process.session_leader.name](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-name) | 'bash' |
| [process.session_leader.pid](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-pid) | 1915529 |
| [process.session_leader.same_as_process](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-same-as-process) | false |
| [process.session_leader.start](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-start) | '2023-03-20T16:03:59.520Z' |
| [process.session_leader.user.id](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-user-id) | '0' |
| [process.session_leader.working_directory](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-working-directory) | '/usr/share/elastic-agent'
| [process.start](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-start) | '2023-03-20T16:03:59.520Z' |
| [process.working_directory](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-working-directory) | '/usr/share/elastic-agent' |
| [user.id](https://www.elastic.co/guide/en/ecs/current/ecs-user.html#field-user-id) | '0' |

# File Events

| Field | Examples |
| --------- | ----------- |
| [@timestamp](https://www.elastic.co/guide/en/ecs/current/ecs-base.html#field-timestamp) | '2023-03-20T16:03:59.520Z' |
| [agent.id](https://www.elastic.co/guide/en/ecs/current/ecs-agent.html#field-agent-id)  | '7829f26d-c2d1-4eaf-a1ac-cd9cb9e12f75' |
| [agent.type](https://www.elastic.co/guide/en/ecs/current/ecs-agent.html#field-agent-type) | 'cloud-defend' |
| [agent.version](https://www.elastic.co/guide/en/ecs/current/ecs-agent.html#field-agent-version) | '8.8.0' |
| [cloud.account.id](https://www.elastic.co/guide/en/ecs/current/ecs-cloud.html#field-cloud-account-id) | '1234567abc' |
| [cloud.account.name](https://www.elastic.co/guide/en/ecs/current/ecs-cloud.html#field-cloud-account-name) | 'elastic-dev' |
| [cloud.availability_zone](https://www.elastic.co/guide/en/ecs/current/ecs-cloud.html#field-cloud-availability-zone) | us-east-1c |
| [cloud.project.id](https://www.elastic.co/guide/en/ecs/current/ecs-cloud.html#field-cloud-project-id) | '123456abc' |
| [cloud.project.name](https://www.elastic.co/guide/en/ecs/current/ecs-cloud.html#field-cloud-project-name) | 'staging' |
| [cloud.provider](https://www.elastic.co/guide/en/ecs/current/ecs-cloud.html#field-cloud-provider) | aws |
| [cloud.region](https://www.elastic.co/guide/en/ecs/current/ecs-cloud.html#field-cloud-region) | 'us-east-1' |
| cloud_defend.matched_selectors | ['binModifications'] |
| cloud_defend.package_policy_id | 4c9cbba0-c812-11ed-a8dd-91ec403e4f03 |
| cloud_defend.package_policy_revision | 2 |
| cloud_defend.trace_point | One of: lsm__path_chmod, lsm__path_mknod, lsm__file_open, lsm__path_truncate, lsm__path_rename, lsm__path_link, lsm__path_unlink |
| [container.id](https://www.elastic.co/guide/en/ecs/current/ecs-container.html#field-container-id) | nginx_1
| [container.image.name](https://www.elastic.co/guide/en/ecs/current/ecs-container.html#field-container-image-name) | nginx |
| [container.image.tag](https://www.elastic.co/guide/en/ecs/current/ecs-container.html#field-container-image-tag) | latest |
| [data_stream.dataset](https://www.elastic.co/guide/en/ecs/current/ecs-data_stream.html#field-data-stream-dataset) | 'cloud_defend.process' |
| [data_stream.namespace](https://www.elastic.co/guide/en/ecs/current/ecs-data_stream.html#field-data-stream-namespace) | 'default' |
| [data_stream.type](https://www.elastic.co/guide/en/ecs/current/ecs-data_stream.html#field-data-stream-type) | 'logs' |
| [ecs.version](https://www.elastic.co/guide/en/ecs/current/ecs-ecs.html#field-ecs-version) | 8.7.0 |
| [event.action](https://www.elastic.co/guide/en/ecs/current/ecs-event.html#field-event-action) | One of: 'creation', 'modification', 'deletion', 'rename', 'link', 'open' |
| [event.agent_id_status](https://www.elastic.co/guide/en/ecs/current/ecs-event.html#field-event-agent-id-status) | 'verified' |
| [event.category](https://www.elastic.co/guide/en/ecs/current/ecs-event.html#field-event-category) | 'process' |
| [event.created](https://www.elastic.co/guide/en/ecs/current/ecs-event.html#field-event-created) | '2023-03-20T16:03:59.520Z' |
| [event.dataset](https://www.elastic.co/guide/en/ecs/current/ecs-event.html#field-event-dataset) | 'cloud_defend.process' |
| [event.id](https://www.elastic.co/guide/en/ecs/current/ecs-event.html#field-event-id) | '3ee85eee-72d9-4e9d-934f-3787952ca830' |
| [event.ingested](https://www.elastic.co/guide/en/ecs/current/ecs-event.html#field-event-ingested) | '2023-03-20T16:04:12Z' |
| [event.kind](https://www.elastic.co/guide/en/ecs/current/ecs-event.html#field-event-kind) | One of: 'event', 'alert' |
| [event.type](https://www.elastic.co/guide/en/ecs/current/ecs-event.html#field-event-type) | One of: 'start', 'end', 'denied' |
| [file.extension](https://www.elastic.co/guide/en/ecs/current/ecs-file.html#field-file-extension) | ts |
| [file.name](https://www.elastic.co/guide/en/ecs/current/ecs-file.html#field-file-name) | script.ts |
| [file.path](https://www.elastic.co/guide/en/ecs/current/ecs-file.html#field-file-path) | /home/workspace/project/script.ts |
| [group.id](https://www.elastic.co/guide/en/ecs/current/ecs-group.html#field-group-id) | '0' |
| [host.architecture](https://www.elastic.co/guide/en/ecs/current/ecs-host.html#field-host-architecture) | 'amd64' |
| [host.boot.id](https://www.elastic.co/guide/en/ecs/current/ecs-host.html#field-host-boot-id) | '815a760f-8153-49e1-9d0b-da0d3b2a468c' |
| [host.id](https://www.elastic.co/guide/en/ecs/current/ecs-host.html#field-host-id) | '1bb9e6a948dfb1c3cd38d1fdc8de4481' |
| [host.ip](https://www.elastic.co/guide/en/ecs/current/ecs-host.html#field-host-ip) | ['127.0.0.1', '172.20.0.2', '172.18.0.6'] |
| [host.hostname](https://www.elastic.co/guide/en/ecs/current/ecs-host.html#field-host-hostname) | 'docker-custom-agent' |
| [host.mac](https://www.elastic.co/guide/en/ecs/current/ecs-host.html#field-host-mac) | ['32:a9:cc:26:4c:e5', '7a:ec:f0:3e:29:ee'] |
| [host.name](https://www.elastic.co/guide/en/ecs/current/ecs-host.html#field-host-name) | 'docker-custom-agent' |
| [host.os.family](https://www.elastic.co/guide/en/ecs/current/ecs-host.html#field-host-os-family) | 'ubuntu' |
| [host.os.full](https://www.elastic.co/guide/en/ecs/current/ecs-host.html#field-host-os-full) | 'Ubuntu 20.04.5' |
| [host.os.kernel](https://www.elastic.co/guide/en/ecs/current/ecs-host.html#field-host-os-kernel) | '5.10.161+ #1 SMP Thu Jan 5 22:49:42 UTC 2023' |
| [host.os.name](https://www.elastic.co/guide/en/ecs/current/ecs-host.html#field-host-os-name) | 'Linux |
| [host.os.platform](https://www.elastic.co/guide/en/ecs/current/ecs-host.html#field-host-os-platform) | 'ubuntu' |
| [host.os.type](https://www.elastic.co/guide/en/ecs/current/ecs-host.html#field-host-os-type) | 'linux' |
| [host.os.version](https://www.elastic.co/guide/en/ecs/current/ecs-host.html#field-host-os-version) | '20.04.5' |
| [host.pid_ns_ino](https://www.elastic.co/guide/en/ecs/current/ecs-host.html#field-host-pid-ns-ino) | 4026531836 |
| [orchestrator.cluster.id](https://www.elastic.co/guide/en/ecs/current/ecs-orchestrator.html#field-orchestrator-cluster-id) | '12345' |
| [orchestrator.cluster.name](https://www.elastic.co/guide/en/ecs/current/ecs-orchestrator.html#field-orchestrator-cluster-name) | 'website' |
| [orchestrator.namespace](https://www.elastic.co/guide/en/ecs/current/ecs-orchestrator.html#field-orchestrator-namespace) | default |
| [orchestrator.resource.ip](https://www.elastic.co/guide/en/ecs/current/ecs-orchestrator.html#field-orchestrator-resource-ip) | '172.18.0.6' |
| [orchestrator.resource.annotation](https://www.elastic.co/guide/en/ecs/current/ecs-orchestrator.html#field-orchestrator-resource-annotation) | ['test one two'] |
| [orchestrator.resource.label](https://www.elastic.co/guide/en/ecs/current/ecs-orchestrator.html#field-orchestrator-resource-label) | ['service:webapp'] |
| [orchestrator.resource.name](https://www.elastic.co/guide/en/ecs/current/ecs-orchestrator.html#field-orchestrator-resource-name) | webapp-proxy |
| [orchestrator.resource.parent.type](https://www.elastic.co/guide/en/ecs/current/ecs-orchestrator.html#field-orchestrator-resource-parent-type) | ... |
| [orchestrator.resource.type](https://www.elastic.co/guide/en/ecs/current/ecs-orchestrator.html#field-orchestrator-resource-type) | pod |
| [process.entity_id](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-entity-id) | 'NzgyOWYyNmQtYzJkMS00ZWFmLWExYWMtY2Q5Y2I5ZTEyZjc1LTE5MTU1MzUtMTY3OTMyODIzOQ==' |
| [process.entry_leader.entity_id](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-entity-id) | 'NzgyOWYyNmQtYzJkMS00ZWFmLWExYWMtY2Q5Y2I5ZTEyZjc1LTE5MTU1MzUtMTY3OTMyODIzOQ==' |
| [process.executable](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-executable) | '/usr/bin/vi' |
| [process.group_leader.entity_id](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-entity-id) | 'NzgyOWYyNmQtYzJkMS00ZWFmLWExYWMtY2Q5Y2I5ZTEyZjc1LTE5MTU1MzUtMTY3OTMyODIzOQ==' |
| [process.interactive](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-interactive) | true |
| [process.name](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-name) | 'vi' |
| [process.parent.entity_id](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-entity-id) | 'NzgyOWYyNmQtYzJkMS00ZWFmLWExYWMtY2Q5Y2I5ZTEyZjc1LTE5MTU1MzUtMTY3OTMyODIzOQ==' |
| [process.pid](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-pid) | 1916234 |
| [process.session_leader.entity_id](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-entity-id) | 'NzgyOWYyNmQtYzJkMS00ZWFmLWExYWMtY2Q5Y2I5ZTEyZjc1LTE5MTU1MzUtMTY3OTMyODIzOQ==' |
| [process.user.id](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#field-process-user-id) | '0' |
| [user.id](https://www.elastic.co/guide/en/ecs/current/ecs-user.html#field-user-id) | '0' |

