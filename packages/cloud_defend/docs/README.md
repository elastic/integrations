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

| Action | Description |
| --------- | ----------- |
| `log`  | Sends events to the `logs-cloud_defend.file-*` data stream for `file` responses, and the `logs-cloud_defend.process-*` data stream for `process` responses. |
| `alert` | Writes events (file or process) to the `logs-cloud_defend.alerts-*` data stream. |
| `block` | Prevents the system operation from proceeding. This blocking action happens *prior* to the execution of the event. It is required that the `alert` action be set if `block` is enabled. *Note: Currently `block` is only supported on file operations. Process blocking coming soon!* |

# Process Events

| Field | ECS |
| --------- | ----------- |
|

# File Events

