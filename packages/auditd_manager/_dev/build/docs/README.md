# Auditd Manager Integration

The Auditd Manager Integration receives audit events from the Linux Audit Framework that
is a part of the Linux kernel.

This integration is available only for Linux.

## Session View powered by Auditd Manager [BETA]

The `add_session_metadata` processor for Auditd Manager powers the [Session View](https://www.elastic.co/guide/en/security/current/session-view.html) utility for the Elastic Security Platform.

To enable the `add_session_metadata` processor for Auditd Manager: 

1. Navigate to the Auditd Manager integration configuration in Kibana.
2. Add the `add_session_metadata` processor configuration under the **Processors** section of Advanced options.

```
  - add_session_metadata:
     backend: "auto"
```

3. Add these rules to the **Audit Rules** section of the configuration: 

```
  -a always,exit -F arch=b64 -S execve,execveat -k exec 
  -a always,exit -F arch=b64 -S exit_group 
  -a always,exit -F arch=b64 -S setsid
```

Changes are applied automatically, and you do not have to restart the service.

## How it works

This integration establishes a subscription to the kernel to receive the events
as they occur.

The Linux Audit Framework can send multiple messages for a single auditable
event. For example, a `rename` syscall causes the kernel to send eight separate
messages. Each message describes a different aspect of the activity that is
occurring (the syscall itself, file paths, current working directory, process
title). This integration will combine all of the data from each of the messages
into a single event.

Messages for one event can be interleaved with messages from another event. This
module will buffer the messages in order to combine related messages into a
single event even if they arrive interleaved or out of order.

## Useful commands

When running this integration, you might find that other monitoring tools interfere with it.

For example, you might encounter errors if another process, such as `auditd`, is
registered to receive data from the Linux Audit Framework. You can use these
commands to see if the `auditd` service is running and stop it:

* See if `auditd` is running:

  ```shell
  service auditd status
  ```

* Stop the `auditd` service:

  ```shell
  service auditd stop
  ```

* Disable `auditd` from starting on boot:

  ```shell
  `chkconfig auditd off`
  ```

* Stop `journald` from listening to audit messages (to save CPU usage and disk space):

  ```shell
  systemctl mask systemd-journald-audit.socket
  ```

## Audit rules

The audit rules are where you configure the activities that are audited. These
rules are configured as either syscalls or files that should be monitored. For
example you can track all `connect` syscalls or file system writes to
`/etc/passwd`.

Auditing a large number of syscalls can place a heavy load on the system so
consider carefully the rules you define and try to apply filters in the rules
themselves to be as selective as possible.

The kernel evaluates the rules in the order in which they were defined so place
the most active rules first in order to speed up evaluation.

You can assign keys to each rule for better identification of the rule that
triggered an event and easier filtering later in Elasticsearch.

Defining any audit rules in the config causes `elastic-agent` to purge all
existing audit rules prior to adding the rules specified in the config.
Therefore it is unnecessary and unsupported to include a `-D` (delete all) rule.

Examples:

```sh
## If you are on a 64 bit platform, everything should be running
## in 64 bit mode. This rule will detect any use of the 32 bit syscalls
## because this might be a sign of someone exploiting a hole in the 32
## bit API.
-a always,exit -F arch=b32 -S all -F key=32bit-abi

## Executions.
-a always,exit -F arch=b64 -S execve,execveat -k exec

## External access (warning: these can be expensive to audit).
-a always,exit -F arch=b64 -S accept,bind,connect -F key=external-access

## Unauthorized access attempts.
-a always,exit -F arch=b64 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EACCES -k access
-a always,exit -F arch=b64 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EPERM -k access

# Things that affect identity.
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity

# Unauthorized access attempts to files (unsuccessful).
-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
```

{{event "auditd"}}

{{fields "auditd"}}
