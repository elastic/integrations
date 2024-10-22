# cilium_tetragon Integration

## Overview

Explain what the integration is, define the third-party product that is providing data, establish its relationship to the larger ecosystem of Elastic products, and help the reader understand how it can be used to solve a tangible problem.
Check the [overview guidelines](https://www.elastic.co/guide/en/integrations-developer/current/documentation-guidelines.html#idg-docs-guidelines-overview) for more information.

## Datastreams

Provide a high-level overview of the kind of data that is collected by the integration. 
Check the [datastreams guidelines](https://www.elastic.co/guide/en/integrations-developer/current/documentation-guidelines.html#idg-docs-guidelines-datastreams) for more information.

## Requirements

The requirements section helps readers to confirm that the integration will work with their systems.
Check the [requirements guidelines](https://www.elastic.co/guide/en/integrations-developer/current/documentation-guidelines.html#idg-docs-guidelines-requirements) for more information.

## Setup

Point the reader to the [Observability Getting started guide](https://www.elastic.co/guide/en/observability/master/observability-get-started.html) for generic, step-by-step instructions. Include any additional setup instructions beyond what’s included in the guide, which may include instructions to update the configuration of a third-party service.
Check the [setup guidelines](https://www.elastic.co/guide/en/integrations-developer/current/documentation-guidelines.html#idg-docs-guidelines-setup) for more information.

## Troubleshooting (optional)

Provide information about special cases and exceptions that aren’t necessary for getting started or won’t be applicable to all users. Check the [troubleshooting guidelines](https://www.elastic.co/guide/en/integrations-developer/current/documentation-guidelines.html#idg-docs-guidelines-troubleshooting) for more information.

## Reference

Provide detailed information about the log or metric types we support within the integration. Check the [reference guidelines](https://www.elastic.co/guide/en/integrations-developer/current/documentation-guidelines.html#idg-docs-guidelines-reference) for more information.

## Logs

### log

Insert a description of the datastream here.

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cilium_tetragon.log.process_exec.parent.auid |  | long |
| cilium_tetragon.log.process_exec.parent.docker |  | keyword |
| cilium_tetragon.log.process_exec.parent.exec_id |  | keyword |
| cilium_tetragon.log.process_exec.parent.flags |  | keyword |
| cilium_tetragon.log.process_exec.parent.parent_exec_id |  | keyword |
| cilium_tetragon.log.process_exec.parent.pod.container.id |  | keyword |
| cilium_tetragon.log.process_exec.parent.pod.container.image.id |  | keyword |
| cilium_tetragon.log.process_exec.parent.pod.container.image.name |  | keyword |
| cilium_tetragon.log.process_exec.parent.pod.container.name |  | keyword |
| cilium_tetragon.log.process_exec.parent.pod.container.pid |  | long |
| cilium_tetragon.log.process_exec.parent.pod.container.start_time |  | keyword |
| cilium_tetragon.log.process_exec.parent.pod.name |  | keyword |
| cilium_tetragon.log.process_exec.parent.pod.namespace |  | keyword |
| cilium_tetragon.log.process_exec.parent.pod.pod_labels.app.kubernetes.io/name |  | keyword |
| cilium_tetragon.log.process_exec.parent.pod.pod_labels.class |  | keyword |
| cilium_tetragon.log.process_exec.parent.pod.pod_labels.org |  | keyword |
| cilium_tetragon.log.process_exec.parent.pod.pod_labels.pod-template-hash |  | keyword |
| cilium_tetragon.log.process_exec.parent.pod.workload |  | keyword |
| cilium_tetragon.log.process_exec.parent.pod.workload_kind |  | keyword |
| cilium_tetragon.log.process_exec.parent.refcnt |  | long |
| cilium_tetragon.log.process_exec.parent.start_time |  | keyword |
| cilium_tetragon.log.process_exec.parent.tid |  | long |
| cilium_tetragon.log.process_exec.process.auid |  | long |
| cilium_tetragon.log.process_exec.process.docker |  | keyword |
| cilium_tetragon.log.process_exec.process.exec_id |  | keyword |
| cilium_tetragon.log.process_exec.process.flags |  | keyword |
| cilium_tetragon.log.process_exec.process.parent_exec_id |  | keyword |
| cilium_tetragon.log.process_exec.process.pod.container.image.id |  | keyword |
| cilium_tetragon.log.process_exec.process.pod.container.pid |  | long |
| cilium_tetragon.log.process_exec.process.pod.container.start_time |  | keyword |
| cilium_tetragon.log.process_exec.process.pod.name |  | keyword |
| cilium_tetragon.log.process_exec.process.pod.namespace |  | keyword |
| cilium_tetragon.log.process_exec.process.pod.pod_labels.app |  | keyword |
| cilium_tetragon.log.process_exec.process.pod.pod_labels.app.kubernetes.io/name |  | keyword |
| cilium_tetragon.log.process_exec.process.pod.pod_labels.class |  | keyword |
| cilium_tetragon.log.process_exec.process.pod.pod_labels.org |  | keyword |
| cilium_tetragon.log.process_exec.process.pod.pod_labels.pod-template-hash |  | keyword |
| cilium_tetragon.log.process_exec.process.pod.workload |  | keyword |
| cilium_tetragon.log.process_exec.process.pod.workload_kind |  | keyword |
| cilium_tetragon.log.process_exec.process.start_time |  | keyword |
| cilium_tetragon.log.process_exec.process.uid |  | long |
| cilium_tetragon.log.process_exit.parent.auid |  | long |
| cilium_tetragon.log.process_exit.parent.docker |  | keyword |
| cilium_tetragon.log.process_exit.parent.exec_id |  | keyword |
| cilium_tetragon.log.process_exit.parent.flags |  | keyword |
| cilium_tetragon.log.process_exit.parent.parent_exec_id |  | keyword |
| cilium_tetragon.log.process_exit.parent.pod.container.id |  | keyword |
| cilium_tetragon.log.process_exit.parent.pod.container.image.id |  | keyword |
| cilium_tetragon.log.process_exit.parent.pod.container.image.name |  | keyword |
| cilium_tetragon.log.process_exit.parent.pod.container.name |  | keyword |
| cilium_tetragon.log.process_exit.parent.pod.container.pid |  | long |
| cilium_tetragon.log.process_exit.parent.pod.container.start_time |  | keyword |
| cilium_tetragon.log.process_exit.parent.pod.name |  | keyword |
| cilium_tetragon.log.process_exit.parent.pod.namespace |  | keyword |
| cilium_tetragon.log.process_exit.parent.pod.pod_labels.app.kubernetes.io/name |  | keyword |
| cilium_tetragon.log.process_exit.parent.pod.pod_labels.class |  | keyword |
| cilium_tetragon.log.process_exit.parent.pod.pod_labels.org |  | keyword |
| cilium_tetragon.log.process_exit.parent.pod.pod_labels.pod-template-hash |  | keyword |
| cilium_tetragon.log.process_exit.parent.pod.workload |  | keyword |
| cilium_tetragon.log.process_exit.parent.pod.workload_kind |  | keyword |
| cilium_tetragon.log.process_exit.parent.refcnt |  | long |
| cilium_tetragon.log.process_exit.parent.start_time |  | keyword |
| cilium_tetragon.log.process_exit.parent.tid |  | long |
| cilium_tetragon.log.process_exit.process.auid |  | long |
| cilium_tetragon.log.process_exit.process.docker |  | keyword |
| cilium_tetragon.log.process_exit.process.exec_id |  | keyword |
| cilium_tetragon.log.process_exit.process.flags |  | keyword |
| cilium_tetragon.log.process_exit.process.parent_exec_id |  | keyword |
| cilium_tetragon.log.process_exit.process.pod.container.image.id |  | keyword |
| cilium_tetragon.log.process_exit.process.pod.container.pid |  | long |
| cilium_tetragon.log.process_exit.process.pod.container.start_time |  | keyword |
| cilium_tetragon.log.process_exit.process.pod.name |  | keyword |
| cilium_tetragon.log.process_exit.process.pod.namespace |  | keyword |
| cilium_tetragon.log.process_exit.process.pod.pod_labels.app.kubernetes.io/name |  | keyword |
| cilium_tetragon.log.process_exit.process.pod.pod_labels.class |  | keyword |
| cilium_tetragon.log.process_exit.process.pod.pod_labels.org |  | keyword |
| cilium_tetragon.log.process_exit.process.pod.pod_labels.pod-template-hash |  | keyword |
| cilium_tetragon.log.process_exit.process.pod.workload |  | keyword |
| cilium_tetragon.log.process_exit.process.pod.workload_kind |  | keyword |
| cilium_tetragon.log.process_exit.process.refcnt |  | long |
| cilium_tetragon.log.process_exit.process.start_time |  | keyword |
| cilium_tetragon.log.process_exit.process.uid |  | long |
| cilium_tetragon.log.process_exit.time |  | keyword |
| cilium_tetragon.log.time |  | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| container.labels | Image labels. | object |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.device_id | ID of the device containing the filesystem where the file resides. | keyword |
| log.file.fingerprint | The sha256 fingerprint identity of the file when fingerprinting is enabled. | keyword |
| log.file.idxhi | The high-order part of a unique identifier that is associated with a file. (Windows-only) | keyword |
| log.file.idxlo | The low-order part of a unique identifier that is associated with a file. (Windows-only) | keyword |
| log.file.inode | Inode number of the log file. | keyword |
| log.file.vol | The serial number of the volume that contains a file. (Windows-only) | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |

