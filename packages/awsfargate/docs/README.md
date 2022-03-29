# AWS Fargate Integration

This integration is used to fetch metrics from [AWS Fargate](https://aws.amazon.com/fargate/).

## AWS Credentials

No AWS credentials are required for this integration.

### Why there are no credentials required?

TBD

## AWS Permissions

TBD

## Metrics

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

