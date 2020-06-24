# Kubernetes integration

This integration is used to collect metrics from 
[Kubernetes clusters](https://kubernetes.io/).

## Compatibility

The Kubernetes package is tested with Kubernetes 1.13.x, 1.14.x, 1.15.x, 1.16.x, 1.17.x, and 1.18.x

## Metrics

### apiserver

This is the `apiserver` dataset of the Kubernetes package, in charge of retrieving metrics
from the Kubernetes API (available at `/metrics`).

This metricset needs access to the `apiserver` component of Kubernetes, accessible typically
by any POD via the `kubernetes.default` service or via environment
variables (`KUBERNETES_SERVICE_HOST` and `KUBERNETES_SERVICE_PORT`).

When the API uses https, the pod will need to authenticate using its default token and trust
the server using the appropiate CA file.

Configuration example using https and token based authentication:


In order to access the `/metrics` path of the API service, some Kubernetes environments might
require the following permission to be added to a ClusterRole.

```yaml
rules:
- nonResourceURLs:
  - /metrics
  verbs:
  - get
```

An example event for `apiserver` looks as following:

```$json
{
    "@timestamp": "2019-03-01T08:05:34.853Z",
    "event": {
        "dataset": "kubernetes.apiserver",
        "duration": 115000,
        "module": "kubernetes"
    },
    "kubernetes": {
        "apiserver": {
            "etcd": {
                "object": {
                    "count": 0
                }
            },
            "request": {
                "resource": "certificatesigningrequests.certificates.k8s.io"
            }
        }
    },
    "metricset": {
        "name": "apiserver",
        "period": 10000
    },
    "service": {
        "address": "127.0.0.1:55555",
        "type": "kubernetes"
    }
}
```

The fields reported are:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| kubernetes.apiserver.audit.event.count | Number of audit events | long |
| kubernetes.apiserver.audit.rejected.count | Number of audit rejected events | long |
| kubernetes.apiserver.client.request.count | Number of requests as client | long |
| kubernetes.apiserver.etcd.object.count | Number of kubernetes objects at etcd | long |
| kubernetes.apiserver.http.request.count | Request count for response | long |
| kubernetes.apiserver.http.request.duration.us.count | Request count for duration | long |
| kubernetes.apiserver.http.request.duration.us.percentile.* | Request duration microseconds percentiles | object |
| kubernetes.apiserver.http.request.duration.us.sum | Request duration microseconds cumulative sum | double |
| kubernetes.apiserver.http.request.size.bytes.count | Request count for size | long |
| kubernetes.apiserver.http.request.size.bytes.percentile.* | Request size percentiles | object |
| kubernetes.apiserver.http.request.size.bytes.sum | Request size cumulative sum | long |
| kubernetes.apiserver.http.response.size.bytes.count | Response count | long |
| kubernetes.apiserver.http.response.size.bytes.percentile.* | Response size percentiles | object |
| kubernetes.apiserver.http.response.size.bytes.sum | Response size cumulative sum | long |
| kubernetes.apiserver.process.cpu.sec | CPU seconds | double |
| kubernetes.apiserver.process.fds.open.count | Number of open file descriptors | long |
| kubernetes.apiserver.process.memory.resident.bytes | Bytes in resident memory | long |
| kubernetes.apiserver.process.memory.virtual.bytes | Bytes in virtual memory | long |
| kubernetes.apiserver.process.started.sec | Seconds since the process started | double |
| kubernetes.apiserver.request.client | Client executing requests | keyword |
| kubernetes.apiserver.request.code | HTTP code | keyword |
| kubernetes.apiserver.request.component | Component handling the request | keyword |
| kubernetes.apiserver.request.content_type | Request HTTP content type | keyword |
| kubernetes.apiserver.request.count | Number of requests | long |
| kubernetes.apiserver.request.current.count | Inflight requests | long |
| kubernetes.apiserver.request.dry_run | Wether the request uses dry run | keyword |
| kubernetes.apiserver.request.duration.us.bucket.* | Request duration, histogram buckets | object |
| kubernetes.apiserver.request.duration.us.count | Request duration, number of operations | long |
| kubernetes.apiserver.request.duration.us.sum | Request duration, sum in microseconds | long |
| kubernetes.apiserver.request.group | API group for the resource | keyword |
| kubernetes.apiserver.request.handler | Request handler | keyword |
| kubernetes.apiserver.request.host | Request host | keyword |
| kubernetes.apiserver.request.kind | Kind of request | keyword |
| kubernetes.apiserver.request.latency.bucket.* | Request latency histogram buckets | object |
| kubernetes.apiserver.request.latency.count | Request latency, number of requests | long |
| kubernetes.apiserver.request.latency.sum | Requests latency, sum of latencies in microseconds | long |
| kubernetes.apiserver.request.longrunning.count | Number of requests active long running requests | long |
| kubernetes.apiserver.request.method | HTTP method | keyword |
| kubernetes.apiserver.request.resource | Requested resource | keyword |
| kubernetes.apiserver.request.scope | Request scope (cluster, namespace, resource) | keyword |
| kubernetes.apiserver.request.subresource | Requested subresource | keyword |
| kubernetes.apiserver.request.verb | HTTP verb | keyword |
| kubernetes.apiserver.request.version | version for the group | keyword |


### container

This is the `container` dataset of the Kubernetes package. It collects container related metrics
from Kubelet's monitoring APIs.

An example event for `container` looks as following:

```$json
{
    "@timestamp": "2017-04-06T15:29:27.150Z",
    "beat": {
        "hostname": "beathost",
        "name": "beathost",
        "version": "6.0.0-alpha1"
    },
    "kubernetes": {
        "container": {
            "cpu": {
                "usage": {
                    "core": {
                        "ns": 3305756719
                    },
                    "nanocores": 5992
                }
            },
            "logs": {
                "available": {
                    "bytes": 1188063105024
                },
                "capacity": {
                    "bytes": 1197211648000
                },
                "inodes": {
                    "count": 584581120,
                    "free": 584447029,
                    "used": 134091
                },
                "used": {
                    "bytes": 0
                }
            },
            "memory": {
                "available": {
                    "bytes": 0
                },
                "majorpagefaults": 47,
                "pagefaults": 2298,
                "rss": {
                    "bytes": 1441792
                },
                "usage": {
                    "bytes": 7643136
                },
                "workingset": {
                    "bytes": 1466368
                }
            },
            "name": "nginx",
            "rootfs": {
                "available": {
                    "bytes": 64694517760
                },
                "capacity": {
                    "bytes": 142782496768
                },
                "inodes": {
                    "used": 0
                },
                "used": {
                    "bytes": 16777216
                }
            },
            "start_time": "2017-04-03T10:01:56Z"
        },
        "namespace": "ns",
        "node": {
          "name": "localhost"
        },
        "pod": {
            "name": "nginx-3137573019-pcfzh",
        }
    },
    "metricset": {
        "host": "localhost:10255",
        "module": "kubernetes",
        "name": "container",
        "rtt": 650739
    },
    "type": "metricsets"
}
```

The fields reported are:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| kubernetes.container.cpu.usage.core.ns | Container CPU Core usage nanoseconds | long |
| kubernetes.container.cpu.usage.limit.pct | CPU usage as a percentage of the defined limit for the container (or total node allocatable CPU if unlimited) | scaled_float |
| kubernetes.container.cpu.usage.nanocores | CPU used nanocores | long |
| kubernetes.container.cpu.usage.node.pct | CPU usage as a percentage of the total node allocatable CPU | scaled_float |
| kubernetes.container.logs.available.bytes | Logs available capacity in bytes | long |
| kubernetes.container.logs.capacity.bytes | Logs total capacity in bytes | long |
| kubernetes.container.logs.inodes.count | Total available inodes | long |
| kubernetes.container.logs.inodes.free | Total free inodes | long |
| kubernetes.container.logs.inodes.used | Total used inodes | long |
| kubernetes.container.logs.used.bytes | Logs used capacity in bytes | long |
| kubernetes.container.memory.available.bytes | Total available memory | long |
| kubernetes.container.memory.majorpagefaults | Number of major page faults | long |
| kubernetes.container.memory.pagefaults | Number of page faults | long |
| kubernetes.container.memory.rss.bytes | RSS memory usage | long |
| kubernetes.container.memory.usage.bytes | Total memory usage | long |
| kubernetes.container.memory.usage.limit.pct | Memory usage as a percentage of the defined limit for the container (or total node allocatable memory if unlimited) | scaled_float |
| kubernetes.container.memory.usage.node.pct | Memory usage as a percentage of the total node allocatable memory | scaled_float |
| kubernetes.container.memory.workingset.bytes | Working set memory usage | long |
| kubernetes.container.rootfs.available.bytes | Root filesystem total available in bytes | long |
| kubernetes.container.rootfs.capacity.bytes | Root filesystem total capacity in bytes | long |
| kubernetes.container.rootfs.inodes.used | Used inodes | long |
| kubernetes.container.rootfs.used.bytes | Root filesystem total used in bytes | long |
| kubernetes.container.start_time | Start time | date |


### controllermanager

This is the `controllermanager` dataset for the Kubernetes package. It collects from
Kubernetes controller component `metrics` endpoint.

An example event for `controllermanager` looks as following:

```$json
{
    "@timestamp": "2019-03-01T08:05:34.853Z",
    "event": {
        "dataset": "kubernetes.controllermanager",
        "duration": 115000,
        "module": "kubernetes"
    },
    "kubernetes": {
        "controllermanager": {
            "client": {
                "request": {
                    "count": 1113352
                }
            },
            "code": "200",
            "host": "192.168.205.10:6443",
            "method": "GET"
        }
    },
    "metricset": {
        "name": "controllermanager",
        "period": 10000
    },
    "service": {
        "address": "127.0.0.1:55555",
        "type": "kubernetes"
    }
}
```

The fields reported are:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| kubernetes.controllermanager.client.request.count | Number of requests as client | long |
| kubernetes.controllermanager.code | HTTP code | keyword |
| kubernetes.controllermanager.handler | Request handler | keyword |
| kubernetes.controllermanager.host | Request host | keyword |
| kubernetes.controllermanager.http.request.count | Request count for response | long |
| kubernetes.controllermanager.http.request.duration.us.count | Request count for duration | long |
| kubernetes.controllermanager.http.request.duration.us.percentile.* | Request duration microseconds percentiles | object |
| kubernetes.controllermanager.http.request.duration.us.sum | Request duration microseconds cumulative sum | double |
| kubernetes.controllermanager.http.request.size.bytes.count | Request count for size | long |
| kubernetes.controllermanager.http.request.size.bytes.percentile.* | Request size percentiles | object |
| kubernetes.controllermanager.http.request.size.bytes.sum | Request size cumulative sum | long |
| kubernetes.controllermanager.http.response.size.bytes.count | Response count | long |
| kubernetes.controllermanager.http.response.size.bytes.percentile.* | Response size percentiles | object |
| kubernetes.controllermanager.http.response.size.bytes.sum | Response size cumulative sum | long |
| kubernetes.controllermanager.leader.is_master | Whether the node is master | boolean |
| kubernetes.controllermanager.method | HTTP method | keyword |
| kubernetes.controllermanager.name | Name for the resource | keyword |
| kubernetes.controllermanager.node.collector.count | Number of nodes | long |
| kubernetes.controllermanager.node.collector.eviction.count | Number of node evictions | long |
| kubernetes.controllermanager.node.collector.health.pct | Percentage of healthy nodes | long |
| kubernetes.controllermanager.node.collector.unhealthy.count | Number of unhealthy nodes | long |
| kubernetes.controllermanager.process.cpu.sec | CPU seconds | double |
| kubernetes.controllermanager.process.fds.open.count | Number of open file descriptors | long |
| kubernetes.controllermanager.process.memory.resident.bytes | Bytes in resident memory | long |
| kubernetes.controllermanager.process.memory.virtual.bytes | Bytes in virtual memory | long |
| kubernetes.controllermanager.process.started.sec | Seconds since the process started | double |
| kubernetes.controllermanager.workqueue.adds.count | Workqueue add count | long |
| kubernetes.controllermanager.workqueue.depth.count | Workqueue depth count | long |
| kubernetes.controllermanager.workqueue.longestrunning.sec | Longest running processors | double |
| kubernetes.controllermanager.workqueue.retries.count | Workqueue number of retries | long |
| kubernetes.controllermanager.workqueue.unfinished.sec | Unfinished processors | double |
| kubernetes.controllermanager.zone | Infrastructure zone | keyword |


### event

This is the `event` dataset of the Kubernetes package. It collects Kubernetes events
related metrics.

An example event for `event` looks as following:

```$json
{
    "@timestamp": "2017-05-15T08:07:12.945Z",
    "beat": {
        "hostname": "hostname",
        "name": "beatname",
        "version": "6.0.0-alpha2"
    },
    "kubernetes": {
        "event": {
            "count": 1,
            "involved_object": {
                "api_version": "extensions",
                "kind": "ReplicaSet",
                "name": "prometheus-2552087900",
                "resource_version": "1047038",
                "uid": "b2f92f14-2ad5-11e7-8cb8-e687a39f6e48"
            },
            "message": "Created pod: prometheus-2552087900-9fxh6",
            "metadata": {
                "generate_name": "",
                "name": "prometheus-2552087900.14bf266355fd16e0",
                "namespace": "default",
                "resource_version": "1047243",
                "self_link": "/api/v1/namespaces/default/events/prometheus-2552087900.14bf266355fd16e0",
                "timestamp": {
                    "created": "2017-05-16T10:30:09-07:00",
                    "deleted": ""
                },
                "uid": "4f3fe524-3a5d-11e7-b8f2-e687a39f6e48"
            },
            "reason": "SuccessfulCreate",
            "timestamp": {
                "first_occurrence": "2017-05-16T17:30:09Z",
                "last_occurrence": "2017-05-16T17:30:09Z"
            },
            "type": "Normal"
        }
    },
    "metricset": {
        "module": "kubernetes",
        "name": "event"
    }
}
```

The fields reported are:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| kubernetes.event.count | Count field records the number of times the particular event has occurred | long |
| kubernetes.event.involved_object.api_version | API version of the object | keyword |
| kubernetes.event.involved_object.kind | API kind of the object | keyword |
| kubernetes.event.involved_object.name | name of the object | keyword |
| kubernetes.event.involved_object.resource_version | resource version of the object | keyword |
| kubernetes.event.involved_object.uid | UUID version of the object | keyword |
| kubernetes.event.message | Message recorded for the given event | text |
| kubernetes.event.metadata.generate_name | Generate name of the event | keyword |
| kubernetes.event.metadata.name | Name of the event | keyword |
| kubernetes.event.metadata.namespace | Namespace in which event was generated | keyword |
| kubernetes.event.metadata.resource_version | Version of the event resource | keyword |
| kubernetes.event.metadata.self_link | URL representing the event | keyword |
| kubernetes.event.metadata.timestamp.created | Timestamp of creation of the given event | date |
| kubernetes.event.metadata.uid | Unique identifier to the event object | keyword |
| kubernetes.event.reason | Reason recorded for the given event | keyword |
| kubernetes.event.source.component | Component from which the event is generated | keyword |
| kubernetes.event.source.host | Node name on which the event is generated | keyword |
| kubernetes.event.timestamp.first_occurrence | Timestamp of first occurrence of event | date |
| kubernetes.event.timestamp.last_occurrence | Timestamp of last occurrence of event | date |
| kubernetes.event.type | Type of the given event | keyword |


### node

This is the `node` dataset of the Kubernetes package. It collects Node related metrics
from Kubelet's monitoring APIs.

An example event for `node` looks as following:

```$json
{
    "@timestamp": "2017-04-06T15:29:27.150Z",
    "beat": {
        "hostname": "beathost",
        "name": "beathost",
        "version": "6.0.0-alpha1"
    },
    "kubernetes": {
        "node": {
            "cpu": {
                "usage": {
                    "core" : {
                        "ns": 7247863769557035
                    },
                    "nanocores": 1662117892
                }
            },
            "fs": {
                "available": {
                    "bytes": 1188063105024
                },
                "capacity": {
                    "bytes": 1197211648000
                },
                "inodes": {
                    "count": 584581120,
                    "free": 584447029,
                    "used": 134091
                },
                "used": {
                    "bytes": 9148542976
                }
            },
            "memory": {
                "available": {
                    "bytes": 134202847232
                },
                "majorpagefaults": 1044,
                "pagefaults": 83482928,
                "rss": {
                    "bytes": 178053120
                },
                "usage": {
                    "bytes": 67062091776
                },
                "workingset": {
                    "bytes": 51496206336
                }
            },
            "name": "localhost",
            "network": {
                "rx": {
                    "bytes": 957942806894,
                    "errors": 0
                },
                "tx": {
                    "bytes": 461158498276,
                    "errors": 0
                }
            },
            "runtime": {
                "imagefs": {
                    "available": {
                        "bytes": 64694517760
                    },
                    "capacity": {
                        "bytes": 142782496768
                    },
                    "used": {
                        "bytes": 29570629855
                    }
                }
            },
            "start_time": "2017-02-08T10:33:38Z"
        }
    },
    "metricset": {
        "host": "localhost:10255",
        "module": "kubernetes",
        "name": "node",
        "rtt": 650741
    },
    "type": "metricsets"
}
```

The fields reported are:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| kubernetes.node.cpu.usage.core.ns | Node CPU Core usage nanoseconds | long |
| kubernetes.node.cpu.usage.nanocores | CPU used nanocores | long |
| kubernetes.node.fs.available.bytes | Filesystem total available in bytes | long |
| kubernetes.node.fs.capacity.bytes | Filesystem total capacity in bytes | long |
| kubernetes.node.fs.inodes.count | Number of inodes | long |
| kubernetes.node.fs.inodes.free | Number of free inodes | long |
| kubernetes.node.fs.inodes.used | Number of used inodes | long |
| kubernetes.node.fs.used.bytes | Filesystem total used in bytes | long |
| kubernetes.node.memory.available.bytes | Total available memory | long |
| kubernetes.node.memory.majorpagefaults | Number of major page faults | long |
| kubernetes.node.memory.pagefaults | Number of page faults | long |
| kubernetes.node.memory.rss.bytes | RSS memory usage | long |
| kubernetes.node.memory.usage.bytes | Total memory usage | long |
| kubernetes.node.memory.workingset.bytes | Working set memory usage | long |
| kubernetes.node.network.rx.bytes | Received bytes | long |
| kubernetes.node.network.rx.errors | Rx errors | long |
| kubernetes.node.network.tx.bytes | Transmitted bytes | long |
| kubernetes.node.network.tx.errors | Tx errors | long |
| kubernetes.node.runtime.imagefs.available.bytes | Image filesystem total available in bytes | long |
| kubernetes.node.runtime.imagefs.capacity.bytes | Image filesystem total capacity in bytes | long |
| kubernetes.node.runtime.imagefs.used.bytes | Image filesystem total used in bytes | long |
| kubernetes.node.start_time | Start time | date |


### pod

This is the `pod` dataset of the Kubernetes package. It collects Pod related metrics
from Kubelet's monitoring APIs.

An example event for `pod` looks as following:

```$json
{
    "@timestamp": "2017-04-06T15:29:27.150Z",
    "beat": {
        "hostname": "beathost",
        "name": "beathost",
        "version": "6.0.0-alpha1"
    },
    "kubernetes": {
        "namespace": "ns",
        "node": {
          "name": "localhost",
        },
        "pod": {
            "name": "nginx-3137573019-pcfzh",
            "uid": "b89a812e-18cd-11e9-b333-080027190d51",
            "network": {
                "rx": {
                    "bytes": 18999261,
                    "errors": 0
                },
                "tx": {
                    "bytes": 28580621,
                    "errors": 0
                }
            },
            "start_time": "2017-04-06T12:09:05Z"
        }
    },
    "metricset": {
        "host": "localhost:10255",
        "module": "kubernetes",
        "name": "pod",
        "rtt": 636230
    },
    "type": "metricsets"
}
```

The fields reported are:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| kubernetes.pod.cpu.usage.limit.pct | CPU usage as a percentage of the defined limit for the pod containers (or total node CPU if one or more containers of the pod are unlimited) | scaled_float |
| kubernetes.pod.cpu.usage.nanocores | CPU used nanocores | long |
| kubernetes.pod.cpu.usage.node.pct | CPU usage as a percentage of the total node CPU | scaled_float |
| kubernetes.pod.memory.available.bytes | Total memory available | long |
| kubernetes.pod.memory.major_page_faults | Total major page faults | long |
| kubernetes.pod.memory.page_faults | Total page faults | long |
| kubernetes.pod.memory.rss.bytes | Total resident set size memory | long |
| kubernetes.pod.memory.usage.bytes | Total memory usage | long |
| kubernetes.pod.memory.usage.limit.pct | Memory usage as a percentage of the defined limit for the pod containers (or total node allocatable memory if unlimited) | scaled_float |
| kubernetes.pod.memory.usage.node.pct | Memory usage as a percentage of the total node allocatable memory | scaled_float |
| kubernetes.pod.memory.working_set.bytes | Total working set memory | long |
| kubernetes.pod.network.rx.bytes | Received bytes | long |
| kubernetes.pod.network.rx.errors | Rx errors | long |
| kubernetes.pod.network.tx.bytes | Transmitted bytes | long |
| kubernetes.pod.network.tx.errors | Tx errors | long |
| kubernetes.pod.start_time | Start time | date |


### proxy

This is the `proxy` dataset of the Kubernetes package. It collects metrics
from Kubernetes Proxy component.

An example event for `proxy` looks as following:

```$json
{
    "@timestamp": "2019-03-01T08:05:34.853Z",
    "event": {
        "dataset": "kubernetes.proxy",
        "duration": 115000,
        "module": "kubernetes"
    },
    "kubernetes": {
        "proxy": {
            "handler": "prometheus",
            "http": {
                "request": {
                    "duration": {
                        "us": {
                            "count": 5719,
                            "percentile": {
                                "50": 3724.635,
                                "90": 6009.016,
                                "99": 15081.009
                            },
                            "sum": 21201441.986
                        }
                    },
                    "size": {
                        "bytes": {
                            "count": 5719,
                            "percentile": {
                                "50": 86,
                                "90": 86,
                                "99": 86
                            },
                            "sum": 491766
                        }
                    }
                },
                "response": {
                    "size": {
                        "bytes": {
                            "count": 5719,
                            "percentile": {
                                "50": 2965,
                                "90": 2970,
                                "99": 2973
                            },
                            "sum": 16977903
                        }
                    }
                }
            }
        }
    },
    "metricset": {
        "name": "proxy",
        "period": 10000
    },
    "service": {
        "address": "127.0.0.1:55555",
        "type": "kubernetes"
    }
}
```

The fields reported are:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| kubernetes.proxy.client.request.count | Number of requests as client | long |
| kubernetes.proxy.code | HTTP code | keyword |
| kubernetes.proxy.handler | Request handler | keyword |
| kubernetes.proxy.host | Request host | keyword |
| kubernetes.proxy.http.request.count | Request count | long |
| kubernetes.proxy.http.request.duration.us.count | Request count for duration | long |
| kubernetes.proxy.http.request.duration.us.percentile.* | Request duration microseconds percentiles | object |
| kubernetes.proxy.http.request.duration.us.sum | Request duration microseconds cumulative sum | double |
| kubernetes.proxy.http.request.size.bytes.count | Request count for size | long |
| kubernetes.proxy.http.request.size.bytes.percentile.* | Request size percentiles | object |
| kubernetes.proxy.http.request.size.bytes.sum | Request size cumulative sum | long |
| kubernetes.proxy.http.response.size.bytes.count | Response count | long |
| kubernetes.proxy.http.response.size.bytes.percentile.* | Response size percentiles | object |
| kubernetes.proxy.http.response.size.bytes.sum | Response size cumulative sum | long |
| kubernetes.proxy.method | HTTP method | keyword |
| kubernetes.proxy.process.cpu.sec | CPU seconds | double |
| kubernetes.proxy.process.fds.open.count | Number of open file descriptors | long |
| kubernetes.proxy.process.memory.resident.bytes | Bytes in resident memory | long |
| kubernetes.proxy.process.memory.virtual.bytes | Bytes in virtual memory | long |
| kubernetes.proxy.process.started.sec | Seconds since the process started | double |
| kubernetes.proxy.sync.networkprogramming.duration.us.bucket.* | Network programming duration, histogram buckets | object |
| kubernetes.proxy.sync.networkprogramming.duration.us.count | Network programming duration, number of operations | long |
| kubernetes.proxy.sync.networkprogramming.duration.us.sum | Network programming duration, sum in microseconds | long |
| kubernetes.proxy.sync.rules.duration.us.bucket.* | SyncProxyRules duration, histogram buckets | object |
| kubernetes.proxy.sync.rules.duration.us.count | SyncProxyRules duration, number of operations | long |
| kubernetes.proxy.sync.rules.duration.us.sum | SyncProxyRules duration, sum of durations in microseconds | long |


### scheduler

This is the `scheduler` dataset of the Kubernetes package. It collects metrics
from Kubernetes Scheduler component.

An example event for `scheduler` looks as following:

```$json
{
    "@timestamp": "2019-03-01T08:05:34.853Z",
    "event": {
        "dataset": "kubernetes.scheduler",
        "duration": 115000,
        "module": "kubernetes"
    },
    "kubernetes": {
        "scheduler": {
            "handler": "prometheus",
            "http": {
                "request": {
                    "duration": {
                        "us": {
                            "count": 4,
                            "percentile": {
                                "50": 7644.523,
                                "90": 7644.523,
                                "99": 7644.523
                            },
                            "sum": 16210.005000000001
                        }
                    },
                    "size": {
                        "bytes": {
                            "count": 4,
                            "percentile": {
                                "50": 64,
                                "90": 64,
                                "99": 64
                            },
                            "sum": 256
                        }
                    }
                },
                "response": {
                    "size": {
                        "bytes": {
                            "count": 4,
                            "percentile": {
                                "50": 48741,
                                "90": 48741,
                                "99": 48741
                            },
                            "sum": 184429
                        }
                    }
                }
            }
        }
    },
    "metricset": {
        "name": "scheduler",
        "period": 10000
    },
    "service": {
        "address": "127.0.0.1:55555",
        "type": "kubernetes"
    }
}
```

The fields reported are:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| kubernetes.scheduler.client.request.count | Number of requests as client | long |
| kubernetes.scheduler.code | HTTP code | keyword |
| kubernetes.scheduler.handler | Request handler | keyword |
| kubernetes.scheduler.host | Request host | keyword |
| kubernetes.scheduler.http.request.count | Request count | long |
| kubernetes.scheduler.http.request.duration.us.count | Request count for duration | long |
| kubernetes.scheduler.http.request.duration.us.percentile.* | Request duration microseconds percentiles | object |
| kubernetes.scheduler.http.request.duration.us.sum | Request duration microseconds cumulative sum | double |
| kubernetes.scheduler.http.request.size.bytes.count | Request count for size | long |
| kubernetes.scheduler.http.request.size.bytes.percentile.* | Request size percentiles | object |
| kubernetes.scheduler.http.request.size.bytes.sum | Request size cumulative sum | long |
| kubernetes.scheduler.http.response.size.bytes.count | Response count | long |
| kubernetes.scheduler.http.response.size.bytes.percentile.* | Response size percentiles | object |
| kubernetes.scheduler.http.response.size.bytes.sum | Response size cumulative sum | long |
| kubernetes.scheduler.leader.is_master | Whether the node is master | boolean |
| kubernetes.scheduler.method | HTTP method | keyword |
| kubernetes.scheduler.name | Name for the resource | keyword |
| kubernetes.scheduler.operation | Scheduling operation | keyword |
| kubernetes.scheduler.process.cpu.sec | CPU seconds | double |
| kubernetes.scheduler.process.fds.open.count | Number of open file descriptors | long |
| kubernetes.scheduler.process.memory.resident.bytes | Bytes in resident memory | long |
| kubernetes.scheduler.process.memory.virtual.bytes | Bytes in virtual memory | long |
| kubernetes.scheduler.process.started.sec | Seconds since the process started | double |
| kubernetes.scheduler.result | Schedule attempt result | keyword |
| kubernetes.scheduler.scheduling.duration.seconds.count | Scheduling count | long |
| kubernetes.scheduler.scheduling.duration.seconds.percentile.* | Scheduling duration percentiles | object |
| kubernetes.scheduler.scheduling.duration.seconds.sum | Scheduling duration cumulative sum | double |
| kubernetes.scheduler.scheduling.e2e.duration.us.bucket.* | End to end scheduling duration microseconds | object |
| kubernetes.scheduler.scheduling.e2e.duration.us.count | End to end scheduling count | long |
| kubernetes.scheduler.scheduling.e2e.duration.us.sum | End to end scheduling duration microseconds sum | long |
| kubernetes.scheduler.scheduling.pod.attempts.count | Pod attempts count | long |
| kubernetes.scheduler.scheduling.pod.preemption.victims.count | Pod preemption victims | long |


### state_container

This is the `state_container` dataset of the Kubernetes package. It collects container related
metrics from `kube_state_metrics`.

An example event for `state_container` looks as following:

```$json
{
  "@timestamp": "2019-10-02T16:47:01.499Z",
  "metricset": {
    "name": "state_container",
    "period": 10000
  },
  "service": {
    "address": "kube-state-metrics.kube-system:8080",
    "type": "kubernetes"
  },
  "kubernetes": {
    "labels": {
      "app": "playground"
    },
    "container": {
      "cpu": {
        "request": {
          "nanocores": 200000000
        }
      },      
      "image": "ubuntu:latest",
      "id": "docker://5f8ce416d10ab0b28ce5c7d521de2264aa03ff4d001e1194076f6a02a330139f",
      "name": "ubuntu",
      "status": {
        "ready": true,
        "restarts": 0,
        "phase": "running"
      }
    },
    "pod": {
      "name": "playground",
      "uid": "d52bd3cb-df62-4cb5-b293-7009055bcaff"
    },
    "namespace": "default",
    "node": {
      "name": "minikube"
    }
  },
  "host": {
    "os": {
      "codename": "bionic",
      "platform": "ubuntu",
      "version": "18.04.3 LTS (Bionic Beaver)",
      "family": "debian",
      "name": "Ubuntu",
      "kernel": "4.15.0"
    },
    "containerized": false,
    "hostname": "minikube",
    "name": "minikube",
    "architecture": "x86_64"
  },
  "agent": {
    "version": "8.0.0",
    "type": "metricbeat",
    "ephemeral_id": "fed15ef3-ab8f-4e11-aded-115ff923bc1e",
    "hostname": "minikube",
    "id": "0df400e0-a5fc-40cc-a0c6-b99029a30cd5"
  },
  "ecs": {
    "version": "1.1.0"
  },
  "container": {
    "runtime": "docker",
    "id": "5f8ce416d10ab0b28ce5c7d521de2264aa03ff4d001e1194076f6a02a330139f"
  },
  "event": {
    "dataset": "kubernetes.container",
    "module": "kubernetes",
    "duration": 33750820
  }
}
```

The fields reported are:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| kubernetes.container.cpu.limit.cores | Container CPU cores limit | float |
| kubernetes.container.cpu.limit.nanocores | Container CPU nanocores limit | long |
| kubernetes.container.cpu.request.cores | Container CPU requested cores | float |
| kubernetes.container.cpu.request.nanocores | Container CPU requested nanocores | long |
| kubernetes.container.id | Container id | keyword |
| kubernetes.container.memory.limit.bytes | Container memory limit in bytes | long |
| kubernetes.container.memory.request.bytes | Container requested memory in bytes | long |
| kubernetes.container.status.phase | Container phase (running, waiting, terminated) | keyword |
| kubernetes.container.status.ready | Container ready status | boolean |
| kubernetes.container.status.reason | Waiting (ContainerCreating, CrashLoopBackoff, ErrImagePull, ImagePullBackoff) or termination (Completed, ContainerCannotRun, Error, OOMKilled) reason. | keyword |
| kubernetes.container.status.restarts | Container restarts count | integer |


### state_cronjob

This is the `state_cronjob` dataset of the Kubernetes package. It collects cronjob related
metrics from `kube_state_metrics`.

An example event for `state_cronjob` looks as following:

```$json
{
  "@timestamp": "2019-08-06T09:04:37.555Z",
  "@metadata": {
    "beat": "metricbeat",
    "type": "_doc",
    "version": "8.0.0"
  },
  "kubernetes": {
    "namespace": "default",
    "cronjob": {
      "is_suspended": false,
      "active": {
        "count": 0
      },
      "last_schedule": {
        "sec": 1.56508224e+09
      },
      "next_schedule": {
        "sec": 1.5650823e+09
      },
      "created": {
        "sec": 1.565081911e+09
      },
      "name": "mycronjob"
    }
  },
  "ecs": {
    "version": "1.0.1"
  },
  "host": {
    "containerized": false,
    "name": "worker2",
    "hostname": "worker2",
    "architecture": "x86_64",
    "os": {
      "codename": "bionic",
      "platform": "ubuntu",
      "version": "18.04.2 LTS (Bionic Beaver)",
      "family": "debian",
      "name": "Ubuntu",
      "kernel": "4.4.0-148-generic"
    }
  },
  "agent": {
    "id": "8a56f5ca-477f-4a10-b88e-e3793ac3f892",
    "version": "8.0.0",
    "type": "metricbeat",
    "ephemeral_id": "9acb5452-9e96-45e6-82ab-76e2f20b22eb",
    "hostname": "worker2"
  },
  "event": {
    "dataset": "kubernetes.cronjob",
    "module": "kubernetes",
    "duration": 7832416
  },
  "metricset": {
    "name": "state_cronjob"
  },
  "service": {
    "address": "kube-state-metrics:8080",
    "type": "kubernetes"
  }
```

The fields reported are:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| kubernetes.cronjob.active.count | Number of active pods for the cronjob | long |
| kubernetes.cronjob.concurrency | Concurrency policy | keyword |
| kubernetes.cronjob.created.sec | Epoch seconds since the cronjob was created | double |
| kubernetes.cronjob.deadline.sec | Deadline seconds after schedule for considering failed | long |
| kubernetes.cronjob.is_suspended | Whether the cronjob is suspended | boolean |
| kubernetes.cronjob.last_schedule.sec | Epoch seconds for last cronjob run | double |
| kubernetes.cronjob.name | Cronjob name | keyword |
| kubernetes.cronjob.next_schedule.sec | Epoch seconds for next cronjob run | double |
| kubernetes.cronjob.schedule | Cronjob schedule | keyword |


### state_deployment

This is the `state_deployment` dataset of the Kubernetes package. It collects deployment related
metrics from `kube_state_metrics`.

An example event for `state_deployment` looks as following:

```$json
{
  "@timestamp": "2017-05-10T16:44:27.915Z",
  "beat": {
    "hostname": "X1",
    "name": "X1",
    "version": "6.0.0-alpha1"
  },
  "kubernetes": {
    "deployment": {
      "name": "wise-lynx-jenkins",
      "paused": false,
      "replicas": {
        "available": 1,
        "desired": 1,
        "unavailable": 0,
        "updated": 1
      }
    },
    "namespace": "jenkins"
  },
  "metricset": {
    "host": "192.168.99.100:18080",
    "module": "kubernetes",
    "name": "state_deployment",
    "namespace": "deployment",
    "rtt": 198882
  }
```

The fields reported are:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| kubernetes.deployment.paused | Kubernetes deployment paused status | boolean |
| kubernetes.deployment.replicas.available | Deployment available replicas | integer |
| kubernetes.deployment.replicas.desired | Deployment number of desired replicas (spec) | integer |
| kubernetes.deployment.replicas.unavailable | Deployment unavailable replicas | integer |
| kubernetes.deployment.replicas.updated | Deployment updated replicas | integer |


### state_node

This is the `state_node` dataset of the Kubernetes package. It collects node related
metrics from `kube_state_metrics`.

An example event for `state_node` looks as following:

```$json
{
  "@timestamp": "2017-05-10T16:45:47.726Z",
  "beat": {
    "hostname": "X1",
    "name": "X1",
    "version": "6.0.0-alpha1"
  },
  "kubernetes": {
    "node": {
      "cpu": {
        "allocatable": {
          "cores": 2
        },
        "capacity": {
          "cores": 2
        }
      },
      "memory": {
        "allocatable": {
          "bytes": 2097786880
        },
        "capacity": {
          "bytes": 2097786880
        }
      },
      "name": "minikube",
      "pod": {
        "allocatable": {
          "total": 110
        },
        "capacity": {
          "total": 110
        }
      },
      "status": {
        "ready": "true",
        "unschedulable": false
      }
    }
  },
  "metricset": {
    "host": "192.168.99.100:18080",
    "module": "kubernetes",
    "name": "state_node",
    "namespace": "node",
    "rtt": 94611
  }
}
```

The fields reported are:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| kubernetes.node.cpu.allocatable.cores | Node CPU allocatable cores | float |
| kubernetes.node.cpu.capacity.cores | Node CPU capacity cores | long |
| kubernetes.node.memory.allocatable.bytes | Node allocatable memory in bytes | long |
| kubernetes.node.memory.capacity.bytes | Node memory capacity in bytes | long |
| kubernetes.node.pod.allocatable.total | Node allocatable pods | long |
| kubernetes.node.pod.capacity.total | Node pod capacity | long |
| kubernetes.node.status.ready | Node ready status (true, false or unknown) | keyword |
| kubernetes.node.status.unschedulable | Node unschedulable status | boolean |


### state_persistentvolume

This is the `state_persistentvolume` dataset of the Kubernetes package. It collects 
PersistentVolume related metrics from `kube_state_metrics`.


The fields reported are:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| kubernetes.persistentvolume.capacity.bytes | Volume capacity | long |
| kubernetes.persistentvolume.name | Volume name. | keyword |
| kubernetes.persistentvolume.phase | Volume phase according to kubernetes | keyword |
| kubernetes.persistentvolume.storage_class | Storage class for the volume | keyword |


### state_persistentvolumeclaim

This is the `state_persistentvolumeclaim` dataset of the Kubernetes package. It collects 
PersistentVolumeClaim related metrics from `kube_state_metrics`.


The fields reported are:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| kubernetes.persistentvolumeclaim.access_mode | Access mode. | keyword |
| kubernetes.persistentvolumeclaim.name | PVC name. | keyword |
| kubernetes.persistentvolumeclaim.phase | PVC phase. | keyword |
| kubernetes.persistentvolumeclaim.request_storage.bytes | Requested capacity. | long |
| kubernetes.persistentvolumeclaim.storage_class | Storage class for the PVC. | keyword |
| kubernetes.persistentvolumeclaim.volume_name | Binded volume name. | keyword |


### state_pod

This is the `state_pod` dataset of the Kubernetes package. It collects 
Pod related metrics from `kube_state_metrics`.

An example event for `state_pod` looks as following:

```$json
{
    "@timestamp": "2019-03-01T08:05:34.853Z",
    "event": {
        "dataset": "kubernetes.pod",
        "duration": 115000,
        "module": "kubernetes"
    },
    "kubernetes": {
        "namespace": "kube-system",
        "node": {
            "name": "minikube"
        },
        "pod": {
            "host_ip": "192.168.99.100",
            "ip": "172.17.0.2",
            "name": "tiller-deploy-3067024529-9lpmb",
            "status": {
                "phase": "running",
                "ready": "true",
                "scheduled": "true"
            }
        }
    },
    "metricset": {
        "name": "state_pod",
        "period": 10000
    },
    "service": {
        "address": "127.0.0.1:55555",
        "type": "kubernetes"
    }
}
```

The fields reported are:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| kubernetes.pod.host_ip | Kubernetes pod host IP | ip |
| kubernetes.pod.ip | Kubernetes pod IP | ip |
| kubernetes.pod.status.phase | Kubernetes pod phase (Running, Pending...) | keyword |
| kubernetes.pod.status.ready | Kubernetes pod ready status (true, false or unknown) | keyword |
| kubernetes.pod.status.scheduled | Kubernetes pod scheduled status (true, false, unknown) | keyword |


### state_replicaset

This is the `state_replicaset` dataset of the Kubernetes package. It collects 
Replicaset related metrics from `kube_state_metrics`.

An example event for `state_replicaset` looks as following:

```$json
{
    "@timestamp": "2019-03-01T08:05:34.853Z",
    "event": {
        "dataset": "kubernetes.replicaset",
        "duration": 115000,
        "module": "kubernetes"
    },
    "kubernetes": {
        "namespace": "default",
        "replicaset": {
            "name": "jumpy-owl-redis-3481028193",
            "replicas": {
                "available": 1,
                "desired": 1,
                "labeled": 1,
                "observed": 1,
                "ready": 0
            }
        }
    },
    "metricset": {
        "name": "state_replicaset",
        "period": 10000
    },
    "service": {
        "address": "127.0.0.1:55555",
        "type": "kubernetes"
    }
}
```

The fields reported are:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| kubernetes.replicaset.replicas.available | The number of replicas per ReplicaSet | long |
| kubernetes.replicaset.replicas.desired | The number of replicas per ReplicaSet | long |
| kubernetes.replicaset.replicas.labeled | The number of fully labeled replicas per ReplicaSet | long |
| kubernetes.replicaset.replicas.observed | The generation observed by the ReplicaSet controller | long |
| kubernetes.replicaset.replicas.ready | The number of ready replicas per ReplicaSet | long |


### state_resourcequota

This is the `state_resourcequota` dataset of the Kubernetes package. It collects 
ResourceQuota related metrics from `kube_state_metrics`.

An example event for `state_resourcequota` looks as following:

```$json
{
    "@timestamp": "2019-09-16T18:37:16.237Z",
    "@metadata": {
      "beat": "metricbeat",
      "type": "_doc",
      "version": "8.0.0"
    },
    "agent": {
      "ephemeral_id": "9a223001-a65f-4460-b106-553151987b09",
      "hostname": "minikube",
      "id": "191c7322-6d36-4f6c-b451-d0302b96841b",
      "version": "8.0.0",
      "type": "metricbeat"
    },
    "kubernetes": {
      "namespace": "rqtest",
      "resourcequota": {
        "quota": 2,
        "name": "objects",
        "resource": "services",
        "type": "hard"
      }
    },
    "event": {
      "module": "kubernetes",
      "duration": 13626177,
      "dataset": "kubernetes.resourcequota"
    },
    "metricset": {
      "period": 10000,
      "name": "state_resourcequota"
    },
    "service": {
      "address": "kube-state-metrics.kube-system:8080",
      "type": "kubernetes"
    },
    "ecs": {
      "version": "1.1.0"
    },
    "host": {
      "name": "minikube",
      "architecture": "x86_64",
      "os": {
        "kernel": "4.15.0",
        "codename": "bionic",
        "platform": "ubuntu",
        "version": "18.04.3 LTS (Bionic Beaver)",
        "family": "debian",
        "name": "Ubuntu"
      },
      "containerized": false,
      "hostname": "minikube"
    }
  }
}
```

The fields reported are:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| kubernetes.resourcequota.created.sec | Epoch seconds since the ResourceQuota was created | double |
| kubernetes.resourcequota.name | ResourceQuota name | keyword |
| kubernetes.resourcequota.quota | Quota informed (hard or used) for the resource | double |
| kubernetes.resourcequota.resource | Resource name the quota applies to | keyword |
| kubernetes.resourcequota.type | Quota information type, `hard` or `used` | keyword |


### state_service

This is the `state_service` dataset of the Kubernetes package. It collects 
Service related metrics from `kube_state_metrics`.

An example event for `state_service` looks as following:

```$json
{
    "@timestamp": "2019-12-18T14:47:52.427Z",
    "@metadata": {
      "beat": "metricbeat",
      "type": "_doc",
      "version": "8.0.0"
    },
    "event": {
      "dataset": "kubernetes.service",
      "module": "kubernetes",
      "duration": 44555276
    },
    "metricset": {
      "name": "state_service",
      "period": 10000
    },
    "service": {
      "type": "kubernetes",
      "address": "kube-state-metrics.kube-system:8080"
    },
    "kubernetes": {
      "service": {
        "type": "ClusterIP",
        "name": "productpage",
        "created": "2019-11-25T21:08:36.000Z",
        "cluster_ip": "10.104.43.66"
      },
      "namespace": "default",
      "labels": {
        "app": "productpage"
      }
    },
    "agent": {
      "type": "metricbeat",
      "ephemeral_id": "c2655cd5-2091-4cd2-848d-6abba04bc26c",
      "hostname": "minikube",
      "id": "e9952df4-592e-4102-84a6-ad0b333b3b98",
      "version": "8.0.0"
    },
    "ecs": {
      "version": "1.2.0"
    },
    "host": {
      "name": "minikube"
    }
  }
```

The fields reported are:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| kubernetes.service.cluster_ip | Internal IP for the service. | ip |
| kubernetes.service.created | Service creation date | date |
| kubernetes.service.external_ip | Service external IP | keyword |
| kubernetes.service.external_name | Service external DNS name | keyword |
| kubernetes.service.ingress_hostname | Ingress Hostname | keyword |
| kubernetes.service.ingress_ip | Ingress IP | keyword |
| kubernetes.service.load_balancer_ip | Load Balancer service IP | keyword |
| kubernetes.service.name | Service name. | keyword |
| kubernetes.service.type | Service type | keyword |


### state_storageclass

This is the `state_storageclass` dataset of the Kubernetes package. It collects 
StorageClass related metrics from `kube_state_metrics`.

An example event for `state_storageclass` looks as following:

```$json
{
  "@timestamp": "2020-02-07T17:10:12.124Z",
  "@metadata": {
    "beat": "metricbeat",
    "type": "_doc",
    "version": "8.0.0"
  },
  "service": {
    "address": "192.168.39.32:32042",
    "type": "kubernetes"
  },
  "kubernetes": {
    "storageclass": {
      "volume_binding_mode": "Immediate",
      "name": "beats-test-sc2",
      "created": "2020-02-07T10:14:28.000Z",
      "provisioner": "kubernetes.io/non-existing2",
      "reclaim_policy": "Delete"
    },
    "labels": {
      "testl3": "value3",
      "testl4": "value4"
    }
  },
  "event": {
    "duration": 13684387,
    "dataset": "kubernetes.storageclass",
    "module": "kubernetes"
  },
  "ecs": {
    "version": "1.4.0"
  },
  "host": {
    "name": "pl51"
  },
  "agent": {
    "version": "8.0.0",
    "type": "metricbeat",
    "ephemeral_id": "f4458304-dc2e-4831-be7a-45cd34126fd2",
    "hostname": "tamag8",
    "id": "e9952df4-592e-4102-84a6-ad0b333b3b98"
  },
  "metricset": {
    "name": "state_storageclass",
    "period": 10000
  }
}
```

The fields reported are:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| kubernetes.storageclass.created | Storage class creation date | date |
| kubernetes.storageclass.name | Storage class name. | keyword |
| kubernetes.storageclass.provisioner | Volume provisioner for the storage class. | keyword |
| kubernetes.storageclass.reclaim_policy | Reclaim policy for dynamically created volumes | keyword |
| kubernetes.storageclass.volume_binding_mode | Mode for default provisioning and binding | keyword |


### system

This is the `system` dataset of the Kubernetes package. It collects System related metrics
from Kubelet's monitoring APIs.

An example event for `system` looks as following:

```$json
{
    "@timestamp": "2017-04-06T15:29:27.150Z",
    "beat": {
        "hostname": "beathost",
        "name": "beathost",
        "version": "6.0.0-alpha1"
    },
    "kubernetes": {
        "node": {
            "name": "localhost"
        },
        "system": {
            "container": "kubernetes",
            "cpu": {
                "usage": {
                    "core": {
                        "ns": 1424273250468228
                    },
                    "nanocores": 382404825
                }
            },
            "memory": {
                "majorpagefaults": 49,
                "pagefaults": 22921778663,
                "rss": {
                    "bytes": 159412224
                },
                "usage": {
                    "bytes": 223035392
                },
                "workingset": {
                    "bytes": 169037824
                }
            },
            "start_time": "2017-02-08T10:35:02Z"
        }
    },
    "metricset": {
        "host": "localhost:10255",
        "module": "kubernetes",
        "name": "system",
        "rtt": 640649
    },
    "type": "metricsets"
}
```

The fields reported are:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| kubernetes.system.container | Container name | keyword |
| kubernetes.system.cpu.usage.core.ns | CPU Core usage nanoseconds | long |
| kubernetes.system.cpu.usage.nanocores | CPU used nanocores | long |
| kubernetes.system.memory.majorpagefaults | Number of major page faults | long |
| kubernetes.system.memory.pagefaults | Number of page faults | long |
| kubernetes.system.memory.rss.bytes | RSS memory usage | long |
| kubernetes.system.memory.usage.bytes | Total memory usage | long |
| kubernetes.system.memory.workingset.bytes | Working set memory usage | long |
| kubernetes.system.start_time | Start time | date |


### volume

This is the `volume` dataset of the Kubernetes package. It collects Volume related metrics
from Kubelet's monitoring APIs.

An example event for `volume` looks as following:

```$json
{
    "@timestamp": "2017-04-06T15:29:27.150Z",
    "beat": {
        "hostname": "beathost",
        "name": "beathost",
        "version": "6.0.0-alpha1"
    },
    "kubernetes": {
        "namespace": "ns",
        "node": {
          "name": "localhost",
        },
        "pod": {
            "name": "nginx-3137573019-pcfzh",
        },
        "volume": {
            "fs": {
                "available": {
                    "bytes": 92849512448
                },
                "capacity": {
                    "bytes": 92849524736
                },
                "inodes": {
                    "count": 22668341,
                    "free": 22668332,
                    "used": 9
                },
                "used": {
                    "bytes": 12288
                }
            },
            "name": "default-token-4fkmg"
        }
    },
    "metricset": {
        "host": "localhost:10255",
        "module": "kubernetes",
        "name": "volume",
        "rtt": 648606
    },
    "type": "metricsets"
}
```

The fields reported are:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| kubernetes.volume.fs.available.bytes | Filesystem total available in bytes | long |
| kubernetes.volume.fs.capacity.bytes | Filesystem total capacity in bytes | long |
| kubernetes.volume.fs.inodes.count | Total inodes | long |
| kubernetes.volume.fs.inodes.free | Free inodes | long |
| kubernetes.volume.fs.inodes.used | Used inodes | long |
| kubernetes.volume.fs.used.bytes | Filesystem total used in bytes | long |
| kubernetes.volume.name | Volume name | keyword |
