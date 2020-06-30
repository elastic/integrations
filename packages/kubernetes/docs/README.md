# Kubernetes integration

This integration is used to collect metrics from 
[Kubernetes clusters](https://kubernetes.io/).

As one of the main pieces provided for Kubernetes monitoring, this integration is capable of fetching metrics from several components:

- [kubelet](https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/)
- [kube-state-metrics](https://github.com/kubernetes/kube-state-metrics)
- [apiserver](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)
- [controller-manager](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/)
- [scheduler](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-scheduler/)
- [proxy](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-proxy/)

Some of the previous components are running on each of the Kubernetes nodes (like `kubelet` or `proxy`) while others provide
a single cluster-wide endpoint. This is important to determine the optimal configuration and running strategy
for the different datasets included in the integration.

For a complete reference on how to configure and run this package on Kubernetes as part of a `DaemonSet` and a `Deployment`,
there's a complete example manifest available in <<TODO: link to the proper page here>> document.

#### Kubernetes endpoints and metricsets

Kubernetes module is a bit complex as its internal datasets require access to a wide variety of endpoints.

This section highlights and introduces some groups of datasets with similar endpoint access needs. 
For more details on the datasets see `configuration example` and the `datasets` sections below.


#### node / system / pod / container / module / volume

The datasets `container`, `node`, `pod`, `system` and `volume` require access to the `kubelet endpoint` in each of
the Kubernetes nodes, hence it's recommended to include them as part
of an `Agent DaemonSet` or standalone Agents running on the hosts.

Depending on the version and configuration of Kubernetes nodes, `kubelet` might provide a read only http port (typically 10255),
which is used in some configuration examples. But in general, and lately, this endpoint requires SSL (`https`) access
(to port 10250 by default) and token based authentication.


##### state_* and event

All datasets with the `state_` prefix require `hosts` field pointing to `kube-state-metrics`
service within the cluster. As the service provides cluster-wide metrics, there's no need to fetch them per node,
hence the recommendation is to run these datasets as part of an `Agent Deployment` with one only replica.

Note: Kube-state-metrics is not deployed by default in Kubernetes. For these cases the instructions for its
deployment are available [here](https://github.com/kubernetes/kube-state-metrics#kubernetes-deployment). 
Generally `kube-state-metrics` runs a `Deployment` and is accessible via a service called `kube-state-metrics` on
`kube-system` namespace, which will be the service to use in our configuration.

#### apiserver

The apiserver dataset requires access to the Kubernetes API, which should be easily available in all Kubernetes
environments. Depending on the Kubernetes configuration, the API access might require SSL (`https`) and token
based authentication.

#### proxy

The proxy dataset requires access to the proxy endpoint in each of Kubernetes nodes, hence it's recommended
to configure it as a part of an `Agent DaemonSet`.

#### scheduler and controllermanager

These datasets require access to the Kubernetes `controller-manager` and `scheduler` endpoints. By default, these pods
run only on master nodes, and they are not exposed via a Service, but there are different strategies
available for its configuration:

- Create `Kubernetes Services` to make `kube-controller-manager` and `kube-scheduler` available and configure
 the datasets to point to these services as part of an `Agent Deployment`.
- Run these datasets as part an `Agent Daemonset` (with HostNetwork setting) with a `nodeSelector` to only run on Master nodes.


Note: In some "As a Service" Kubernetes implementations, like `GKE`, the master nodes or even the pods running on
the masters won't be visible. In these cases it won't be possible to use `scheduler` and `controllermanager` metricsets.

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
  "_id": "XVh163IBolOt49UrV2yq",
  "_index": ".ds-metrics-kubernetes.apiserver-default-000001",
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:30:34.616Z",
    "agent": {
      "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
      "id": "a6147a6e-6626-4a84-9907-f372f6c61eee",
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "type": "metricbeat",
      "version": "8.0.0"
    },
    "dataset": {
      "name": "kubernetes.apiserver",
      "namespace": "default",
      "type": "metrics"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "event": {
      "dataset": "kubernetes.apiserver",
      "duration": 114780772,
      "module": "kubernetes"
    },
    "host": {
      "architecture": "x86_64",
      "containerized": false,
      "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "ip": [
        "172.17.0.11"
      ],
      "mac": [
        "02:42:ac:11:00:0b"
      ],
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "os": {
        "codename": "Core",
        "family": "redhat",
        "kernel": "4.19.81",
        "name": "CentOS Linux",
        "platform": "centos",
        "version": "7 (Core)"
      }
    },
    "kubernetes": {
      "apiserver": {
        "request": {
          "client": "metrics-server/v0.0.0 (linux/amd64) kubernetes/$Format",
          "code": "200",
          "component": "apiserver",
          "content_type": "application/vnd.kubernetes.protobuf",
          "count": 3,
          "resource": "nodes",
          "scope": "cluster",
          "verb": "LIST",
          "version": "v1"
        }
      }
    },
    "metricset": {
      "name": "apiserver",
      "period": 30000
    },
    "service": {
      "address": "10.96.0.1:443",
      "type": "kubernetes"
    },
    "stream": {
      "dataset": "kubernetes.apiserver",
      "namespace": "default",
      "type": "metrics"
    }
  },
  "_version": 1,
  "fields": {
    "@timestamp": [
      "2020-06-25T12:30:34.616Z"
    ]
  },
  "sort": [
    1593088234616
  ]
}
```

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
  "_id": "y1h363IBolOt49UrGcjO",
  "_index": ".ds-metrics-kubernetes.container-default-000001",
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:32:29.748Z",
    "agent": {
      "ephemeral_id": "b964a246-96c0-456a-a5c2-8c8b1040ecaf",
      "id": "f7ec69f9-4997-4e76-b6c7-0c75206b727a",
      "name": "minikube",
      "type": "metricbeat",
      "version": "8.0.0"
    },
    "dataset": {
      "name": "kubernetes.container",
      "namespace": "default",
      "type": "metrics"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "event": {
      "dataset": "kubernetes.container",
      "duration": 11091346,
      "module": "kubernetes"
    },
    "host": {
      "architecture": "x86_64",
      "containerized": false,
      "hostname": "minikube",
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "ip": [
        "192.168.64.10",
        "fe80::a883:2fff:fe7f:6b12",
        "172.17.0.1",
        "fe80::42:d4ff:fe8c:9493",
        "fe80::2859:80ff:fe9e:fcd6",
        "fe80::d83a:d9ff:fee9:7052",
        "fe80::880a:b6ff:fe18:ba76",
        "fe80::f447:faff:fe80:e88b",
        "fe80::9cc3:ffff:fe95:e48e",
        "fe80::6c1c:29ff:fe50:d40c",
        "fe80::b4f3:11ff:fe60:14ed",
        "fe80::20f2:2aff:fe96:1e7b",
        "fe80::5434:baff:fede:5720",
        "fe80::a878:91ff:fe29:81f7"
      ],
      "mac": [
        "aa:83:2f:7f:6b:12",
        "02:42:d4:8c:94:93",
        "2a:59:80:9e:fc:d6",
        "da:3a:d9:e9:70:52",
        "8a:0a:b6:18:ba:76",
        "f6:47:fa:80:e8:8b",
        "9e:c3:ff:95:e4:8e",
        "6e:1c:29:50:d4:0c",
        "b6:f3:11:60:14:ed",
        "22:f2:2a:96:1e:7b",
        "56:34:ba:de:57:20",
        "aa:78:91:29:81:f7"
      ],
      "name": "minikube",
      "os": {
        "codename": "Core",
        "family": "redhat",
        "kernel": "4.19.81",
        "name": "CentOS Linux",
        "platform": "centos",
        "version": "7 (Core)"
      }
    },
    "kubernetes": {
      "container": {
        "cpu": {
          "usage": {
            "core": {
              "ns": 12206519774
            },
            "limit": {
              "pct": 0.00015289625
            },
            "nanocores": 611585,
            "node": {
              "pct": 0.00015289625
            }
          }
        },
        "logs": {
          "available": {
            "bytes": 6724222976
          },
          "capacity": {
            "bytes": 17361141760
          },
          "inodes": {
            "count": 9768928,
            "free": 9545018,
            "used": 223910
          },
          "used": {
            "bytes": 1617920
          }
        },
        "memory": {
          "available": {
            "bytes": 188600320
          },
          "majorpagefaults": 528,
          "pagefaults": 10164,
          "rss": {
            "bytes": 18386944
          },
          "usage": {
            "bytes": 94306304,
            "limit": {
              "pct": 0.005608354460473573
            },
            "node": {
              "pct": 0.005608354460473573
            }
          },
          "workingset": {
            "bytes": 21114880
          }
        },
        "name": "metricbeat",
        "rootfs": {
          "available": {
            "bytes": 6724222976
          },
          "capacity": {
            "bytes": 17361141760
          },
          "inodes": {
            "used": 17
          },
          "used": {
            "bytes": 61440
          }
        },
        "start_time": "2020-06-25T07:19:37Z"
      },
      "namespace": "kube-system",
      "node": {
        "name": "minikube"
      },
      "pod": {
        "name": "metricbeat-g9fc6"
      }
    },
    "metricset": {
      "name": "container",
      "period": 10000
    },
    "service": {
      "address": "minikube:10250",
      "type": "kubernetes"
    },
    "stream": {
      "dataset": "kubernetes.container",
      "namespace": "default",
      "type": "metrics"
    }
  },
  "_version": 1,
  "fields": {
    "@timestamp": [
      "2020-06-25T12:32:29.748Z"
    ],
    "kubernetes.container.start_time": [
      "2020-06-25T07:19:37.000Z"
    ]
  },
  "sort": [
    1593088349748
  ]
}
```

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
  "_id": "qFh463IBolOt49UrBPYP",
  "_index": ".ds-metrics-kubernetes.controllermanager-default-000001",
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:33:29.643Z",
    "agent": {
      "ephemeral_id": "b964a246-96c0-456a-a5c2-8c8b1040ecaf",
      "id": "f7ec69f9-4997-4e76-b6c7-0c75206b727a",
      "name": "minikube",
      "type": "metricbeat",
      "version": "8.0.0"
    },
    "dataset": {
      "name": "kubernetes.controllermanager",
      "namespace": "default",
      "type": "metrics"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "event": {
      "dataset": "kubernetes.controllermanager",
      "duration": 8893806,
      "module": "kubernetes"
    },
    "host": {
      "architecture": "x86_64",
      "containerized": false,
      "hostname": "minikube",
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "ip": [
        "192.168.64.10",
        "fe80::a883:2fff:fe7f:6b12",
        "172.17.0.1",
        "fe80::42:d4ff:fe8c:9493",
        "fe80::2859:80ff:fe9e:fcd6",
        "fe80::d83a:d9ff:fee9:7052",
        "fe80::880a:b6ff:fe18:ba76",
        "fe80::f447:faff:fe80:e88b",
        "fe80::9cc3:ffff:fe95:e48e",
        "fe80::6c1c:29ff:fe50:d40c",
        "fe80::b4f3:11ff:fe60:14ed",
        "fe80::20f2:2aff:fe96:1e7b",
        "fe80::5434:baff:fede:5720",
        "fe80::a878:91ff:fe29:81f7"
      ],
      "mac": [
        "aa:83:2f:7f:6b:12",
        "02:42:d4:8c:94:93",
        "2a:59:80:9e:fc:d6",
        "da:3a:d9:e9:70:52",
        "8a:0a:b6:18:ba:76",
        "f6:47:fa:80:e8:8b",
        "9e:c3:ff:95:e4:8e",
        "6e:1c:29:50:d4:0c",
        "b6:f3:11:60:14:ed",
        "22:f2:2a:96:1e:7b",
        "56:34:ba:de:57:20",
        "aa:78:91:29:81:f7"
      ],
      "name": "minikube",
      "os": {
        "codename": "Core",
        "family": "redhat",
        "kernel": "4.19.81",
        "name": "CentOS Linux",
        "platform": "centos",
        "version": "7 (Core)"
      }
    },
    "kubernetes": {
      "controllermanager": {
        "name": "certificate",
        "workqueue": {
          "adds": {
            "count": 0
          },
          "depth": {
            "count": 0
          },
          "longestrunning": {
            "sec": 0
          },
          "retries": {
            "count": 0
          },
          "unfinished": {
            "sec": 0
          }
        }
      }
    },
    "metricset": {
      "name": "controllermanager",
      "period": 10000
    },
    "service": {
      "address": "localhost:10252",
      "type": "kubernetes"
    },
    "stream": {
      "dataset": "kubernetes.controllermanager",
      "namespace": "default",
      "type": "metrics"
    }
  },
  "_version": 1,
  "fields": {
    "@timestamp": [
      "2020-06-25T12:33:29.643Z"
    ]
  },
  "sort": [
    1593088409643
  ]
}
```

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
  "_id": "EVh163IBolOt49UrPGji",
  "_index": ".ds-metrics-kubernetes.event-default-000001",
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:30:27.575Z",
    "agent": {
      "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
      "id": "a6147a6e-6626-4a84-9907-f372f6c61eee",
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "type": "metricbeat",
      "version": "8.0.0"
    },
    "dataset": {
      "name": "kubernetes.event",
      "namespace": "default",
      "type": "metrics"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "event": {
      "dataset": "kubernetes.event",
      "module": "kubernetes"
    },
    "host": {
      "architecture": "x86_64",
      "containerized": false,
      "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "ip": [
        "172.17.0.11"
      ],
      "mac": [
        "02:42:ac:11:00:0b"
      ],
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "os": {
        "codename": "Core",
        "family": "redhat",
        "kernel": "4.19.81",
        "name": "CentOS Linux",
        "platform": "centos",
        "version": "7 (Core)"
      }
    },
    "kubernetes": {
      "event": {
        "count": 1861,
        "involved_object": {
          "api_version": "kibana.k8s.elastic.co/v1",
          "kind": "Kibana",
          "name": "monitor",
          "resource_version": "101842",
          "uid": "45a19de5-5eef-4090-a2d3-dbceb0a28af8"
        },
        "message": "Failed to find referenced backend beats/monitor: Elasticsearch.elasticsearch.k8s.elastic.co \"monitor\" not found",
        "metadata": {
          "generate_name": "",
          "name": "monitor.161bb862545e3099",
          "namespace": "beats",
          "resource_version": "485630",
          "self_link": "/api/v1/namespaces/beats/events/monitor.161bb862545e3099",
          "timestamp": {
            "created": "2020-06-25T07:20:25.000Z"
          },
          "uid": "604e39e0-862f-4615-9cec-8cb62299dea3"
        },
        "reason": "AssociationError",
        "source": {
          "component": "kibana-association-controller",
          "host": ""
        },
        "timestamp": {
          "first_occurrence": "2020-06-25T07:20:25.000Z",
          "last_occurrence": "2020-06-25T12:30:27.000Z"
        },
        "type": "Warning"
      }
    },
    "metricset": {
      "name": "event"
    },
    "service": {
      "type": "kubernetes"
    },
    "stream": {
      "dataset": "kubernetes.event",
      "namespace": "default",
      "type": "metrics"
    }
  },
  "_version": 1,
  "fields": {
    "@timestamp": [
      "2020-06-25T12:30:27.575Z"
    ],
    "kubernetes.event.metadata.timestamp.created": [
      "2020-06-25T07:20:25.000Z"
    ],
    "kubernetes.event.timestamp.first_occurrence": [
      "2020-06-25T07:20:25.000Z"
    ],
    "kubernetes.event.timestamp.last_occurrence": [
      "2020-06-25T12:30:27.000Z"
    ]
  },
  "sort": [
    1593088227575
  ]
}
```

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
  "_id": "Gll563IBolOt49UrFS2Q",
  "_index": ".ds-metrics-kubernetes.node-default-000001",
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:34:39.723Z",
    "agent": {
      "ephemeral_id": "b964a246-96c0-456a-a5c2-8c8b1040ecaf",
      "id": "f7ec69f9-4997-4e76-b6c7-0c75206b727a",
      "name": "minikube",
      "type": "metricbeat",
      "version": "8.0.0"
    },
    "dataset": {
      "name": "kubernetes.node",
      "namespace": "default",
      "type": "metrics"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "event": {
      "dataset": "kubernetes.node",
      "duration": 13042307,
      "module": "kubernetes"
    },
    "host": {
      "architecture": "x86_64",
      "containerized": false,
      "hostname": "minikube",
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "ip": [
        "192.168.64.10",
        "fe80::a883:2fff:fe7f:6b12",
        "172.17.0.1",
        "fe80::42:d4ff:fe8c:9493",
        "fe80::2859:80ff:fe9e:fcd6",
        "fe80::d83a:d9ff:fee9:7052",
        "fe80::880a:b6ff:fe18:ba76",
        "fe80::f447:faff:fe80:e88b",
        "fe80::9cc3:ffff:fe95:e48e",
        "fe80::6c1c:29ff:fe50:d40c",
        "fe80::b4f3:11ff:fe60:14ed",
        "fe80::20f2:2aff:fe96:1e7b",
        "fe80::5434:baff:fede:5720",
        "fe80::a878:91ff:fe29:81f7"
      ],
      "mac": [
        "aa:83:2f:7f:6b:12",
        "02:42:d4:8c:94:93",
        "2a:59:80:9e:fc:d6",
        "da:3a:d9:e9:70:52",
        "8a:0a:b6:18:ba:76",
        "f6:47:fa:80:e8:8b",
        "9e:c3:ff:95:e4:8e",
        "6e:1c:29:50:d4:0c",
        "b6:f3:11:60:14:ed",
        "22:f2:2a:96:1e:7b",
        "56:34:ba:de:57:20",
        "aa:78:91:29:81:f7"
      ],
      "name": "minikube",
      "os": {
        "codename": "Core",
        "family": "redhat",
        "kernel": "4.19.81",
        "name": "CentOS Linux",
        "platform": "centos",
        "version": "7 (Core)"
      }
    },
    "kubernetes": {
      "labels": {
        "beta_kubernetes_io/arch": "amd64",
        "beta_kubernetes_io/os": "linux",
        "kubernetes_io/arch": "amd64",
        "kubernetes_io/hostname": "minikube",
        "kubernetes_io/os": "linux",
        "node-role_kubernetes_io/master": ""
      },
      "node": {
        "cpu": {
          "usage": {
            "core": {
              "ns": 6136184971873
            },
            "nanocores": 455263291
          }
        },
        "fs": {
          "available": {
            "bytes": 6655090688
          },
          "capacity": {
            "bytes": 17361141760
          },
          "inodes": {
            "count": 9768928,
            "free": 9544777,
            "used": 224151
          },
          "used": {
            "bytes": 9689358336
          }
        },
        "memory": {
          "available": {
            "bytes": 12746428416
          },
          "majorpagefaults": 0,
          "pagefaults": 31680,
          "rss": {
            "bytes": 3252125696
          },
          "usage": {
            "bytes": 5670916096
          },
          "workingset": {
            "bytes": 4068896768
          }
        },
        "name": "minikube",
        "network": {
          "rx": {
            "bytes": 107077476,
            "errors": 0
          },
          "tx": {
            "bytes": 67457933,
            "errors": 0
          }
        },
        "runtime": {
          "imagefs": {
            "available": {
              "bytes": 6655090688
            },
            "capacity": {
              "bytes": 17361141760
            },
            "used": {
              "bytes": 8719928568
            }
          }
        },
        "start_time": "2020-06-25T07:18:38Z"
      }
    },
    "metricset": {
      "name": "node",
      "period": 10000
    },
    "service": {
      "address": "minikube:10250",
      "type": "kubernetes"
    },
    "stream": {
      "dataset": "kubernetes.node",
      "namespace": "default",
      "type": "metrics"
    }
  },
  "_version": 1,
  "fields": {
    "@timestamp": [
      "2020-06-25T12:34:39.723Z"
    ],
    "kubernetes.node.start_time": [
      "2020-06-25T07:18:38.000Z"
    ]
  },
  "sort": [
    1593088479723
  ]
}
```

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
  "_id": "4Vl563IBolOt49UrYz6x",
  "_index": ".ds-metrics-kubernetes.pod-default-000001",
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:34:59.729Z",
    "agent": {
      "ephemeral_id": "b964a246-96c0-456a-a5c2-8c8b1040ecaf",
      "id": "f7ec69f9-4997-4e76-b6c7-0c75206b727a",
      "name": "minikube",
      "type": "metricbeat",
      "version": "8.0.0"
    },
    "dataset": {
      "name": "kubernetes.pod",
      "namespace": "default",
      "type": "metrics"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "event": {
      "dataset": "kubernetes.pod",
      "duration": 20735189,
      "module": "kubernetes"
    },
    "host": {
      "architecture": "x86_64",
      "containerized": false,
      "hostname": "minikube",
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "ip": [
        "192.168.64.10",
        "fe80::a883:2fff:fe7f:6b12",
        "172.17.0.1",
        "fe80::42:d4ff:fe8c:9493",
        "fe80::2859:80ff:fe9e:fcd6",
        "fe80::d83a:d9ff:fee9:7052",
        "fe80::880a:b6ff:fe18:ba76",
        "fe80::f447:faff:fe80:e88b",
        "fe80::9cc3:ffff:fe95:e48e",
        "fe80::6c1c:29ff:fe50:d40c",
        "fe80::b4f3:11ff:fe60:14ed",
        "fe80::20f2:2aff:fe96:1e7b",
        "fe80::5434:baff:fede:5720",
        "fe80::a878:91ff:fe29:81f7"
      ],
      "mac": [
        "aa:83:2f:7f:6b:12",
        "02:42:d4:8c:94:93",
        "2a:59:80:9e:fc:d6",
        "da:3a:d9:e9:70:52",
        "8a:0a:b6:18:ba:76",
        "f6:47:fa:80:e8:8b",
        "9e:c3:ff:95:e4:8e",
        "6e:1c:29:50:d4:0c",
        "b6:f3:11:60:14:ed",
        "22:f2:2a:96:1e:7b",
        "56:34:ba:de:57:20",
        "aa:78:91:29:81:f7"
      ],
      "name": "minikube",
      "os": {
        "codename": "Core",
        "family": "redhat",
        "kernel": "4.19.81",
        "name": "CentOS Linux",
        "platform": "centos",
        "version": "7 (Core)"
      }
    },
    "kubernetes": {
      "namespace": "kube-system",
      "node": {
        "name": "minikube"
      },
      "pod": {
        "cpu": {
          "usage": {
            "limit": {
              "pct": 0.0007029795
            },
            "nanocores": 2811918,
            "node": {
              "pct": 0.0007029795
            }
          }
        },
        "memory": {
          "available": {
            "bytes": 0
          },
          "major_page_faults": 0,
          "page_faults": 5742,
          "rss": {
            "bytes": 7823360
          },
          "usage": {
            "bytes": 13508608,
            "limit": {
              "pct": 0.0008033509820466402
            },
            "node": {
              "pct": 0.0008033509820466402
            }
          },
          "working_set": {
            "bytes": 8556544
          }
        },
        "name": "kube-state-metrics-57cd6fdf9-hd959",
        "network": {
          "rx": {
            "bytes": 25671624,
            "errors": 0
          },
          "tx": {
            "bytes": 1092900259,
            "errors": 0
          }
        },
        "start_time": "2020-06-18T11:12:58Z",
        "uid": "a7c61334-dd52-4a12-bed5-4daee4c74139"
      }
    },
    "metricset": {
      "name": "pod",
      "period": 10000
    },
    "service": {
      "address": "minikube:10250",
      "type": "kubernetes"
    },
    "stream": {
      "dataset": "kubernetes.pod",
      "namespace": "default",
      "type": "metrics"
    }
  },
  "_version": 1,
  "fields": {
    "@timestamp": [
      "2020-06-25T12:34:59.729Z"
    ],
    "kubernetes.pod.start_time": [
      "2020-06-18T11:12:58.000Z"
    ]
  },
  "sort": [
    1593088499729
  ]
}
```

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
  "_id": "Z1l563IBolOt49Ur2FXO",
  "_index": ".ds-metrics-kubernetes.proxy-default-000001",
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:35:29.639Z",
    "agent": {
      "ephemeral_id": "b964a246-96c0-456a-a5c2-8c8b1040ecaf",
      "id": "f7ec69f9-4997-4e76-b6c7-0c75206b727a",
      "name": "minikube",
      "type": "metricbeat",
      "version": "8.0.0"
    },
    "dataset": {
      "name": "kubernetes.proxy",
      "namespace": "default",
      "type": "metrics"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "event": {
      "dataset": "kubernetes.proxy",
      "duration": 2031254,
      "module": "kubernetes"
    },
    "host": {
      "architecture": "x86_64",
      "containerized": false,
      "hostname": "minikube",
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "ip": [
        "192.168.64.10",
        "fe80::a883:2fff:fe7f:6b12",
        "172.17.0.1",
        "fe80::42:d4ff:fe8c:9493",
        "fe80::2859:80ff:fe9e:fcd6",
        "fe80::d83a:d9ff:fee9:7052",
        "fe80::880a:b6ff:fe18:ba76",
        "fe80::f447:faff:fe80:e88b",
        "fe80::9cc3:ffff:fe95:e48e",
        "fe80::6c1c:29ff:fe50:d40c",
        "fe80::b4f3:11ff:fe60:14ed",
        "fe80::20f2:2aff:fe96:1e7b",
        "fe80::5434:baff:fede:5720",
        "fe80::a878:91ff:fe29:81f7"
      ],
      "mac": [
        "aa:83:2f:7f:6b:12",
        "02:42:d4:8c:94:93",
        "2a:59:80:9e:fc:d6",
        "da:3a:d9:e9:70:52",
        "8a:0a:b6:18:ba:76",
        "f6:47:fa:80:e8:8b",
        "9e:c3:ff:95:e4:8e",
        "6e:1c:29:50:d4:0c",
        "b6:f3:11:60:14:ed",
        "22:f2:2a:96:1e:7b",
        "56:34:ba:de:57:20",
        "aa:78:91:29:81:f7"
      ],
      "name": "minikube",
      "os": {
        "codename": "Core",
        "family": "redhat",
        "kernel": "4.19.81",
        "name": "CentOS Linux",
        "platform": "centos",
        "version": "7 (Core)"
      }
    },
    "kubernetes": {
      "proxy": {
        "process": {
          "cpu": {
            "sec": 8
          },
          "fds": {
            "open": {
              "count": 17
            }
          },
          "memory": {
            "resident": {
              "bytes": 37609472
            },
            "virtual": {
              "bytes": 143990784
            }
          },
          "started": {
            "sec": 1593069580.69
          }
        },
        "sync": {
          "networkprogramming": {
            "duration": {
              "us": {
                "bucket": {
                  "+Inf": 19,
                  "0": 0,
                  "1000000": 11,
                  "10000000": 11,
                  "100000000": 11,
                  "105000000": 11,
                  "11000000": 11,
                  "110000000": 11,
                  "115000000": 11,
                  "12000000": 11,
                  "120000000": 11,
                  "13000000": 11,
                  "14000000": 11,
                  "15000000": 11,
                  "150000000": 11,
                  "16000000": 11,
                  "17000000": 11,
                  "18000000": 11,
                  "180000000": 11,
                  "19000000": 11,
                  "2000000": 11,
                  "20000000": 11,
                  "21000000": 11,
                  "210000000": 11,
                  "22000000": 11,
                  "23000000": 11,
                  "24000000": 11,
                  "240000000": 11,
                  "250000": 4,
                  "25000000": 11,
                  "26000000": 11,
                  "27000000": 11,
                  "270000000": 11,
                  "28000000": 11,
                  "29000000": 11,
                  "3000000": 11,
                  "30000000": 11,
                  "300000000": 11,
                  "31000000": 11,
                  "32000000": 11,
                  "33000000": 11,
                  "34000000": 11,
                  "35000000": 11,
                  "36000000": 11,
                  "37000000": 11,
                  "38000000": 11,
                  "39000000": 11,
                  "4000000": 11,
                  "40000000": 11,
                  "41000000": 11,
                  "42000000": 11,
                  "43000000": 11,
                  "44000000": 11,
                  "45000000": 11,
                  "46000000": 11,
                  "47000000": 11,
                  "48000000": 11,
                  "49000000": 11,
                  "500000": 8,
                  "5000000": 11,
                  "50000000": 11,
                  "51000000": 11,
                  "52000000": 11,
                  "53000000": 11,
                  "54000000": 11,
                  "55000000": 11,
                  "56000000": 11,
                  "57000000": 11,
                  "58000000": 11,
                  "59000000": 11,
                  "6000000": 11,
                  "60000000": 11,
                  "65000000": 11,
                  "7000000": 11,
                  "70000000": 11,
                  "75000000": 11,
                  "8000000": 11,
                  "80000000": 11,
                  "85000000": 11,
                  "9000000": 11,
                  "90000000": 11,
                  "95000000": 11
                },
                "count": 19,
                "sum": 5571080914163.27
              }
            }
          },
          "rules": {
            "duration": {
              "us": {
                "bucket": {
                  "+Inf": 18,
                  "1000": 0,
                  "1024000": 18,
                  "128000": 17,
                  "16000": 0,
                  "16384000": 18,
                  "2000": 0,
                  "2048000": 18,
                  "256000": 18,
                  "32000": 10,
                  "4000": 0,
                  "4096000": 18,
                  "512000": 18,
                  "64000": 16,
                  "8000": 0,
                  "8192000": 18
                },
                "count": 18,
                "sum": 763620.9329999998
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
      "address": "localhost:10249",
      "type": "kubernetes"
    },
    "stream": {
      "dataset": "kubernetes.proxy",
      "namespace": "default",
      "type": "metrics"
    }
  },
  "_version": 1,
  "fields": {
    "@timestamp": [
      "2020-06-25T12:35:29.639Z"
    ]
  },
  "sort": [
    1593088529639
  ]
}
```

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
  "_id": "01l663IBolOt49UrTW36",
  "_index": ".ds-metrics-kubernetes.scheduler-default-000001",
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:35:59.624Z",
    "agent": {
      "ephemeral_id": "b964a246-96c0-456a-a5c2-8c8b1040ecaf",
      "id": "f7ec69f9-4997-4e76-b6c7-0c75206b727a",
      "name": "minikube",
      "type": "metricbeat",
      "version": "8.0.0"
    },
    "dataset": {
      "name": "kubernetes.scheduler",
      "namespace": "default",
      "type": "metrics"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "event": {
      "dataset": "kubernetes.scheduler",
      "duration": 7245648,
      "module": "kubernetes"
    },
    "host": {
      "architecture": "x86_64",
      "containerized": false,
      "hostname": "minikube",
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "ip": [
        "192.168.64.10",
        "fe80::a883:2fff:fe7f:6b12",
        "172.17.0.1",
        "fe80::42:d4ff:fe8c:9493",
        "fe80::2859:80ff:fe9e:fcd6",
        "fe80::d83a:d9ff:fee9:7052",
        "fe80::880a:b6ff:fe18:ba76",
        "fe80::f447:faff:fe80:e88b",
        "fe80::9cc3:ffff:fe95:e48e",
        "fe80::6c1c:29ff:fe50:d40c",
        "fe80::b4f3:11ff:fe60:14ed",
        "fe80::20f2:2aff:fe96:1e7b",
        "fe80::5434:baff:fede:5720",
        "fe80::a878:91ff:fe29:81f7"
      ],
      "mac": [
        "aa:83:2f:7f:6b:12",
        "02:42:d4:8c:94:93",
        "2a:59:80:9e:fc:d6",
        "da:3a:d9:e9:70:52",
        "8a:0a:b6:18:ba:76",
        "f6:47:fa:80:e8:8b",
        "9e:c3:ff:95:e4:8e",
        "6e:1c:29:50:d4:0c",
        "b6:f3:11:60:14:ed",
        "22:f2:2a:96:1e:7b",
        "56:34:ba:de:57:20",
        "aa:78:91:29:81:f7"
      ],
      "name": "minikube",
      "os": {
        "codename": "Core",
        "family": "redhat",
        "kernel": "4.19.81",
        "name": "CentOS Linux",
        "platform": "centos",
        "version": "7 (Core)"
      }
    },
    "kubernetes": {
      "scheduler": {
        "leader": {
          "is_master": true
        },
        "name": "kube-scheduler"
      }
    },
    "metricset": {
      "name": "scheduler",
      "period": 10000
    },
    "service": {
      "address": "localhost:10251",
      "type": "kubernetes"
    },
    "stream": {
      "dataset": "kubernetes.scheduler",
      "namespace": "default",
      "type": "metrics"
    }
  },
  "_version": 1,
  "fields": {
    "@timestamp": [
      "2020-06-25T12:35:59.624Z"
    ]
  },
  "sort": [
    1593088559624
  ]
}
```

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
  "_id": "P1l663IBolOt49Ur1YbF",
  "_index": ".ds-metrics-kubernetes.state_container-default-000001",
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:36:34.469Z",
    "agent": {
      "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
      "id": "a6147a6e-6626-4a84-9907-f372f6c61eee",
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "type": "metricbeat",
      "version": "8.0.0"
    },
    "container": {
      "id": "b00b185f2b304a7ece804d1af28eb232f825255f716bcc85ef5bd20d5a4f45d4",
      "runtime": "docker"
    },
    "dataset": {
      "name": "kubernetes.state_container",
      "namespace": "default",
      "type": "metrics"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "event": {
      "dataset": "kubernetes.container",
      "duration": 8554499,
      "module": "kubernetes"
    },
    "host": {
      "architecture": "x86_64",
      "containerized": false,
      "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "ip": [
        "172.17.0.11"
      ],
      "mac": [
        "02:42:ac:11:00:0b"
      ],
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "os": {
        "codename": "Core",
        "family": "redhat",
        "kernel": "4.19.81",
        "name": "CentOS Linux",
        "platform": "centos",
        "version": "7 (Core)"
      }
    },
    "kubernetes": {
      "container": {
        "cpu": {
          "request": {
            "cores": 0.1
          }
        },
        "id": "docker://b00b185f2b304a7ece804d1af28eb232f825255f716bcc85ef5bd20d5a4f45d4",
        "image": "k8s.gcr.io/kube-scheduler:v1.17.0",
        "name": "kube-scheduler",
        "status": {
          "phase": "running",
          "ready": true,
          "restarts": 10
        }
      },
      "labels": {
        "component": "kube-scheduler",
        "tier": "control-plane"
      },
      "namespace": "kube-system",
      "node": {
        "name": "minikube"
      },
      "pod": {
        "name": "kube-scheduler-minikube",
        "uid": "9cdbd5ea-7638-4e86-a706-a5b222d86f26"
      }
    },
    "metricset": {
      "name": "state_container",
      "period": 10000
    },
    "service": {
      "address": "kube-state-metrics:8080",
      "type": "kubernetes"
    },
    "stream": {
      "dataset": "kubernetes.state_container",
      "namespace": "default",
      "type": "metrics"
    }
  },
  "_version": 1,
  "fields": {
    "@timestamp": [
      "2020-06-25T12:36:34.469Z"
    ]
  },
  "sort": [
    1593088594469
  ]
}
```

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
  "_id": "qFqA63IBolOt49Urybs0",
  "_index": ".ds-metrics-kubernetes.state_cronjob-default-000001",
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:43:04.384Z",
    "agent": {
      "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
      "id": "a6147a6e-6626-4a84-9907-f372f6c61eee",
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "type": "metricbeat",
      "version": "8.0.0"
    },
    "dataset": {
      "name": "kubernetes.state_cronjob",
      "namespace": "default",
      "type": "metrics"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "event": {
      "dataset": "kubernetes.cronjob",
      "duration": 9482053,
      "module": "kubernetes"
    },
    "host": {
      "architecture": "x86_64",
      "containerized": false,
      "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "ip": [
        "172.17.0.11"
      ],
      "mac": [
        "02:42:ac:11:00:0b"
      ],
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "os": {
        "codename": "Core",
        "family": "redhat",
        "kernel": "4.19.81",
        "name": "CentOS Linux",
        "platform": "centos",
        "version": "7 (Core)"
      }
    },
    "kubernetes": {
      "cronjob": {
        "active": {
          "count": 0
        },
        "created": {
          "sec": 1593088862
        },
        "is_suspended": false,
        "last_schedule": {
          "sec": 1593088920
        },
        "name": "hello",
        "next_schedule": {
          "sec": 1593088980
        }
      },
      "namespace": "default"
    },
    "metricset": {
      "name": "state_cronjob",
      "period": 10000
    },
    "service": {
      "address": "kube-state-metrics:8080",
      "type": "kubernetes"
    },
    "stream": {
      "dataset": "kubernetes.state_cronjob",
      "namespace": "default",
      "type": "metrics"
    }
  },
  "_version": 1,
  "fields": {
    "@timestamp": [
      "2020-06-25T12:43:04.384Z"
    ]
  },
  "sort": [
    1593088984384
  ]
}
```

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
  "_id": "H1l763IBolOt49UrSp72",
  "_index": ".ds-metrics-kubernetes.state_deployment-default-000001",
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:37:04.455Z",
    "agent": {
      "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
      "id": "a6147a6e-6626-4a84-9907-f372f6c61eee",
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "type": "metricbeat",
      "version": "8.0.0"
    },
    "dataset": {
      "name": "kubernetes.state_deployment",
      "namespace": "default",
      "type": "metrics"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "event": {
      "dataset": "kubernetes.deployment",
      "duration": 8648138,
      "module": "kubernetes"
    },
    "host": {
      "architecture": "x86_64",
      "containerized": false,
      "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "ip": [
        "172.17.0.11"
      ],
      "mac": [
        "02:42:ac:11:00:0b"
      ],
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "os": {
        "codename": "Core",
        "family": "redhat",
        "kernel": "4.19.81",
        "name": "CentOS Linux",
        "platform": "centos",
        "version": "7 (Core)"
      }
    },
    "kubernetes": {
      "deployment": {
        "name": "metricbeat",
        "paused": false,
        "replicas": {
          "available": 1,
          "desired": 1,
          "unavailable": 0,
          "updated": 1
        }
      },
      "labels": {
        "k8s-app": "metricbeat"
      },
      "namespace": "kube-system"
    },
    "metricset": {
      "name": "state_deployment",
      "period": 10000
    },
    "service": {
      "address": "kube-state-metrics:8080",
      "type": "kubernetes"
    },
    "stream": {
      "dataset": "kubernetes.state_deployment",
      "namespace": "default",
      "type": "metrics"
    }
  },
  "_version": 1,
  "fields": {
    "@timestamp": [
      "2020-06-25T12:37:04.455Z"
    ]
  },
  "sort": [
    1593088624455
  ]
}
```

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
  "_id": "c1l763IBolOt49Ur58c8",
  "_index": ".ds-metrics-kubernetes.state_node-default-000001",
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:37:44.457Z",
    "agent": {
      "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
      "id": "a6147a6e-6626-4a84-9907-f372f6c61eee",
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "type": "metricbeat",
      "version": "8.0.0"
    },
    "dataset": {
      "name": "kubernetes.state_node",
      "namespace": "default",
      "type": "metrics"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "event": {
      "dataset": "kubernetes.node",
      "duration": 8194220,
      "module": "kubernetes"
    },
    "host": {
      "architecture": "x86_64",
      "containerized": false,
      "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "ip": [
        "172.17.0.11"
      ],
      "mac": [
        "02:42:ac:11:00:0b"
      ],
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "os": {
        "codename": "Core",
        "family": "redhat",
        "kernel": "4.19.81",
        "name": "CentOS Linux",
        "platform": "centos",
        "version": "7 (Core)"
      }
    },
    "kubernetes": {
      "labels": {
        "beta_kubernetes_io/arch": "amd64",
        "beta_kubernetes_io/os": "linux",
        "kubernetes_io/arch": "amd64",
        "kubernetes_io/hostname": "minikube",
        "kubernetes_io/os": "linux",
        "node-role_kubernetes_io/master": ""
      },
      "node": {
        "cpu": {
          "allocatable": {
            "cores": 4
          },
          "capacity": {
            "cores": 4
          }
        },
        "memory": {
          "allocatable": {
            "bytes": 16815325184
          },
          "capacity": {
            "bytes": 16815325184
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
      "name": "state_node",
      "period": 10000
    },
    "service": {
      "address": "kube-state-metrics:8080",
      "type": "kubernetes"
    },
    "stream": {
      "dataset": "kubernetes.state_node",
      "namespace": "default",
      "type": "metrics"
    }
  },
  "_version": 1,
  "fields": {
    "@timestamp": [
      "2020-06-25T12:37:44.457Z"
    ]
  },
  "sort": [
    1593088664457
  ]
}
```

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

An example event for `state_persistentvolume` looks as following:

```$json
{
  "_id": "8lqB63IBolOt49UrjOyD",
  "_index": ".ds-metrics-kubernetes.state_persistentvolume-default-000001",
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:43:54.412Z",
    "agent": {
      "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
      "id": "a6147a6e-6626-4a84-9907-f372f6c61eee",
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "type": "metricbeat",
      "version": "8.0.0"
    },
    "dataset": {
      "name": "kubernetes.state_persistentvolume",
      "namespace": "default",
      "type": "metrics"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "event": {
      "dataset": "kubernetes.persistentvolume",
      "duration": 12149615,
      "module": "kubernetes"
    },
    "host": {
      "architecture": "x86_64",
      "containerized": false,
      "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "ip": [
        "172.17.0.11"
      ],
      "mac": [
        "02:42:ac:11:00:0b"
      ],
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "os": {
        "codename": "Core",
        "family": "redhat",
        "kernel": "4.19.81",
        "name": "CentOS Linux",
        "platform": "centos",
        "version": "7 (Core)"
      }
    },
    "kubernetes": {
      "labels": {
        "type": "local"
      },
      "persistentvolume": {
        "capacity": {
          "bytes": 10737418240
        },
        "name": "task-pv-volume",
        "phase": "Bound",
        "storage_class": "manual"
      }
    },
    "metricset": {
      "name": "state_persistentvolume",
      "period": 10000
    },
    "service": {
      "address": "kube-state-metrics:8080",
      "type": "kubernetes"
    },
    "stream": {
      "dataset": "kubernetes.state_persistentvolume",
      "namespace": "default",
      "type": "metrics"
    }
  },
  "_version": 1,
  "fields": {
    "@timestamp": [
      "2020-06-25T12:43:54.412Z"
    ]
  },
  "sort": [
    1593089034412
  ]
}
```

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

An example event for `state_persistentvolumeclaim` looks as following:

```$json
{
  "_id": "6FuC63IBolOt49UrTxrR",
  "_index": ".ds-metrics-kubernetes.state_persistentvolumeclaim-default-000001",
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:44:44.418Z",
    "agent": {
      "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
      "id": "a6147a6e-6626-4a84-9907-f372f6c61eee",
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "type": "metricbeat",
      "version": "8.0.0"
    },
    "dataset": {
      "name": "kubernetes.state_persistentvolumeclaim",
      "namespace": "default",
      "type": "metrics"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "event": {
      "dataset": "kubernetes.persistentvolumeclaim",
      "duration": 5698588,
      "module": "kubernetes"
    },
    "host": {
      "architecture": "x86_64",
      "containerized": false,
      "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "ip": [
        "172.17.0.11"
      ],
      "mac": [
        "02:42:ac:11:00:0b"
      ],
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "os": {
        "codename": "Core",
        "family": "redhat",
        "kernel": "4.19.81",
        "name": "CentOS Linux",
        "platform": "centos",
        "version": "7 (Core)"
      }
    },
    "kubernetes": {
      "namespace": "default",
      "persistentvolumeclaim": {
        "access_mode": "ReadWriteOnce",
        "name": "task-pv-claim",
        "phase": "Bound",
        "request_storage": {
          "bytes": 3221225472
        },
        "storage_class": "manual",
        "volume_name": "task-pv-volume"
      }
    },
    "metricset": {
      "name": "state_persistentvolumeclaim",
      "period": 10000
    },
    "service": {
      "address": "kube-state-metrics:8080",
      "type": "kubernetes"
    },
    "stream": {
      "dataset": "kubernetes.state_persistentvolumeclaim",
      "namespace": "default",
      "type": "metrics"
    }
  },
  "_version": 1,
  "fields": {
    "@timestamp": [
      "2020-06-25T12:44:44.418Z"
    ]
  },
  "sort": [
    1593089084418
  ]
}
```

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
  "_id": "YVl863IBolOt49UrqueH",
  "_index": ".ds-metrics-kubernetes.state_pod-default-000001",
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:38:34.469Z",
    "agent": {
      "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
      "id": "a6147a6e-6626-4a84-9907-f372f6c61eee",
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "type": "metricbeat",
      "version": "8.0.0"
    },
    "dataset": {
      "name": "kubernetes.state_pod",
      "namespace": "default",
      "type": "metrics"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "event": {
      "dataset": "kubernetes.pod",
      "duration": 10777415,
      "module": "kubernetes"
    },
    "host": {
      "architecture": "x86_64",
      "containerized": false,
      "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "ip": [
        "172.17.0.11"
      ],
      "mac": [
        "02:42:ac:11:00:0b"
      ],
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "os": {
        "codename": "Core",
        "family": "redhat",
        "kernel": "4.19.81",
        "name": "CentOS Linux",
        "platform": "centos",
        "version": "7 (Core)"
      }
    },
    "kubernetes": {
      "labels": {
        "controller-revision-hash": "85649b9ddb",
        "k8s-app": "filebeat",
        "pod-template-generation": "1"
      },
      "namespace": "kube-system",
      "node": {
        "name": "minikube"
      },
      "pod": {
        "host_ip": "192.168.64.10",
        "ip": "192.168.64.10",
        "name": "filebeat-dqzzz",
        "status": {
          "phase": "running",
          "ready": "true",
          "scheduled": "true"
        },
        "uid": "a5f1d3c9-40b6-4182-823b-dd5ff9832279"
      }
    },
    "metricset": {
      "name": "state_pod",
      "period": 10000
    },
    "service": {
      "address": "kube-state-metrics:8080",
      "type": "kubernetes"
    },
    "stream": {
      "dataset": "kubernetes.state_pod",
      "namespace": "default",
      "type": "metrics"
    }
  },
  "_version": 1,
  "fields": {
    "@timestamp": [
      "2020-06-25T12:38:34.469Z"
    ]
  },
  "sort": [
    1593088714469
  ]
}
```

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
  "_id": "U1l863IBolOt49Ur-Pu2",
  "_index": ".ds-metrics-kubernetes.state_replicaset-default-000001",
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:38:54.482Z",
    "agent": {
      "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
      "id": "a6147a6e-6626-4a84-9907-f372f6c61eee",
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "type": "metricbeat",
      "version": "8.0.0"
    },
    "dataset": {
      "name": "kubernetes.state_replicaset",
      "namespace": "default",
      "type": "metrics"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "event": {
      "dataset": "kubernetes.replicaset",
      "duration": 5456128,
      "module": "kubernetes"
    },
    "host": {
      "architecture": "x86_64",
      "containerized": false,
      "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "ip": [
        "172.17.0.11"
      ],
      "mac": [
        "02:42:ac:11:00:0b"
      ],
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "os": {
        "codename": "Core",
        "family": "redhat",
        "kernel": "4.19.81",
        "name": "CentOS Linux",
        "platform": "centos",
        "version": "7 (Core)"
      }
    },
    "kubernetes": {
      "deployment": {
        "name": "nginx-ingress-controller"
      },
      "labels": {
        "addonmanager_kubernetes_io/mode": "Reconcile",
        "app_kubernetes_io/name": "nginx-ingress-controller",
        "app_kubernetes_io/part-of": "kube-system",
        "pod-template-hash": "6fc5bcc8c9"
      },
      "namespace": "kube-system",
      "replicaset": {
        "name": "nginx-ingress-controller-6fc5bcc8c9",
        "replicas": {
          "available": 1,
          "desired": 1,
          "labeled": 1,
          "observed": 1,
          "ready": 1
        }
      }
    },
    "metricset": {
      "name": "state_replicaset",
      "period": 10000
    },
    "service": {
      "address": "kube-state-metrics:8080",
      "type": "kubernetes"
    },
    "stream": {
      "dataset": "kubernetes.state_replicaset",
      "namespace": "default",
      "type": "metrics"
    }
  },
  "_version": 1,
  "fields": {
    "@timestamp": [
      "2020-06-25T12:38:54.482Z"
    ]
  },
  "sort": [
    1593088734482
  ]
}
```

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

This is the `state_resourcequota` dataset of the Kubernetes package. It collects ResourceQuota related metrics
from `kube_state_metrics`.

An example event for `state_resourcequota` looks as following:

```$json
{
  "_id": "4FuC63IBolOt49UrnSHz",
  "_index": ".ds-metrics-kubernetes.state_resourcequota-default-000001",
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:45:04.416Z",
    "agent": {
      "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
      "id": "a6147a6e-6626-4a84-9907-f372f6c61eee",
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "type": "metricbeat",
      "version": "8.0.0"
    },
    "dataset": {
      "name": "kubernetes.state_resourcequota",
      "namespace": "default",
      "type": "metrics"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "event": {
      "dataset": "kubernetes.resourcequota",
      "duration": 6324269,
      "module": "kubernetes"
    },
    "host": {
      "architecture": "x86_64",
      "containerized": false,
      "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "ip": [
        "172.17.0.11"
      ],
      "mac": [
        "02:42:ac:11:00:0b"
      ],
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "os": {
        "codename": "Core",
        "family": "redhat",
        "kernel": "4.19.81",
        "name": "CentOS Linux",
        "platform": "centos",
        "version": "7 (Core)"
      }
    },
    "kubernetes": {
      "namespace": "quota-object-example",
      "resourcequota": {
        "name": "object-quota-demo",
        "quota": 1,
        "resource": "persistentvolumeclaims",
        "type": "hard"
      }
    },
    "metricset": {
      "name": "state_resourcequota",
      "period": 10000
    },
    "service": {
      "address": "kube-state-metrics:8080",
      "type": "kubernetes"
    },
    "stream": {
      "dataset": "kubernetes.state_resourcequota",
      "namespace": "default",
      "type": "metrics"
    }
  },
  "_version": 1,
  "fields": {
    "@timestamp": [
      "2020-06-25T12:45:04.416Z"
    ]
  },
  "sort": [
    1593089104416
  ]
}
```

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
  "_id": "Elp963IBolOt49UrbRPd",
  "_index": ".ds-metrics-kubernetes.state_service-default-000001",
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:39:24.389Z",
    "agent": {
      "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
      "id": "a6147a6e-6626-4a84-9907-f372f6c61eee",
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "type": "metricbeat",
      "version": "8.0.0"
    },
    "dataset": {
      "name": "kubernetes.state_service",
      "namespace": "default",
      "type": "metrics"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "event": {
      "dataset": "kubernetes.service",
      "duration": 10966648,
      "module": "kubernetes"
    },
    "host": {
      "architecture": "x86_64",
      "containerized": false,
      "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "ip": [
        "172.17.0.11"
      ],
      "mac": [
        "02:42:ac:11:00:0b"
      ],
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "os": {
        "codename": "Core",
        "family": "redhat",
        "kernel": "4.19.81",
        "name": "CentOS Linux",
        "platform": "centos",
        "version": "7 (Core)"
      }
    },
    "kubernetes": {
      "labels": {
        "addonmanager_kubernetes_io_mode": "Reconcile",
        "kubernetes_io_minikube_addons": "metrics-server",
        "kubernetes_io_minikube_addons_endpoint": "metrics-server",
        "kubernetes_io_name": "Metrics-server"
      },
      "namespace": "kube-system",
      "service": {
        "cluster_ip": "10.96.124.248",
        "created": "2020-06-10T09:02:27.000Z",
        "name": "metrics-server",
        "type": "ClusterIP"
      }
    },
    "metricset": {
      "name": "state_service",
      "period": 10000
    },
    "service": {
      "address": "kube-state-metrics:8080",
      "type": "kubernetes"
    },
    "stream": {
      "dataset": "kubernetes.state_service",
      "namespace": "default",
      "type": "metrics"
    }
  },
  "_version": 1,
  "fields": {
    "@timestamp": [
      "2020-06-25T12:39:24.389Z"
    ],
    "kubernetes.service.created": [
      "2020-06-10T09:02:27.000Z"
    ]
  },
  "sort": [
    1593088764389
  ]
}
```

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


### state_statefulset

This is the `state_statefulset` dataset of the Kubernetes package.

An example event for `state_statefulset` looks as following:

```$json
{
  "_id": "Elp963IBolOt49UrbRPd",
  "_index": ".ds-metrics-kubernetes.state_statefulset-default-000001",
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:39:24.389Z",
    "agent": {
      "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
      "id": "a6147a6e-6626-4a84-9907-f372f6c61eee",
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "type": "metricbeat",
      "version": "8.0.0"
    },
    "dataset": {
      "name": "kubernetes.state_statefulset",
      "namespace": "default",
      "type": "metrics"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "event": {
      "dataset": "kubernetes.statefulset",
      "duration": 10966648,
      "module": "kubernetes"
    },
    "host": {
      "architecture": "x86_64",
      "containerized": false,
      "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "ip": [
        "172.17.0.11"
      ],
      "mac": [
        "02:42:ac:11:00:0b"
      ],
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "os": {
        "codename": "Core",
        "family": "redhat",
        "kernel": "4.19.81",
        "name": "CentOS Linux",
        "platform": "centos",
        "version": "7 (Core)"
      }
    },
    "kubernetes": {
      "namespace": "default",
      "statefulset": {
        "created": 1511989697,
        "generation": {
          "desired": 4,
          "observed": 2
        },
        "name": "mysql",
        "replicas": {
          "desired": 5,
          "observed": 2
        }
      }
    },
    "metricset": {
      "name": "state_statefulset",
      "period": 10000
    },
    "service": {
      "address": "kube-state-metrics:8080",
      "type": "kubernetes"
    },
    "stream": {
      "dataset": "kubernetes.state_statefulset",
      "namespace": "default",
      "type": "metrics"
    }
  },
  "_version": 1,
  "fields": {
    "@timestamp": [
      "2020-06-25T12:39:24.389Z"
    ],
    "kubernetes.statefulset.created": [
      "2020-06-10T09:02:27.000Z"
    ]
  },
  "sort": [
    1593088764389
  ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| kubernetes.statefulset.created | The creation timestamp (epoch) for StatefulSet | long |
| kubernetes.statefulset.generation.desired | The desired generation per StatefulSet | long |
| kubernetes.statefulset.generation.observed | The observed generation per StatefulSet | long |
| kubernetes.statefulset.replicas.desired | The number of desired replicas per StatefulSet | long |
| kubernetes.statefulset.replicas.observed | The number of observed replicas per StatefulSet | long |


### state_storageclass

This is the `state_storageclass` dataset of the Kubernetes package. It collects 
StorageClass related metrics from `kube_state_metrics`.

An example event for `state_storageclass` looks as following:

```$json
{
  "_id": "KFp963IBolOt49UruyX3",
  "_index": ".ds-metrics-kubernetes.state_storageclass-default-000001",
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:39:44.399Z",
    "agent": {
      "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
      "id": "a6147a6e-6626-4a84-9907-f372f6c61eee",
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "type": "metricbeat",
      "version": "8.0.0"
    },
    "dataset": {
      "name": "kubernetes.state_storageclass",
      "namespace": "default",
      "type": "metrics"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "event": {
      "dataset": "kubernetes.storageclass",
      "duration": 5713503,
      "module": "kubernetes"
    },
    "host": {
      "architecture": "x86_64",
      "containerized": false,
      "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "ip": [
        "172.17.0.11"
      ],
      "mac": [
        "02:42:ac:11:00:0b"
      ],
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "os": {
        "codename": "Core",
        "family": "redhat",
        "kernel": "4.19.81",
        "name": "CentOS Linux",
        "platform": "centos",
        "version": "7 (Core)"
      }
    },
    "kubernetes": {
      "labels": {
        "addonmanager_kubernetes_io_mode": "EnsureExists"
      },
      "storageclass": {
        "created": "2020-06-10T09:02:27.000Z",
        "name": "standard",
        "provisioner": "k8s.io/minikube-hostpath",
        "reclaim_policy": "Delete",
        "volume_binding_mode": "Immediate"
      }
    },
    "metricset": {
      "name": "state_storageclass",
      "period": 10000
    },
    "service": {
      "address": "kube-state-metrics:8080",
      "type": "kubernetes"
    },
    "stream": {
      "dataset": "kubernetes.state_storageclass",
      "namespace": "default",
      "type": "metrics"
    }
  },
  "_version": 1,
  "fields": {
    "@timestamp": [
      "2020-06-25T12:39:44.399Z"
    ],
    "kubernetes.storageclass.created": [
      "2020-06-10T09:02:27.000Z"
    ]
  },
  "sort": [
    1593088784399
  ]
}
```

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
  "_id": "sVp963IBolOt49Ur9yyT",
  "_index": ".ds-metrics-kubernetes.system-default-000001",
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:39:59.647Z",
    "agent": {
      "ephemeral_id": "b964a246-96c0-456a-a5c2-8c8b1040ecaf",
      "id": "f7ec69f9-4997-4e76-b6c7-0c75206b727a",
      "name": "minikube",
      "type": "metricbeat",
      "version": "8.0.0"
    },
    "dataset": {
      "name": "kubernetes.system",
      "namespace": "default",
      "type": "metrics"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "event": {
      "dataset": "kubernetes.system",
      "duration": 20012905,
      "module": "kubernetes"
    },
    "host": {
      "architecture": "x86_64",
      "containerized": false,
      "hostname": "minikube",
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "ip": [
        "192.168.64.10",
        "fe80::a883:2fff:fe7f:6b12",
        "172.17.0.1",
        "fe80::42:d4ff:fe8c:9493",
        "fe80::2859:80ff:fe9e:fcd6",
        "fe80::d83a:d9ff:fee9:7052",
        "fe80::880a:b6ff:fe18:ba76",
        "fe80::f447:faff:fe80:e88b",
        "fe80::9cc3:ffff:fe95:e48e",
        "fe80::6c1c:29ff:fe50:d40c",
        "fe80::b4f3:11ff:fe60:14ed",
        "fe80::20f2:2aff:fe96:1e7b",
        "fe80::5434:baff:fede:5720",
        "fe80::a878:91ff:fe29:81f7"
      ],
      "mac": [
        "aa:83:2f:7f:6b:12",
        "02:42:d4:8c:94:93",
        "2a:59:80:9e:fc:d6",
        "da:3a:d9:e9:70:52",
        "8a:0a:b6:18:ba:76",
        "f6:47:fa:80:e8:8b",
        "9e:c3:ff:95:e4:8e",
        "6e:1c:29:50:d4:0c",
        "b6:f3:11:60:14:ed",
        "22:f2:2a:96:1e:7b",
        "56:34:ba:de:57:20",
        "aa:78:91:29:81:f7"
      ],
      "name": "minikube",
      "os": {
        "codename": "Core",
        "family": "redhat",
        "kernel": "4.19.81",
        "name": "CentOS Linux",
        "platform": "centos",
        "version": "7 (Core)"
      }
    },
    "kubernetes": {
      "node": {
        "name": "minikube"
      },
      "system": {
        "container": "runtime",
        "cpu": {
          "usage": {
            "core": {
              "ns": 530899961233
            },
            "nanocores": 35779815
          }
        },
        "memory": {
          "majorpagefaults": 99,
          "pagefaults": 12944019,
          "rss": {
            "bytes": 125259776
          },
          "usage": {
            "bytes": 198279168
          },
          "workingset": {
            "bytes": 178794496
          }
        },
        "start_time": "2020-06-25T07:19:32Z"
      }
    },
    "metricset": {
      "name": "system",
      "period": 10000
    },
    "service": {
      "address": "minikube:10250",
      "type": "kubernetes"
    },
    "stream": {
      "dataset": "kubernetes.system",
      "namespace": "default",
      "type": "metrics"
    }
  },
  "_version": 1,
  "fields": {
    "@timestamp": [
      "2020-06-25T12:39:59.647Z"
    ],
    "kubernetes.system.start_time": [
      "2020-06-25T07:19:32.000Z"
    ]
  },
  "sort": [
    1593088799647
  ]
}
```

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
  "_id": "b1p-63IBolOt49UrRT-d",
  "_index": ".ds-metrics-kubernetes.volume-default-000001",
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:40:19.649Z",
    "agent": {
      "ephemeral_id": "b964a246-96c0-456a-a5c2-8c8b1040ecaf",
      "id": "f7ec69f9-4997-4e76-b6c7-0c75206b727a",
      "name": "minikube",
      "type": "metricbeat",
      "version": "8.0.0"
    },
    "dataset": {
      "name": "kubernetes.volume",
      "namespace": "default",
      "type": "metrics"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "event": {
      "dataset": "kubernetes.volume",
      "duration": 12481688,
      "module": "kubernetes"
    },
    "host": {
      "architecture": "x86_64",
      "containerized": false,
      "hostname": "minikube",
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "ip": [
        "192.168.64.10",
        "fe80::a883:2fff:fe7f:6b12",
        "172.17.0.1",
        "fe80::42:d4ff:fe8c:9493",
        "fe80::2859:80ff:fe9e:fcd6",
        "fe80::d83a:d9ff:fee9:7052",
        "fe80::880a:b6ff:fe18:ba76",
        "fe80::f447:faff:fe80:e88b",
        "fe80::9cc3:ffff:fe95:e48e",
        "fe80::6c1c:29ff:fe50:d40c",
        "fe80::b4f3:11ff:fe60:14ed",
        "fe80::20f2:2aff:fe96:1e7b",
        "fe80::5434:baff:fede:5720",
        "fe80::a878:91ff:fe29:81f7"
      ],
      "mac": [
        "aa:83:2f:7f:6b:12",
        "02:42:d4:8c:94:93",
        "2a:59:80:9e:fc:d6",
        "da:3a:d9:e9:70:52",
        "8a:0a:b6:18:ba:76",
        "f6:47:fa:80:e8:8b",
        "9e:c3:ff:95:e4:8e",
        "6e:1c:29:50:d4:0c",
        "b6:f3:11:60:14:ed",
        "22:f2:2a:96:1e:7b",
        "56:34:ba:de:57:20",
        "aa:78:91:29:81:f7"
      ],
      "name": "minikube",
      "os": {
        "codename": "Core",
        "family": "redhat",
        "kernel": "4.19.81",
        "name": "CentOS Linux",
        "platform": "centos",
        "version": "7 (Core)"
      }
    },
    "kubernetes": {
      "namespace": "kube-system",
      "node": {
        "name": "minikube"
      },
      "pod": {
        "name": "metricbeat-g9fc6"
      },
      "volume": {
        "fs": {
          "available": {
            "bytes": 7719858176
          },
          "capacity": {
            "bytes": 17361141760
          },
          "inodes": {
            "count": 9768928,
            "free": 9549949,
            "used": 5
          },
          "used": {
            "bytes": 12288
          }
        },
        "name": "config"
      }
    },
    "metricset": {
      "name": "volume",
      "period": 10000
    },
    "service": {
      "address": "minikube:10250",
      "type": "kubernetes"
    },
    "stream": {
      "dataset": "kubernetes.volume",
      "namespace": "default",
      "type": "metrics"
    }
  },
  "_version": 1,
  "fields": {
    "@timestamp": [
      "2020-06-25T12:40:19.649Z"
    ]
  },
  "sort": [
    1593088819649
  ]
}
```

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
