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
  "_index": ".ds-metrics-kubernetes.apiserver-default-000001",
  "_id": "XVh163IBolOt49UrV2yq",
  "_version": 1,
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:30:34.616Z",
    "metricset": {
      "name": "apiserver",
      "period": 30000
    },
    "service": {
      "address": "10.96.0.1:443",
      "type": "kubernetes"
    },
    "event": {
      "dataset": "kubernetes.apiserver",
      "module": "kubernetes",
      "duration": 114780772
    },
    "kubernetes": {
      "apiserver": {
        "request": {
          "client": "metrics-server/v0.0.0 (linux/amd64) kubernetes/$Format",
          "version": "v1",
          "count": 3,
          "scope": "cluster",
          "content_type": "application/vnd.kubernetes.protobuf",
          "code": "200",
          "verb": "LIST",
          "component": "apiserver",
          "resource": "nodes"
        }
      }
    },
    "ecs": {
      "version": "1.5.0"
    },
    "agent": {
      "version": "8.0.0",
      "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
      "id": "a6147a6e-6626-4a84-9907-f372f6c61eee",
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "type": "metricbeat"
    },
    "dataset": {
      "namespace": "default",
      "type": "metrics",
      "name": "kubernetes.apiserver"
    },
    "stream": {
      "dataset": "kubernetes.apiserver",
      "namespace": "default",
      "type": "metrics"
    },
    "host": {
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "containerized": false,
      "ip": [
        "172.17.0.11"
      ],
      "mac": [
        "02:42:ac:11:00:0b"
      ],
      "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "architecture": "x86_64",
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "os": {
        "family": "redhat",
        "name": "CentOS Linux",
        "kernel": "4.19.81",
        "codename": "Core",
        "platform": "centos",
        "version": "7 (Core)"
      }
    }
  },
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

The fields reported are:

{{fields "apiserver"}}

### container

This is the `container` dataset of the Kubernetes package. It collects container related metrics
from Kubelet's monitoring APIs.

An example event for `container` looks as following:

```$json
{
  "_index": ".ds-metrics-kubernetes.container-default-000001",
  "_id": "y1h363IBolOt49UrGcjO",
  "_version": 1,
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:32:29.748Z",
    "kubernetes": {
      "namespace": "kube-system",
      "node": {
        "name": "minikube"
      },
      "pod": {
        "name": "metricbeat-g9fc6"
      },
      "container": {
        "rootfs": {
          "used": {
            "bytes": 61440
          },
          "inodes": {
            "used": 17
          },
          "available": {
            "bytes": 6724222976
          },
          "capacity": {
            "bytes": 17361141760
          }
        },
        "logs": {
          "used": {
            "bytes": 1617920
          },
          "inodes": {
            "count": 9768928,
            "used": 223910,
            "free": 9545018
          },
          "available": {
            "bytes": 6724222976
          },
          "capacity": {
            "bytes": 17361141760
          }
        },
        "start_time": "2020-06-25T07:19:37Z",
        "name": "metricbeat",
        "cpu": {
          "usage": {
            "node": {
              "pct": 0.00015289625
            },
            "limit": {
              "pct": 0.00015289625
            },
            "nanocores": 611585,
            "core": {
              "ns": 12206519774
            }
          }
        },
        "memory": {
          "pagefaults": 10164,
          "majorpagefaults": 528,
          "available": {
            "bytes": 188600320
          },
          "usage": {
            "limit": {
              "pct": 0.005608354460473573
            },
            "bytes": 94306304,
            "node": {
              "pct": 0.005608354460473573
            }
          },
          "workingset": {
            "bytes": 21114880
          },
          "rss": {
            "bytes": 18386944
          }
        }
      }
    },
    "dataset": {
      "namespace": "default",
      "type": "metrics",
      "name": "kubernetes.container"
    },
    "stream": {
      "namespace": "default",
      "type": "metrics",
      "dataset": "kubernetes.container"
    },
    "host": {
      "containerized": false,
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
      "hostname": "minikube",
      "architecture": "x86_64",
      "os": {
        "family": "redhat",
        "name": "CentOS Linux",
        "kernel": "4.19.81",
        "codename": "Core",
        "platform": "centos",
        "version": "7 (Core)"
      },
      "name": "minikube",
      "id": "b0e83d397c054b8a99a431072fe4617b"
    },
    "agent": {
      "type": "metricbeat",
      "version": "8.0.0",
      "ephemeral_id": "b964a246-96c0-456a-a5c2-8c8b1040ecaf",
      "id": "f7ec69f9-4997-4e76-b6c7-0c75206b727a",
      "name": "minikube"
    },
    "metricset": {
      "period": 10000,
      "name": "container"
    },
    "service": {
      "address": "minikube:10250",
      "type": "kubernetes"
    },
    "event": {
      "dataset": "kubernetes.container",
      "module": "kubernetes",
      "duration": 11091346
    },
    "ecs": {
      "version": "1.5.0"
    }
  },
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

The fields reported are:

{{fields "container"}}

### controllermanager

This is the `controllermanager` dataset for the Kubernetes package. It collects from
Kubernetes controller component `metrics` endpoint.

An example event for `controllermanager` looks as following:

```$json
{
  "_index": ".ds-metrics-kubernetes.controllermanager-default-000001",
  "_id": "qFh463IBolOt49UrBPYP",
  "_version": 1,
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:33:29.643Z",
    "kubernetes": {
      "controllermanager": {
        "workqueue": {
          "unfinished": {
            "sec": 0
          },
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
          }
        },
        "name": "certificate"
      }
    },
    "event": {
      "dataset": "kubernetes.controllermanager",
      "module": "kubernetes",
      "duration": 8893806
    },
    "dataset": {
      "namespace": "default",
      "type": "metrics",
      "name": "kubernetes.controllermanager"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "host": {
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
      "hostname": "minikube",
      "architecture": "x86_64",
      "os": {
        "codename": "Core",
        "platform": "centos",
        "version": "7 (Core)",
        "family": "redhat",
        "name": "CentOS Linux",
        "kernel": "4.19.81"
      },
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "containerized": false,
      "name": "minikube"
    },
    "agent": {
      "version": "8.0.0",
      "ephemeral_id": "b964a246-96c0-456a-a5c2-8c8b1040ecaf",
      "id": "f7ec69f9-4997-4e76-b6c7-0c75206b727a",
      "name": "minikube",
      "type": "metricbeat"
    },
    "metricset": {
      "period": 10000,
      "name": "controllermanager"
    },
    "service": {
      "address": "localhost:10252",
      "type": "kubernetes"
    },
    "stream": {
      "namespace": "default",
      "type": "metrics",
      "dataset": "kubernetes.controllermanager"
    }
  },
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

The fields reported are:

{{fields "controllermanager"}}

### event

This is the `event` dataset of the Kubernetes package. It collects Kubernetes events
related metrics.

An example event for `event` looks as following:

```$json
{
  "_index": ".ds-metrics-kubernetes.event-default-000001",
  "_id": "EVh163IBolOt49UrPGji",
  "_version": 1,
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:30:27.575Z",
    "metricset": {
      "name": "event"
    },
    "stream": {
      "dataset": "kubernetes.event",
      "namespace": "default",
      "type": "metrics"
    },
    "agent": {
      "type": "metricbeat",
      "version": "8.0.0",
      "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
      "id": "a6147a6e-6626-4a84-9907-f372f6c61eee",
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "event": {
      "dataset": "kubernetes.event",
      "module": "kubernetes"
    },
    "service": {
      "type": "kubernetes"
    },
    "kubernetes": {
      "event": {
        "metadata": {
          "uid": "604e39e0-862f-4615-9cec-8cb62299dea3",
          "resource_version": "485630",
          "timestamp": {
            "created": "2020-06-25T07:20:25.000Z"
          },
          "name": "monitor.161bb862545e3099",
          "namespace": "beats",
          "self_link": "/api/v1/namespaces/beats/events/monitor.161bb862545e3099",
          "generate_name": ""
        },
        "timestamp": {
          "first_occurrence": "2020-06-25T07:20:25.000Z",
          "last_occurrence": "2020-06-25T12:30:27.000Z"
        },
        "message": "Failed to find referenced backend beats/monitor: Elasticsearch.elasticsearch.k8s.elastic.co \"monitor\" not found",
        "reason": "AssociationError",
        "type": "Warning",
        "count": 1861,
        "source": {
          "host": "",
          "component": "kibana-association-controller"
        },
        "involved_object": {
          "api_version": "kibana.k8s.elastic.co/v1",
          "resource_version": "101842",
          "name": "monitor",
          "kind": "Kibana",
          "uid": "45a19de5-5eef-4090-a2d3-dbceb0a28af8"
        }
      }
    },
    "dataset": {
      "name": "kubernetes.event",
      "namespace": "default",
      "type": "metrics"
    },
    "host": {
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "containerized": false,
      "ip": [
        "172.17.0.11"
      ],
      "mac": [
        "02:42:ac:11:00:0b"
      ],
      "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "architecture": "x86_64",
      "os": {
        "platform": "centos",
        "version": "7 (Core)",
        "family": "redhat",
        "name": "CentOS Linux",
        "kernel": "4.19.81",
        "codename": "Core"
      }
    }
  },
  "fields": {
    "kubernetes.event.timestamp.first_occurrence": [
      "2020-06-25T07:20:25.000Z"
    ],
    "kubernetes.event.timestamp.last_occurrence": [
      "2020-06-25T12:30:27.000Z"
    ],
    "kubernetes.event.metadata.timestamp.created": [
      "2020-06-25T07:20:25.000Z"
    ],
    "@timestamp": [
      "2020-06-25T12:30:27.575Z"
    ]
  },
  "sort": [
    1593088227575
  ]
}
```

The fields reported are:

{{fields "event"}}

### node

This is the `node` dataset of the Kubernetes package. It collects Node related metrics
from Kubelet's monitoring APIs.

An example event for `node` looks as following:

```$json
{
  "_index": ".ds-metrics-kubernetes.node-default-000001",
  "_id": "Gll563IBolOt49UrFS2Q",
  "_version": 1,
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:34:39.723Z",
    "event": {
      "dataset": "kubernetes.node",
      "module": "kubernetes",
      "duration": 13042307
    },
    "service": {
      "type": "kubernetes",
      "address": "minikube:10250"
    },
    "host": {
      "containerized": false,
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
      "hostname": "minikube",
      "architecture": "x86_64",
      "os": {
        "codename": "Core",
        "platform": "centos",
        "version": "7 (Core)",
        "family": "redhat",
        "name": "CentOS Linux",
        "kernel": "4.19.81"
      },
      "id": "b0e83d397c054b8a99a431072fe4617b"
    },
    "metricset": {
      "name": "node",
      "period": 10000
    },
    "kubernetes": {
      "labels": {
        "beta_kubernetes_io/os": "linux",
        "kubernetes_io/arch": "amd64",
        "kubernetes_io/hostname": "minikube",
        "kubernetes_io/os": "linux",
        "node-role_kubernetes_io/master": "",
        "beta_kubernetes_io/arch": "amd64"
      },
      "node": {
        "memory": {
          "available": {
            "bytes": 12746428416
          },
          "usage": {
            "bytes": 5670916096
          },
          "workingset": {
            "bytes": 4068896768
          },
          "rss": {
            "bytes": 3252125696
          },
          "pagefaults": 31680,
          "majorpagefaults": 0
        },
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
        "fs": {
          "available": {
            "bytes": 6655090688
          },
          "capacity": {
            "bytes": 17361141760
          },
          "used": {
            "bytes": 9689358336
          },
          "inodes": {
            "count": 9768928,
            "used": 224151,
            "free": 9544777
          }
        },
        "runtime": {
          "imagefs": {
            "capacity": {
              "bytes": 17361141760
            },
            "used": {
              "bytes": 8719928568
            },
            "available": {
              "bytes": 6655090688
            }
          }
        },
        "start_time": "2020-06-25T07:18:38Z",
        "name": "minikube",
        "cpu": {
          "usage": {
            "core": {
              "ns": 6136184971873
            },
            "nanocores": 455263291
          }
        }
      }
    },
    "dataset": {
      "namespace": "default",
      "type": "metrics",
      "name": "kubernetes.node"
    },
    "stream": {
      "namespace": "default",
      "type": "metrics",
      "dataset": "kubernetes.node"
    },
    "agent": {
      "name": "minikube",
      "type": "metricbeat",
      "version": "8.0.0",
      "ephemeral_id": "b964a246-96c0-456a-a5c2-8c8b1040ecaf",
      "id": "f7ec69f9-4997-4e76-b6c7-0c75206b727a"
    },
    "ecs": {
      "version": "1.5.0"
    }
  },
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

The fields reported are:

{{fields "node"}}

### pod

This is the `pod` dataset of the Kubernetes package. It collects Pod related metrics
from Kubelet's monitoring APIs.

An example event for `pod` looks as following:

```$json
{
  "_index": ".ds-metrics-kubernetes.pod-default-000001",
  "_id": "4Vl563IBolOt49UrYz6x",
  "_version": 1,
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:34:59.729Z",
    "kubernetes": {
      "pod": {
        "memory": {
          "rss": {
            "bytes": 7823360
          },
          "page_faults": 5742,
          "major_page_faults": 0,
          "usage": {
            "limit": {
              "pct": 0.0008033509820466402
            },
            "bytes": 13508608,
            "node": {
              "pct": 0.0008033509820466402
            }
          },
          "available": {
            "bytes": 0
          },
          "working_set": {
            "bytes": 8556544
          }
        },
        "network": {
          "rx": {
            "bytes": 25671624,
            "errors": 0
          },
          "tx": {
            "errors": 0,
            "bytes": 1092900259
          }
        },
        "start_time": "2020-06-18T11:12:58Z",
        "name": "kube-state-metrics-57cd6fdf9-hd959",
        "uid": "a7c61334-dd52-4a12-bed5-4daee4c74139",
        "cpu": {
          "usage": {
            "nanocores": 2811918,
            "node": {
              "pct": 0.0007029795
            },
            "limit": {
              "pct": 0.0007029795
            }
          }
        }
      },
      "namespace": "kube-system",
      "node": {
        "name": "minikube"
      }
    },
    "event": {
      "duration": 20735189,
      "dataset": "kubernetes.pod",
      "module": "kubernetes"
    },
    "stream": {
      "dataset": "kubernetes.pod",
      "namespace": "default",
      "type": "metrics"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "metricset": {
      "period": 10000,
      "name": "pod"
    },
    "service": {
      "type": "kubernetes",
      "address": "minikube:10250"
    },
    "dataset": {
      "type": "metrics",
      "name": "kubernetes.pod",
      "namespace": "default"
    },
    "host": {
      "name": "minikube",
      "hostname": "minikube",
      "architecture": "x86_64",
      "os": {
        "kernel": "4.19.81",
        "codename": "Core",
        "platform": "centos",
        "version": "7 (Core)",
        "family": "redhat",
        "name": "CentOS Linux"
      },
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "containerized": false,
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
      ]
    },
    "agent": {
      "type": "metricbeat",
      "version": "8.0.0",
      "ephemeral_id": "b964a246-96c0-456a-a5c2-8c8b1040ecaf",
      "id": "f7ec69f9-4997-4e76-b6c7-0c75206b727a",
      "name": "minikube"
    }
  },
  "fields": {
    "kubernetes.pod.start_time": [
      "2020-06-18T11:12:58.000Z"
    ],
    "@timestamp": [
      "2020-06-25T12:34:59.729Z"
    ]
  },
  "sort": [
    1593088499729
  ]
}
```

The fields reported are:

{{fields "pod"}}

### proxy

This is the `proxy` dataset of the Kubernetes package. It collects metrics
from Kubernetes Proxy component.

An example event for `proxy` looks as following:

```$json
{
  "_index": ".ds-metrics-kubernetes.proxy-default-000001",
  "_id": "Z1l563IBolOt49Ur2FXO",
  "_version": 1,
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:35:29.639Z",
    "agent": {
      "name": "minikube",
      "type": "metricbeat",
      "version": "8.0.0",
      "ephemeral_id": "b964a246-96c0-456a-a5c2-8c8b1040ecaf",
      "id": "f7ec69f9-4997-4e76-b6c7-0c75206b727a"
    },
    "dataset": {
      "namespace": "default",
      "type": "metrics",
      "name": "kubernetes.proxy"
    },
    "stream": {
      "type": "metrics",
      "dataset": "kubernetes.proxy",
      "namespace": "default"
    },
    "host": {
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
      "name": "minikube",
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
      "hostname": "minikube",
      "architecture": "x86_64",
      "os": {
        "codename": "Core",
        "platform": "centos",
        "version": "7 (Core)",
        "family": "redhat",
        "name": "CentOS Linux",
        "kernel": "4.19.81"
      },
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "containerized": false
    },
    "kubernetes": {
      "proxy": {
        "sync": {
          "rules": {
            "duration": {
              "us": {
                "sum": 763620.9329999998,
                "count": 18,
                "bucket": {
                  "1000": 0,
                  "2000": 0,
                  "4000": 0,
                  "8000": 0,
                  "16000": 0,
                  "32000": 10,
                  "64000": 16,
                  "128000": 17,
                  "256000": 18,
                  "512000": 18,
                  "1024000": 18,
                  "2048000": 18,
                  "4096000": 18,
                  "8192000": 18,
                  "16384000": 18,
                  "+Inf": 18
                }
              }
            }
          },
          "networkprogramming": {
            "duration": {
              "us": {
                "count": 19,
                "bucket": {
                  "0": 0,
                  "250000": 4,
                  "500000": 8,
                  "1000000": 11,
                  "2000000": 11,
                  "3000000": 11,
                  "4000000": 11,
                  "5000000": 11,
                  "6000000": 11,
                  "7000000": 11,
                  "8000000": 11,
                  "9000000": 11,
                  "10000000": 11,
                  "11000000": 11,
                  "12000000": 11,
                  "13000000": 11,
                  "14000000": 11,
                  "15000000": 11,
                  "16000000": 11,
                  "17000000": 11,
                  "18000000": 11,
                  "19000000": 11,
                  "20000000": 11,
                  "21000000": 11,
                  "22000000": 11,
                  "23000000": 11,
                  "24000000": 11,
                  "25000000": 11,
                  "26000000": 11,
                  "27000000": 11,
                  "28000000": 11,
                  "29000000": 11,
                  "30000000": 11,
                  "31000000": 11,
                  "32000000": 11,
                  "33000000": 11,
                  "34000000": 11,
                  "35000000": 11,
                  "36000000": 11,
                  "37000000": 11,
                  "38000000": 11,
                  "39000000": 11,
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
                  "60000000": 11,
                  "65000000": 11,
                  "70000000": 11,
                  "75000000": 11,
                  "80000000": 11,
                  "85000000": 11,
                  "90000000": 11,
                  "95000000": 11,
                  "100000000": 11,
                  "105000000": 11,
                  "110000000": 11,
                  "115000000": 11,
                  "120000000": 11,
                  "150000000": 11,
                  "180000000": 11,
                  "210000000": 11,
                  "240000000": 11,
                  "270000000": 11,
                  "300000000": 11,
                  "+Inf": 19
                },
                "sum": 5571080914163.27
              }
            }
          }
        },
        "process": {
          "cpu": {
            "sec": 8
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
          },
          "fds": {
            "open": {
              "count": 17
            }
          }
        }
      }
    },
    "ecs": {
      "version": "1.5.0"
    },
    "event": {
      "module": "kubernetes",
      "duration": 2031254,
      "dataset": "kubernetes.proxy"
    },
    "metricset": {
      "name": "proxy",
      "period": 10000
    },
    "service": {
      "address": "localhost:10249",
      "type": "kubernetes"
    }
  },
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

The fields reported are:

{{fields "proxy"}}

### scheduler

This is the `scheduler` dataset of the Kubernetes package. It collects metrics
from Kubernetes Scheduler component.

An example event for `scheduler` looks as following:

```$json
{
  "_index": ".ds-metrics-kubernetes.scheduler-default-000001",
  "_id": "01l663IBolOt49UrTW36",
  "_version": 1,
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:35:59.624Z",
    "agent": {
      "version": "8.0.0",
      "ephemeral_id": "b964a246-96c0-456a-a5c2-8c8b1040ecaf",
      "id": "f7ec69f9-4997-4e76-b6c7-0c75206b727a",
      "name": "minikube",
      "type": "metricbeat"
    },
    "dataset": {
      "name": "kubernetes.scheduler",
      "namespace": "default",
      "type": "metrics"
    },
    "stream": {
      "namespace": "default",
      "type": "metrics",
      "dataset": "kubernetes.scheduler"
    },
    "host": {
      "hostname": "minikube",
      "architecture": "x86_64",
      "os": {
        "kernel": "4.19.81",
        "codename": "Core",
        "platform": "centos",
        "version": "7 (Core)",
        "family": "redhat",
        "name": "CentOS Linux"
      },
      "name": "minikube",
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "containerized": false,
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
      ]
    },
    "ecs": {
      "version": "1.5.0"
    },
    "event": {
      "duration": 7245648,
      "dataset": "kubernetes.scheduler",
      "module": "kubernetes"
    },
    "metricset": {
      "name": "scheduler",
      "period": 10000
    },
    "service": {
      "address": "localhost:10251",
      "type": "kubernetes"
    },
    "kubernetes": {
      "scheduler": {
        "name": "kube-scheduler",
        "leader": {
          "is_master": true
        }
      }
    }
  },
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

The fields reported are:

{{fields "scheduler"}}

### state_container

This is the `state_container` dataset of the Kubernetes package. It collects container related
metrics from `kube_state_metrics`.

An example event for `state_container` looks as following:

```$json
{
  "_index": ".ds-metrics-kubernetes.state_container-default-000001",
  "_id": "P1l663IBolOt49Ur1YbF",
  "_version": 1,
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:36:34.469Z",
    "host": {
      "ip": [
        "172.17.0.11"
      ],
      "mac": [
        "02:42:ac:11:00:0b"
      ],
      "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "architecture": "x86_64",
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "os": {
        "family": "redhat",
        "name": "CentOS Linux",
        "kernel": "4.19.81",
        "codename": "Core",
        "platform": "centos",
        "version": "7 (Core)"
      },
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "containerized": false
    },
    "event": {
      "dataset": "kubernetes.container",
      "module": "kubernetes",
      "duration": 8554499
    },
    "kubernetes": {
      "node": {
        "name": "minikube"
      },
      "labels": {
        "component": "kube-scheduler",
        "tier": "control-plane"
      },
      "container": {
        "image": "k8s.gcr.io/kube-scheduler:v1.17.0",
        "name": "kube-scheduler",
        "cpu": {
          "request": {
            "cores": 0.1
          }
        },
        "status": {
          "phase": "running",
          "ready": true,
          "restarts": 10
        },
        "id": "docker://b00b185f2b304a7ece804d1af28eb232f825255f716bcc85ef5bd20d5a4f45d4"
      },
      "pod": {
        "name": "kube-scheduler-minikube",
        "uid": "9cdbd5ea-7638-4e86-a706-a5b222d86f26"
      },
      "namespace": "kube-system"
    },
    "dataset": {
      "name": "kubernetes.state_container",
      "namespace": "default",
      "type": "metrics"
    },
    "stream": {
      "type": "metrics",
      "dataset": "kubernetes.state_container",
      "namespace": "default"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "agent": {
      "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
      "id": "a6147a6e-6626-4a84-9907-f372f6c61eee",
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "type": "metricbeat",
      "version": "8.0.0"
    },
    "container": {
      "runtime": "docker",
      "id": "b00b185f2b304a7ece804d1af28eb232f825255f716bcc85ef5bd20d5a4f45d4"
    },
    "service": {
      "address": "kube-state-metrics:8080",
      "type": "kubernetes"
    },
    "metricset": {
      "name": "state_container",
      "period": 10000
    }
  },
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

The fields reported are:

{{fields "state_container"}}

### state_cronjob

This is the `state_cronjob` dataset of the Kubernetes package. It collects cronjob related
metrics from `kube_state_metrics`.

An example event for `state_cronjob` looks as following:

```$json
{
  "_index": ".ds-metrics-kubernetes.state_cronjob-default-000001",
  "_id": "qFqA63IBolOt49Urybs0",
  "_version": 1,
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:43:04.384Z",
    "metricset": {
      "name": "state_cronjob",
      "period": 10000
    },
    "service": {
      "address": "kube-state-metrics:8080",
      "type": "kubernetes"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "host": {
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "containerized": false,
      "ip": [
        "172.17.0.11"
      ],
      "mac": [
        "02:42:ac:11:00:0b"
      ],
      "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "architecture": "x86_64",
      "os": {
        "family": "redhat",
        "name": "CentOS Linux",
        "kernel": "4.19.81",
        "codename": "Core",
        "platform": "centos",
        "version": "7 (Core)"
      }
    },
    "event": {
      "dataset": "kubernetes.cronjob",
      "module": "kubernetes",
      "duration": 9482053
    },
    "kubernetes": {
      "namespace": "default",
      "cronjob": {
        "active": {
          "count": 0
        },
        "is_suspended": false,
        "name": "hello",
        "next_schedule": {
          "sec": 1593088980
        },
        "last_schedule": {
          "sec": 1593088920
        },
        "created": {
          "sec": 1593088862
        }
      }
    },
    "dataset": {
      "type": "metrics",
      "name": "kubernetes.state_cronjob",
      "namespace": "default"
    },
    "stream": {
      "namespace": "default",
      "type": "metrics",
      "dataset": "kubernetes.state_cronjob"
    },
    "agent": {
      "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
      "id": "a6147a6e-6626-4a84-9907-f372f6c61eee",
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "type": "metricbeat",
      "version": "8.0.0"
    }
  },
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

The fields reported are:

{{fields "state_cronjob"}}

### state_deployment

This is the `state_deployment` dataset of the Kubernetes package. It collects deployment related
metrics from `kube_state_metrics`.

An example event for `state_deployment` looks as following:

```$json
{
  "_index": ".ds-metrics-kubernetes.state_deployment-default-000001",
  "_id": "H1l763IBolOt49UrSp72",
  "_version": 1,
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:37:04.455Z",
    "service": {
      "address": "kube-state-metrics:8080",
      "type": "kubernetes"
    },
    "event": {
      "module": "kubernetes",
      "duration": 8648138,
      "dataset": "kubernetes.deployment"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "metricset": {
      "name": "state_deployment",
      "period": 10000
    },
    "kubernetes": {
      "deployment": {
        "name": "metricbeat",
        "replicas": {
          "unavailable": 0,
          "desired": 1,
          "updated": 1,
          "available": 1
        },
        "paused": false
      },
      "labels": {
        "k8s-app": "metricbeat"
      },
      "namespace": "kube-system"
    },
    "dataset": {
      "type": "metrics",
      "name": "kubernetes.state_deployment",
      "namespace": "default"
    },
    "stream": {
      "type": "metrics",
      "dataset": "kubernetes.state_deployment",
      "namespace": "default"
    },
    "host": {
      "mac": [
        "02:42:ac:11:00:0b"
      ],
      "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "architecture": "x86_64",
      "os": {
        "name": "CentOS Linux",
        "kernel": "4.19.81",
        "codename": "Core",
        "platform": "centos",
        "version": "7 (Core)",
        "family": "redhat"
      },
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "containerized": false,
      "ip": [
        "172.17.0.11"
      ]
    },
    "agent": {
      "version": "8.0.0",
      "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
      "id": "a6147a6e-6626-4a84-9907-f372f6c61eee",
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "type": "metricbeat"
    }
  },
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

The fields reported are:

{{fields "state_deployment"}}

### state_node

This is the `state_node` dataset of the Kubernetes package. It collects node related
metrics from `kube_state_metrics`.

An example event for `state_node` looks as following:

```$json
{
  "_index": ".ds-metrics-kubernetes.state_node-default-000001",
  "_id": "c1l763IBolOt49Ur58c8",
  "_version": 1,
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:37:44.457Z",
    "ecs": {
      "version": "1.5.0"
    },
    "host": {
      "mac": [
        "02:42:ac:11:00:0b"
      ],
      "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "architecture": "x86_64",
      "os": {
        "kernel": "4.19.81",
        "codename": "Core",
        "platform": "centos",
        "version": "7 (Core)",
        "family": "redhat",
        "name": "CentOS Linux"
      },
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "containerized": false,
      "ip": [
        "172.17.0.11"
      ]
    },
    "dataset": {
      "namespace": "default",
      "type": "metrics",
      "name": "kubernetes.state_node"
    },
    "stream": {
      "namespace": "default",
      "type": "metrics",
      "dataset": "kubernetes.state_node"
    },
    "metricset": {
      "name": "state_node",
      "period": 10000
    },
    "kubernetes": {
      "node": {
        "pod": {
          "capacity": {
            "total": 110
          },
          "allocatable": {
            "total": 110
          }
        },
        "memory": {
          "capacity": {
            "bytes": 16815325184
          },
          "allocatable": {
            "bytes": 16815325184
          }
        },
        "cpu": {
          "allocatable": {
            "cores": 4
          },
          "capacity": {
            "cores": 4
          }
        },
        "name": "minikube",
        "status": {
          "ready": "true",
          "unschedulable": false
        }
      },
      "labels": {
        "kubernetes_io/arch": "amd64",
        "kubernetes_io/hostname": "minikube",
        "kubernetes_io/os": "linux",
        "node-role_kubernetes_io/master": "",
        "beta_kubernetes_io/arch": "amd64",
        "beta_kubernetes_io/os": "linux"
      }
    },
    "agent": {
      "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
      "id": "a6147a6e-6626-4a84-9907-f372f6c61eee",
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "type": "metricbeat",
      "version": "8.0.0"
    },
    "service": {
      "type": "kubernetes",
      "address": "kube-state-metrics:8080"
    },
    "event": {
      "dataset": "kubernetes.node",
      "module": "kubernetes",
      "duration": 8194220
    }
  },
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

The fields reported are:

{{fields "state_node"}}

### state_persistentvolume

This is the `state_persistentvolume` dataset of the Kubernetes package. It collects 
PersistentVolume related metrics from `kube_state_metrics`.

An example event for `state_persistentvolume` looks as following:

```$json
{
  "_index": ".ds-metrics-kubernetes.state_persistentvolume-default-000001",
  "_id": "8lqB63IBolOt49UrjOyD",
  "_version": 1,
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:43:54.412Z",
    "ecs": {
      "version": "1.5.0"
    },
    "event": {
      "module": "kubernetes",
      "duration": 12149615,
      "dataset": "kubernetes.persistentvolume"
    },
    "agent": {
      "version": "8.0.0",
      "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
      "id": "a6147a6e-6626-4a84-9907-f372f6c61eee",
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "type": "metricbeat"
    },
    "kubernetes": {
      "persistentvolume": {
        "capacity": {
          "bytes": 10737418240
        },
        "phase": "Bound",
        "storage_class": "manual",
        "name": "task-pv-volume"
      },
      "labels": {
        "type": "local"
      }
    },
    "dataset": {
      "name": "kubernetes.state_persistentvolume",
      "namespace": "default",
      "type": "metrics"
    },
    "stream": {
      "type": "metrics",
      "dataset": "kubernetes.state_persistentvolume",
      "namespace": "default"
    },
    "host": {
      "ip": [
        "172.17.0.11"
      ],
      "mac": [
        "02:42:ac:11:00:0b"
      ],
      "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "architecture": "x86_64",
      "os": {
        "codename": "Core",
        "platform": "centos",
        "version": "7 (Core)",
        "family": "redhat",
        "name": "CentOS Linux",
        "kernel": "4.19.81"
      },
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "containerized": false
    },
    "metricset": {
      "period": 10000,
      "name": "state_persistentvolume"
    },
    "service": {
      "address": "kube-state-metrics:8080",
      "type": "kubernetes"
    }
  },
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

The fields reported are:

{{fields "state_persistentvolume"}}

### state_persistentvolumeclaim

This is the `state_persistentvolumeclaim` dataset of the Kubernetes package. It collects 
PersistentVolumeClaim related metrics from `kube_state_metrics`.

An example event for `state_persistentvolumeclaim` looks as following:

```$json
{
  "_index": ".ds-metrics-kubernetes.state_persistentvolumeclaim-default-000001",
  "_id": "6FuC63IBolOt49UrTxrR",
  "_version": 1,
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:44:44.418Z",
    "event": {
      "dataset": "kubernetes.persistentvolumeclaim",
      "module": "kubernetes",
      "duration": 5698588
    },
    "metricset": {
      "name": "state_persistentvolumeclaim",
      "period": 10000
    },
    "service": {
      "address": "kube-state-metrics:8080",
      "type": "kubernetes"
    },
    "kubernetes": {
      "namespace": "default",
      "persistentvolumeclaim": {
        "phase": "Bound",
        "storage_class": "manual",
        "volume_name": "task-pv-volume",
        "name": "task-pv-claim",
        "request_storage": {
          "bytes": 3221225472
        },
        "access_mode": "ReadWriteOnce"
      }
    },
    "dataset": {
      "namespace": "default",
      "type": "metrics",
      "name": "kubernetes.state_persistentvolumeclaim"
    },
    "agent": {
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "type": "metricbeat",
      "version": "8.0.0",
      "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
      "id": "a6147a6e-6626-4a84-9907-f372f6c61eee"
    },
    "stream": {
      "type": "metrics",
      "dataset": "kubernetes.state_persistentvolumeclaim",
      "namespace": "default"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "host": {
      "os": {
        "platform": "centos",
        "version": "7 (Core)",
        "family": "redhat",
        "name": "CentOS Linux",
        "kernel": "4.19.81",
        "codename": "Core"
      },
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "containerized": false,
      "ip": [
        "172.17.0.11"
      ],
      "mac": [
        "02:42:ac:11:00:0b"
      ],
      "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "architecture": "x86_64"
    }
  },
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

The fields reported are:

{{fields "state_persistentvolumeclaim"}}

### state_pod

This is the `state_pod` dataset of the Kubernetes package. It collects 
Pod related metrics from `kube_state_metrics`.

An example event for `state_pod` looks as following:

```$json
{
  "_index": ".ds-metrics-kubernetes.state_pod-default-000001",
  "_id": "YVl863IBolOt49UrqueH",
  "_version": 1,
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:38:34.469Z",
    "dataset": {
      "name": "kubernetes.state_pod",
      "namespace": "default",
      "type": "metrics"
    },
    "stream": {
      "namespace": "default",
      "type": "metrics",
      "dataset": "kubernetes.state_pod"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "host": {
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "containerized": false,
      "ip": [
        "172.17.0.11"
      ],
      "mac": [
        "02:42:ac:11:00:0b"
      ],
      "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "architecture": "x86_64",
      "os": {
        "kernel": "4.19.81",
        "codename": "Core",
        "platform": "centos",
        "version": "7 (Core)",
        "family": "redhat",
        "name": "CentOS Linux"
      }
    },
    "event": {
      "duration": 10777415,
      "dataset": "kubernetes.pod",
      "module": "kubernetes"
    },
    "service": {
      "type": "kubernetes",
      "address": "kube-state-metrics:8080"
    },
    "kubernetes": {
      "pod": {
        "name": "filebeat-dqzzz",
        "status": {
          "ready": "true",
          "scheduled": "true",
          "phase": "running"
        },
        "host_ip": "192.168.64.10",
        "ip": "192.168.64.10",
        "uid": "a5f1d3c9-40b6-4182-823b-dd5ff9832279"
      },
      "namespace": "kube-system",
      "node": {
        "name": "minikube"
      },
      "labels": {
        "controller-revision-hash": "85649b9ddb",
        "k8s-app": "filebeat",
        "pod-template-generation": "1"
      }
    },
    "agent": {
      "id": "a6147a6e-6626-4a84-9907-f372f6c61eee",
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "type": "metricbeat",
      "version": "8.0.0",
      "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487"
    },
    "metricset": {
      "period": 10000,
      "name": "state_pod"
    }
  },
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

The fields reported are:

{{fields "state_pod"}}

### state_replicaset

This is the `state_replicaset` dataset of the Kubernetes package. It collects 
Replicaset related metrics from `kube_state_metrics`.

An example event for `state_replicaset` looks as following:

```$json
{
  "_index": ".ds-metrics-kubernetes.state_replicaset-default-000001",
  "_id": "U1l863IBolOt49Ur-Pu2",
  "_version": 1,
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:38:54.482Z",
    "service": {
      "address": "kube-state-metrics:8080",
      "type": "kubernetes"
    },
    "metricset": {
      "period": 10000,
      "name": "state_replicaset"
    },
    "dataset": {
      "namespace": "default",
      "type": "metrics",
      "name": "kubernetes.state_replicaset"
    },
    "stream": {
      "type": "metrics",
      "dataset": "kubernetes.state_replicaset",
      "namespace": "default"
    },
    "event": {
      "module": "kubernetes",
      "duration": 5456128,
      "dataset": "kubernetes.replicaset"
    },
    "kubernetes": {
      "namespace": "kube-system",
      "replicaset": {
        "name": "nginx-ingress-controller-6fc5bcc8c9",
        "replicas": {
          "labeled": 1,
          "ready": 1,
          "available": 1,
          "observed": 1,
          "desired": 1
        }
      },
      "deployment": {
        "name": "nginx-ingress-controller"
      },
      "labels": {
        "app_kubernetes_io/part-of": "kube-system",
        "pod-template-hash": "6fc5bcc8c9",
        "addonmanager_kubernetes_io/mode": "Reconcile",
        "app_kubernetes_io/name": "nginx-ingress-controller"
      }
    },
    "agent": {
      "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
      "id": "a6147a6e-6626-4a84-9907-f372f6c61eee",
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "type": "metricbeat",
      "version": "8.0.0"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "host": {
      "containerized": false,
      "ip": [
        "172.17.0.11"
      ],
      "mac": [
        "02:42:ac:11:00:0b"
      ],
      "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "architecture": "x86_64",
      "os": {
        "platform": "centos",
        "version": "7 (Core)",
        "family": "redhat",
        "name": "CentOS Linux",
        "kernel": "4.19.81",
        "codename": "Core"
      },
      "id": "b0e83d397c054b8a99a431072fe4617b"
    }
  },
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

The fields reported are:

{{fields "state_replicaset"}}

### state_resourcequota

This is the `state_resourcequota` dataset of the Kubernetes package. It collects 
ResourceQuota related metrics from `kube_state_metrics`.

An example event for `state_resourcequota` looks as following:

```$json
{
  "_index": ".ds-metrics-kubernetes.state_resourcequota-default-000001",
  "_id": "4FuC63IBolOt49UrnSHz",
  "_version": 1,
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:45:04.416Z",
    "metricset": {
      "name": "state_resourcequota",
      "period": 10000
    },
    "dataset": {
      "type": "metrics",
      "name": "kubernetes.state_resourcequota",
      "namespace": "default"
    },
    "host": {
      "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "architecture": "x86_64",
      "os": {
        "codename": "Core",
        "platform": "centos",
        "version": "7 (Core)",
        "family": "redhat",
        "name": "CentOS Linux",
        "kernel": "4.19.81"
      },
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "containerized": false,
      "ip": [
        "172.17.0.11"
      ],
      "mac": [
        "02:42:ac:11:00:0b"
      ]
    },
    "service": {
      "address": "kube-state-metrics:8080",
      "type": "kubernetes"
    },
    "event": {
      "dataset": "kubernetes.resourcequota",
      "module": "kubernetes",
      "duration": 6324269
    },
    "agent": {
      "id": "a6147a6e-6626-4a84-9907-f372f6c61eee",
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "type": "metricbeat",
      "version": "8.0.0",
      "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "kubernetes": {
      "namespace": "quota-object-example",
      "resourcequota": {
        "name": "object-quota-demo",
        "resource": "persistentvolumeclaims",
        "type": "hard",
        "quota": 1
      }
    },
    "stream": {
      "type": "metrics",
      "dataset": "kubernetes.state_resourcequota",
      "namespace": "default"
    }
  },
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

The fields reported are:

{{fields "state_resourcequota"}}

### state_service

This is the `state_service` dataset of the Kubernetes package. It collects 
Service related metrics from `kube_state_metrics`.

An example event for `state_service` looks as following:

```$json
{
  "_index": ".ds-metrics-kubernetes.state_service-default-000001",
  "_id": "Elp963IBolOt49UrbRPd",
  "_version": 1,
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:39:24.389Z",
    "kubernetes": {
      "labels": {
        "kubernetes_io_minikube_addons_endpoint": "metrics-server",
        "kubernetes_io_name": "Metrics-server",
        "addonmanager_kubernetes_io_mode": "Reconcile",
        "kubernetes_io_minikube_addons": "metrics-server"
      },
      "service": {
        "name": "metrics-server",
        "created": "2020-06-10T09:02:27.000Z",
        "cluster_ip": "10.96.124.248",
        "type": "ClusterIP"
      },
      "namespace": "kube-system"
    },
    "event": {
      "dataset": "kubernetes.service",
      "module": "kubernetes",
      "duration": 10966648
    },
    "metricset": {
      "name": "state_service",
      "period": 10000
    },
    "host": {
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "containerized": false,
      "ip": [
        "172.17.0.11"
      ],
      "mac": [
        "02:42:ac:11:00:0b"
      ],
      "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "architecture": "x86_64",
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "os": {
        "platform": "centos",
        "version": "7 (Core)",
        "family": "redhat",
        "name": "CentOS Linux",
        "kernel": "4.19.81",
        "codename": "Core"
      }
    },
    "agent": {
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "type": "metricbeat",
      "version": "8.0.0",
      "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
      "id": "a6147a6e-6626-4a84-9907-f372f6c61eee"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "service": {
      "address": "kube-state-metrics:8080",
      "type": "kubernetes"
    },
    "dataset": {
      "name": "kubernetes.state_service",
      "namespace": "default",
      "type": "metrics"
    },
    "stream": {
      "dataset": "kubernetes.state_service",
      "namespace": "default",
      "type": "metrics"
    }
  },
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

The fields reported are:

{{fields "state_service"}}

### state_storageclass

This is the `state_storageclass` dataset of the Kubernetes package. It collects 
StorageClass related metrics from `kube_state_metrics`.

An example event for `state_storageclass` looks as following:

```$json
{
  "_index": ".ds-metrics-kubernetes.state_storageclass-default-000001",
  "_id": "KFp963IBolOt49UruyX3",
  "_version": 1,
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:39:44.399Z",
    "agent": {
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "type": "metricbeat",
      "version": "8.0.0",
      "ephemeral_id": "644323b5-5d6a-4dfb-92dd-35ca602db487",
      "id": "a6147a6e-6626-4a84-9907-f372f6c61eee"
    },
    "kubernetes": {
      "storageclass": {
        "provisioner": "k8s.io/minikube-hostpath",
        "reclaim_policy": "Delete",
        "volume_binding_mode": "Immediate",
        "name": "standard",
        "created": "2020-06-10T09:02:27.000Z"
      },
      "labels": {
        "addonmanager_kubernetes_io_mode": "EnsureExists"
      }
    },
    "dataset": {
      "name": "kubernetes.state_storageclass",
      "namespace": "default",
      "type": "metrics"
    },
    "stream": {
      "dataset": "kubernetes.state_storageclass",
      "namespace": "default",
      "type": "metrics"
    },
    "host": {
      "hostname": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "architecture": "x86_64",
      "os": {
        "platform": "centos",
        "version": "7 (Core)",
        "family": "redhat",
        "name": "CentOS Linux",
        "kernel": "4.19.81",
        "codename": "Core"
      },
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "name": "agent-ingest-management-clusterscope-674dbb75df-rp8cc",
      "containerized": false,
      "ip": [
        "172.17.0.11"
      ],
      "mac": [
        "02:42:ac:11:00:0b"
      ]
    },
    "event": {
      "module": "kubernetes",
      "duration": 5713503,
      "dataset": "kubernetes.storageclass"
    },
    "metricset": {
      "name": "state_storageclass",
      "period": 10000
    },
    "service": {
      "address": "kube-state-metrics:8080",
      "type": "kubernetes"
    },
    "ecs": {
      "version": "1.5.0"
    }
  },
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

The fields reported are:

{{fields "state_storageclass"}}

### system

This is the `system` dataset of the Kubernetes package. It collects System related metrics
from Kubelet's monitoring APIs.

An example event for `system` looks as following:

```$json
{
  "_index": ".ds-metrics-kubernetes.system-default-000001",
  "_id": "sVp963IBolOt49Ur9yyT",
  "_version": 1,
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:39:59.647Z",
    "dataset": {
      "namespace": "default",
      "type": "metrics",
      "name": "kubernetes.system"
    },
    "service": {
      "address": "minikube:10250",
      "type": "kubernetes"
    },
    "event": {
      "duration": 20012905,
      "dataset": "kubernetes.system",
      "module": "kubernetes"
    },
    "stream": {
      "dataset": "kubernetes.system",
      "namespace": "default",
      "type": "metrics"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "host": {
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
      "hostname": "minikube",
      "name": "minikube",
      "architecture": "x86_64",
      "os": {
        "version": "7 (Core)",
        "family": "redhat",
        "name": "CentOS Linux",
        "kernel": "4.19.81",
        "codename": "Core",
        "platform": "centos"
      },
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "containerized": false,
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
      ]
    },
    "agent": {
      "ephemeral_id": "b964a246-96c0-456a-a5c2-8c8b1040ecaf",
      "id": "f7ec69f9-4997-4e76-b6c7-0c75206b727a",
      "name": "minikube",
      "type": "metricbeat",
      "version": "8.0.0"
    },
    "kubernetes": {
      "node": {
        "name": "minikube"
      },
      "system": {
        "container": "runtime",
        "cpu": {
          "usage": {
            "nanocores": 35779815,
            "core": {
              "ns": 530899961233
            }
          }
        },
        "memory": {
          "pagefaults": 12944019,
          "majorpagefaults": 99,
          "usage": {
            "bytes": 198279168
          },
          "workingset": {
            "bytes": 178794496
          },
          "rss": {
            "bytes": 125259776
          }
        },
        "start_time": "2020-06-25T07:19:32Z"
      }
    },
    "metricset": {
      "name": "system",
      "period": 10000
    }
  },
  "fields": {
    "kubernetes.system.start_time": [
      "2020-06-25T07:19:32.000Z"
    ],
    "@timestamp": [
      "2020-06-25T12:39:59.647Z"
    ]
  },
  "sort": [
    1593088799647
  ]
}
```

The fields reported are:

{{fields "system"}}

### volume

This is the `volume` dataset of the Kubernetes package. It collects Volume related metrics
from Kubelet's monitoring APIs.

An example event for `volume` looks as following:

```$json
{
  "_index": ".ds-metrics-kubernetes.volume-default-000001",
  "_id": "b1p-63IBolOt49UrRT-d",
  "_version": 1,
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-25T12:40:19.649Z",
    "ecs": {
      "version": "1.5.0"
    },
    "metricset": {
      "name": "volume",
      "period": 10000
    },
    "service": {
      "type": "kubernetes",
      "address": "minikube:10250"
    },
    "kubernetes": {
      "pod": {
        "name": "metricbeat-g9fc6"
      },
      "volume": {
        "name": "config",
        "fs": {
          "inodes": {
            "used": 5,
            "free": 9549949,
            "count": 9768928
          },
          "available": {
            "bytes": 7719858176
          },
          "capacity": {
            "bytes": 17361141760
          },
          "used": {
            "bytes": 12288
          }
        }
      },
      "namespace": "kube-system",
      "node": {
        "name": "minikube"
      }
    },
    "dataset": {
      "type": "metrics",
      "name": "kubernetes.volume",
      "namespace": "default"
    },
    "stream": {
      "namespace": "default",
      "type": "metrics",
      "dataset": "kubernetes.volume"
    },
    "host": {
      "architecture": "x86_64",
      "os": {
        "platform": "centos",
        "version": "7 (Core)",
        "family": "redhat",
        "name": "CentOS Linux",
        "kernel": "4.19.81",
        "codename": "Core"
      },
      "id": "b0e83d397c054b8a99a431072fe4617b",
      "containerized": false,
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
      "name": "minikube",
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
      "hostname": "minikube"
    },
    "agent": {
      "type": "metricbeat",
      "version": "8.0.0",
      "ephemeral_id": "b964a246-96c0-456a-a5c2-8c8b1040ecaf",
      "id": "f7ec69f9-4997-4e76-b6c7-0c75206b727a",
      "name": "minikube"
    },
    "event": {
      "dataset": "kubernetes.volume",
      "module": "kubernetes",
      "duration": 12481688
    }
  },
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

The fields reported are:

{{fields "volume"}}