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

{{fields "apiserver"}}

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

{{fields "container"}}

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

{{fields "controllermanager"}}

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

{{fields "event"}}

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

{{fields "node"}}

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

{{fields "pod"}}

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

{{fields "proxy"}}

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

{{fields "scheduler"}}

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

{{fields "state_container"}}

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

{{fields "state_cronjob"}}

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

{{fields "state_deployment"}}

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

{{fields "state_node"}}

### state_persistentvolume

This is the `state_persistentvolume` dataset of the Kubernetes package. It collects 
PersistentVolume related metrics from `kube_state_metrics`.


The fields reported are:

{{fields "state_persistentvolume"}}

### state_persistentvolumeclaim

This is the `state_persistentvolumeclaim` dataset of the Kubernetes package. It collects 
PersistentVolumeClaim related metrics from `kube_state_metrics`.


The fields reported are:

{{fields "state_persistentvolumeclaim"}}

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

{{fields "state_pod"}}

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

{{fields "state_replicaset"}}

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

{{fields "state_resourcequota"}}

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

{{fields "state_service"}}

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

{{fields "state_storageclass"}}

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

{{fields "system"}}

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

{{fields "volume"}}