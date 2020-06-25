# RabbitMQ Integration

This integration uses [http://www.rabbitmq.com/management.html](HTTP API) created by the management plugin to collect metrics.

The default data streams are `connection`, `node`, `queue`, `exchange` and standard logs.

If `management.path_prefix` is set in RabbitMQ configuration, management_path_prefix has to be set to the same value
in this integration configuration.

## Compatibility

The RabbitMQ integration is fully tested with RabbitMQ 3.7.4 and it should be compatible with any version supporting
the management plugin (which needs to be installed and enabled). Exchange dataset is also tested with 3.6.0, 3.6.5 and 3.7.14.

The application logs dataset parses single file format introduced in 3.7.0.

## Logs

### Application Logs

Application logs collects standard RabbitMQ logs.

{{fields "log"}}

## Metrics

### Connection Metrics

An example event for connection looks as following:

```$json
{
   "@timestamp":"2020-06-25T10:16:10.138Z",
   "dataset":{
      "name":"rabbitmq.connection",
      "namespace":"default",
      "type":"metrics"
   },
   "rabbitmq":{
      "vhost":"/",
      "connection":{
         "channel_max":65535,
         "channels":2,
         "client_provided":{
            "name":"Connection1"
         },
         "frame_max":131072,
         "host":"::1",
         "name":"[::1]:31153 -\u003e [::1]:5672",
         "octet_count":{
            "received":5834,
            "sent":5834
         },
         "packet_count":{
            "pending":0,
            "received":442,
            "sent":422
         },
         "peer":{
            "host":"::1",
            "port":31153
         },
         "port":5672,
         "state":"running",
         "type":"network"
      }
   },
   "event":{
      "duration":374411,
      "dataset":"rabbitmq.connection",
      "module":"rabbitmq"
   },
   "stream":{
      "dataset":"rabbitmq.connection",
      "namespace":"default",
      "type":"metrics"
   },
   "metricset":{
      "name":"connection",
      "period":10000
   },
   "service":{
      "address":"localhost:15672",
      "type":"rabbitmq"
   },
   "ecs":{
      "version":"1.5.0"
   }
}
```

{{fields "connection"}}

### Exchange Metrics

An example event for exchange looks as following:

```$json
{
   "@timestamp":"2020-06-25T10:04:20.944Z",
   "dataset":{
      "name":"rabbitmq.exchange",
      "namespace":"default",
      "type":"metrics"
   },
   "rabbitmq":{
      "vhost":"/",
      "exchange":{
         "arguments":{

         },
         "type":"direct",
         "durable":true,
         "auto_delete":false,
         "name":"",
         "internal":false
      }
   },
   "event":{
      "duration":4078507,
      "dataset":"rabbitmq.exchange",
      "module":"rabbitmq"
   },
   "stream":{
      "dataset":"rabbitmq.exchange",
      "namespace":"default",
      "type":"metrics"
   },
   "metricset":{
      "name":"exchange",
      "period":10000
   },
   "user":{
      "name":"rmq-internal"
   },
   "service":{
      "address":"localhost:15672",
      "type":"rabbitmq"
   },
   "ecs":{
      "version":"1.5.0"
   }
}
```

{{fields "exchange"}}

### Node Metrics

The "node" dataset collects metrics about RabbitMQ nodes.

It supports two modes to collect data which can be selected with the "Collection mode" setting:

* `node` - collects metrics only from the node the agent connects to.
* `cluster` - collects metrics from all the nodes in the cluster. This is recommended when collecting metrics of an only endpoint for the whole cluster.

An example event for node looks as following:

```$json
{
   "@timestamp":"2020-06-25T10:04:20.944Z",
   "dataset":{
      "namespace":"default",
      "type":"metrics",
      "name":"rabbitmq.exchange"
   },
   "rabbitmq":{
      "vhost":"/",
      "exchange":{
         "type":"fanout",
         "durable":true,
         "auto_delete":false,
         "internal":false,
         "name":"amq.fanout",
         "arguments":{

         }
      }
   },
   "metricset":{
      "name":"exchange",
      "period":10000
   },
   "user":{
      "name":"rmq-internal"
   },
   "ecs":{
      "version":"1.5.0"
   },
   "stream":{
      "type":"metrics",
      "dataset":"rabbitmq.exchange",
      "namespace":"default"
   },
   "service":{
      "address":"localhost:15672",
      "type":"rabbitmq"
   },
   "event":{
      "dataset":"rabbitmq.exchange",
      "module":"rabbitmq",
      "duration":4104737
   }
}
```

{{fields "node"}}

### Queue Metrics

An example event for queue looks as following:

```$json
{
   "@timestamp":"2020-06-25T10:15:10.955Z",
   "dataset":{
      "type":"metrics",
      "name":"rabbitmq.queue",
      "namespace":"default"
   },
   "rabbitmq":{
      "node":{
         "name":"rabbit@047b9c4733f5"
      },
      "queue":{
         "auto_delete":false,
         "state":"running",
         "disk":{
            "reads":{

            },
            "writes":{

            }
         },
         "memory":{
            "bytes":14000
         },
         "messages":{
            "persistent":{
               "count":0
            },
            "total":{
               "details":{
                  "rate":0
               },
               "count":0
            },
            "ready":{
               "details":{
                  "rate":0
               },
               "count":0
            },
            "unacknowledged":{
               "count":0,
               "details":{
                  "rate":0
               }
            }
         },
         "durable":true,
         "arguments":{

         },
         "consumers":{
            "utilisation":{

            },
            "count":0
         },
         "name":"NameofQueue1",
         "exclusive":false
      },
      "vhost":"/"
   },
   "event":{
      "dataset":"rabbitmq.queue",
      "module":"rabbitmq",
      "duration":5860529
   },
   "metricset":{
      "name":"queue",
      "period":10000
   },
   "service":{
      "type":"rabbitmq",
      "address":"localhost:15672"
   },
   "stream":{
      "dataset":"rabbitmq.queue",
      "namespace":"default",
      "type":"metrics"
   },
   "ecs":{
      "version":"1.5.0"
   }
}
```

{{fields "queue"}}