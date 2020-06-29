# MySQL Integration

This integration periodically fetches logs and metrics from [MySQL](https://www.mysql.com/) servers.

## Compatibility

The `error` and `slowlog` datasets were tested with logs from MySQL 5.5, 5.7 and 8.0, MariaDB 10.1, 10.2 and 10.3, and Percona 5.7 and 8.0.

The `galera_status` and `status` datasets were tested with MySQL and Percona 5.7 and 8.0 and are expected to work with all
versions >= 5.7.0. It is also tested with MariaDB 10.2, 10.3 and 10.4.

## Logs

### error

The `error` dataset collects the MySQL error logs.

{{fields "error"}}

### slowlog

The `slowlog` dataset collects the MySQL slow logs.

{{fields "slowlog"}}

## Metrics

### galera_status

The `galera_status` dataset periodically fetches metrics from [Galera](http://galeracluster.com/)-MySQL cluster servers.

An example event for `galera_status` looks as following:

```$json
{
   "@timestamp":"2020-04-20T12:33:24.613Z",
   "mysql":{
      "galera_status":{
         "apply":{
            "oooe":0,
            "oool":0,
            "window":1
         },
         "connected":"ON",
         "flow_ctl":{
            "recv":0,
            "sent":0,
            "paused":0,
            "paused_ns":0
         },
         "ready":"ON",
         "received":{
            "count":173,
            "bytes":152425
         },
         "local":{
            "state":"Synced",
            "bf_aborts":0,
            "cert_failures":0,
            "commits":1325,
            "recv":{
               "queue_max":2,
               "queue_min":0,
               "queue":0,
               "queue_avg":0.011561
            },
            "replays":0,
            "send":{
               "queue_min":0,
               "queue":0,
               "queue_avg":0,
               "queue_max":1
            }
         },
         "evs":{
            "evict":"",
            "state":"OPERATIONAL"
         },
         "repl":{
            "bytes":1689804,
            "data_bytes":1540647,
            "keys":4170,
            "keys_bytes":63973,
            "other_bytes":0,
            "count":1331
         },
         "commit":{
            "oooe":0,
            "window":1
         },
         "cluster":{
            "conf_id":930,
            "size":3,
            "status":"Primary"
         },
         "last_committed":23944,
         "cert":{
            "deps_distance":43.524557,
            "index_size":22,
            "interval":0
         }
      }
   },
   "fields":{
      "stream":{
         "type":"metrics",
         "dataset":"mysql.galera_status",
         "namespace":"default"
      }
   },
   "ecs":{
      "version":"1.5.0"
   },
   "agent":{
      "hostname":"MacBook-Elastic.local",
      "id":"ede0be38-46a9-4ffc-8f1e-2ff9195193b6",
      "version":"8.0.0",
      "type":"metricbeat",
      "ephemeral_id":"4c773a2e-16d5-4d86-be49-cfb3573f4f4f"
   },
   "event":{
      "dataset":"mysql.galera_status",
      "module":"mysql",
      "duration":3275482
   },
   "metricset":{
      "name":"galera_status",
      "period":10000
   },
   "service":{
      "address":"127.0.0.1:3306",
      "type":"mysql"
   }
}
```

The fields reported are:

{{fields "galera_status"}}

### status

The MySQL `status` dataset collects data from MySQL by running a `SHOW GLOBAL STATUS;` SQL query. This query returns a large number of metrics.

An example event for `status` looks as following:

```$json
{
   "@timestamp":"2020-04-20T12:32:54.614Z",
   "mysql":{
      "status":{
         "max_used_connections":3,
         "queries":479,
         "handler":{
            "prepare":0,
            "savepoint":0,
            "update":0,
            "delete":0,
            "read":{
               "rnd_next":59604,
               "first":8,
               "key":6,
               "last":0,
               "next":1,
               "prev":0,
               "rnd":0
            },
            "rollback":0,
            "write":0,
            "commit":5,
            "savepoint_rollback":0,
            "external_lock":552,
            "mrr_init":0
         },
         "aborted":{
            "clients":0,
            "connects":0
         },
         "threads":{
            "running":2,
            "cached":1,
            "created":3,
            "connected":2
         },
         "flush_commands":1,
         "created":{
            "tmp":{
               "disk_tables":0,
               "files":6,
               "tables":0
            }
         },
         "connections":159,
         "command":{
            "insert":0,
            "select":155,
            "update":0,
            "delete":0
         },
         "opened_tables":122,
         "binlog":{
            "cache":{
               "use":0,
               "disk_use":0
            }
         },
         "delayed":{
            "writes":0,
            "errors":0,
            "insert_threads":0
         },
         "questions":479,
         "innodb":{
            "buffer_pool":{
               "read":{
                  "ahead_rnd":0,
                  "requests":1488,
                  "ahead":0,
                  "ahead_evicted":0
               },
               "pool":{
                  "wait_free":0,
                  "reads":405
               },
               "write_requests":325,
               "bytes":{
                  "data":7176192,
                  "dirty":0
               },
               "pages":{
                  "dirty":0,
                  "flushed":36,
                  "free":7753,
                  "misc":0,
                  "total":8191,
                  "data":438
               }
            }
         },
         "bytes":{
            "received":38468,
            "sent":1622162
         },
         "open":{
            "streams":0,
            "tables":115,
            "files":14
         }
      }
   },
   "event":{
      "dataset":"mysql.status",
      "module":"mysql",
      "duration":4708776
   },
   "metricset":{
      "name":"status",
      "period":10000
   },
   "fields":{
      "stream":{
         "type":"metrics",
         "dataset":"mysql.status",
         "namespace":"default"
      }
   },
   "ecs":{
      "version":"1.5.0"
   },
   "agent":{
      "id":"ede0be38-46a9-4ffc-8f1e-2ff9195193b6",
      "version":"8.0.0",
      "type":"metricbeat",
      "ephemeral_id":"4c773a2e-16d5-4d86-be49-cfb3573f4f4f",
      "hostname":"MacBook-Elastic.local"
   },
   "service":{
      "address":"127.0.0.1:3306",
      "type":"mysql"
   }
}
```

The fields reported are:

{{fields "status"}}
