# MongoDB Integration

This integration is used to fetch logs and metrics from [MongoDB](https://www.mongodb.com/).

## Compatibility

The `log` dataset is tested with logs from versions v3.2.11 on Debian.
The `collstats`, `dbstats`, `metrics`, `replstatus` and `status` datasets are 
tested with MongoDB 3.4 and 3.0 and are expected to work with all versions >= 2.8.

## MongoDB Privileges
In order to use the metrics datasets, the MongoDB user specified in the package
configuration needs to have certain [privileges](https://docs.mongodb.com/manual/core/authorization/#privileges).

We recommend using the [clusterMonitor](https://docs.mongodb.com/manual/reference/built-in-roles/#clusterMonitor) 
role to cover all the necessary privileges.

You can use the following command in Mongo shell to create the privileged user
(make sure you are using the `admin` db by using `db` command in Mongo shell).

```
db.createUser(
    {
        user: "beats",
        pwd: "pass",
        roles: ["clusterMonitor"]
    }
)
```

You can use the following command in Mongo shell to grant the role to an 
existing user (make sure you are using the `admin` db by using `db` command in 
Mongo shell).

```
db.grantRolesToUser("user", ["clusterMonitor"])
```

## Logs

### log

The `log` dataset collects the MongoDB logs.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. | date |
| log.file.path | Full path to the log file this event came from, including the file name. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | text |
| mongodb.log.component | Functional categorization of message | keyword |
| mongodb.log.context | Context of message | keyword |


## Metrics

### collstats

The `collstats` dataset uses the top administrative command to return usage 
statistics for each collection. It provides the amount of time, in microseconds,
used and a count of operations for the following types: total, readLock, writeLock,
queries, getmore, insert, update, remove, and commands.

It requires the following privileges, which is covered by the [clusterMonitor](https://docs.mongodb.com/manual/reference/built-in-roles/#clusterMonitor) role:

* [top action](https://docs.mongodb.com/manual/reference/privilege-actions/#top) on [cluster resource](https://docs.mongodb.com/manual/reference/resource-document/#cluster-resource)

An example event for `collstats` looks as following:

```$json
{
  "_id": "6hT0AXMB-2lnjH4qREj1",
  "_index": ".ds-metrics-mongodb.collstats-default-000001",
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-29T21:20:51.459Z",
    "agent": {
      "ephemeral_id": "9f6fc260-82b5-4630-95d8-df64f1379b55",
      "id": "2281e192-85d5-4d68-b90a-36a31df7b29a",
      "name": "KaiyanMacBookPro",
      "type": "metricbeat",
      "version": "8.0.0"
    },
    "dataset": {
      "name": "mongodb.collstats",
      "namespace": "default",
      "type": "metrics"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "event": {
      "dataset": "mongodb.collstats",
      "duration": 3378520,
      "module": "mongodb"
    },
    "metricset": {
      "name": "collstats",
      "period": 10000
    },
    "mongodb": {
      "collstats": {
        "collection": "startup_log",
        "commands": {
          "count": 0,
          "time": {
            "us": 0
          }
        },
        "db": "local",
        "getmore": {
          "count": 0,
          "time": {
            "us": 0
          }
        },
        "insert": {
          "count": 0,
          "time": {
            "us": 0
          }
        },
        "lock": {
          "read": {
            "count": 74,
            "time": {
              "us": 443
            }
          },
          "write": {
            "count": 1,
            "time": {
              "us": 8
            }
          }
        },
        "name": "local.startup_log",
        "queries": {
          "count": 0,
          "time": {
            "us": 0
          }
        },
        "remove": {
          "count": 0,
          "time": {
            "us": 0
          }
        },
        "total": {
          "count": 75,
          "time": {
            "us": 451
          }
        },
        "update": {
          "count": 0,
          "time": {
            "us": 0
          }
        }
      }
    },
    "service": {
      "address": "localhost:27017",
      "type": "mongodb"
    },
    "stream": {
      "dataset": "mongodb.collstats",
      "namespace": "default",
      "type": "metrics"
    }
  },
  "_version": 1,
  "fields": {
    "@timestamp": [
      "2020-06-29T21:20:51.459Z"
    ]
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
| mongodb.collstats.collection | Collection name. | keyword |
| mongodb.collstats.commands.count | Number of database commands executed. | long |
| mongodb.collstats.commands.time.us | Time executing database commands in microseconds. | long |
| mongodb.collstats.db | Database name. | keyword |
| mongodb.collstats.getmore.count | Number of times a cursor asked for more data. | long |
| mongodb.collstats.getmore.time.us | Time asking for more cursor rows in microseconds. | long |
| mongodb.collstats.insert.count | Number of document insert events. | long |
| mongodb.collstats.insert.time.us | Time inserting new documents in microseconds. | long |
| mongodb.collstats.lock.read.count | Number of read lock wait events. | long |
| mongodb.collstats.lock.read.time.us | Time waiting for read locks in microseconds. | long |
| mongodb.collstats.lock.write.count | Number of write lock wait events. | long |
| mongodb.collstats.lock.write.time.us | Time waiting for write locks in microseconds. | long |
| mongodb.collstats.name | Combination of database and collection name. | keyword |
| mongodb.collstats.queries.count | Number of queries executed. | long |
| mongodb.collstats.queries.time.us | Time running queries in microseconds. | long |
| mongodb.collstats.remove.count | Number of document delete events. | long |
| mongodb.collstats.remove.time.us | Time deleting documents in microseconds. | long |
| mongodb.collstats.total.count | Total number of lock wait events. | long |
| mongodb.collstats.total.time.us | Total waiting time for locks in microseconds. | long |
| mongodb.collstats.update.count | Number of document update events. | long |
| mongodb.collstats.update.time.us | Time updating documents in microseconds. | long |
| service.address | Address of the machine where the service is running. | ip |


### dbstats

The `dbstats` dataset collects storage statistics for a given database. 

It requires the following privileges, which is covered by the [clusterMonitor](https://docs.mongodb.com/manual/reference/built-in-roles/#clusterMonitor) role:

* [listDatabases](https://docs.mongodb.com/manual/reference/privilege-actions/#listDatabases) 
action on [cluster resource](https://docs.mongodb.com/manual/reference/resource-document/#cluster-resource)

* for each of the databases, also need [dbStats](https://docs.mongodb.com/manual/reference/privilege-actions/#dbStats)
action on the [database resource](https://docs.mongodb.com/manual/reference/resource-document/#database-and-or-collection-resource)

An example event for `dbstats` looks as following:

```$json
{
  "_id": "6hT0AXMB-2lnjH4qREj0",
  "_index": ".ds-metrics-mongodb.dbstats-default-000001",
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-29T21:20:51.459Z",
    "agent": {
      "ephemeral_id": "9f6fc260-82b5-4630-95d8-df64f1379b55",
      "id": "2281e192-85d5-4d68-b90a-36a31df7b29a",
      "name": "KaiyanMacBookPro",
      "type": "metricbeat",
      "version": "8.0.0"
    },
    "dataset": {
      "name": "mongodb.dbstats",
      "namespace": "default",
      "type": "metrics"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "event": {
      "dataset": "mongodb.dbstats",
      "duration": 3378520,
      "module": "mongodb"
    },
    "metricset": {
      "name": "dbstats",
      "period": 10000
    },
    "mongodb": {
      "dbstats": {
        "avg_obj_size": {
          "bytes": 59
        },
        "collections": 1,
        "data_size": {
          "bytes": 59
        },
        "db": "admin",
        "file_size": {},
        "index_size": {
          "bytes": 20480
        },
        "indexes": 1,
        "ns_size_mb": {},
        "num_extents": 0,
        "objects": 1,
        "storage_size": {
          "bytes": 20480
        }
      }
    },
    "service": {
      "address": "localhost:27017",
      "type": "mongodb"
    },
    "stream": {
      "dataset": "mongodb.dbstats",
      "namespace": "default",
      "type": "metrics"
    }
  },
  "_version": 1,
  "fields": {
    "@timestamp": [
      "2020-06-29T21:20:51.459Z"
    ]
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
| mongodb.dbstats.avg_obj_size.bytes |  | long |
| mongodb.dbstats.collections |  | integer |
| mongodb.dbstats.data_file_version.major |  | long |
| mongodb.dbstats.data_file_version.minor |  | long |
| mongodb.dbstats.data_size.bytes |  | long |
| mongodb.dbstats.db |  | keyword |
| mongodb.dbstats.extent_free_list.num |  | long |
| mongodb.dbstats.extent_free_list.size.bytes |  | long |
| mongodb.dbstats.file_size.bytes |  | long |
| mongodb.dbstats.index_size.bytes |  | long |
| mongodb.dbstats.indexes |  | long |
| mongodb.dbstats.ns_size_mb.mb |  | long |
| mongodb.dbstats.num_extents |  | long |
| mongodb.dbstats.objects |  | long |
| mongodb.dbstats.storage_size.bytes |  | long |
| service.address | Address of the machine where the service is running. | ip |


### metrics

It requires the following privileges, which is covered by the clusterMonitor role:

* [serverStatus](https://docs.mongodb.com/manual/reference/privilege-actions/#serverStatus) 
action on [cluster resource](https://docs.mongodb.com/manual/reference/resource-document/#cluster-resource)

An example event for `metrics` looks as following:

```$json
{
  "_id": "6RT0AXMB-2lnjH4qREj0",
  "_index": ".ds-metrics-mongodb.metrics-default-000001",
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-29T21:20:51.459Z",
    "agent": {
      "ephemeral_id": "9f6fc260-82b5-4630-95d8-df64f1379b55",
      "id": "2281e192-85d5-4d68-b90a-36a31df7b29a",
      "name": "KaiyanMacBookPro",
      "type": "metricbeat",
      "version": "8.0.0"
    },
    "dataset": {
      "name": "mongodb.metrics",
      "namespace": "default",
      "type": "metrics"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "event": {
      "dataset": "mongodb.metrics",
      "duration": 3039885,
      "module": "mongodb"
    },
    "metricset": {
      "name": "metrics",
      "period": 10000
    },
    "mongodb": {
      "metrics": {
        "commands": {
          "aggregate": {
            "failed": 0,
            "total": 0
          },
          "build_info": {
            "failed": 0,
            "total": 6
          },
          "coll_stats": {
            "failed": 0,
            "total": 0
          },
          "connection_pool_stats": {
            "failed": 0,
            "total": 0
          },
          "count": {
            "failed": 0,
            "total": 0
          },
          "db_stats": {
            "failed": 0,
            "total": 2044
          },
          "distinct": {
            "failed": 0,
            "total": 0
          },
          "find": {
            "failed": 0,
            "total": 94
          },
          "get_cmd_line_opts": {
            "failed": 0,
            "total": 2
          },
          "get_last_error": {
            "failed": 0,
            "total": 0
          },
          "get_log": {
            "failed": 0,
            "total": 2
          },
          "get_more": {
            "failed": 0,
            "total": 0
          },
          "get_parameter": {
            "failed": 0,
            "total": 0
          },
          "host_info": {
            "failed": 0,
            "total": 0
          },
          "insert": {
            "failed": 0,
            "total": 7
          },
          "is_master": {
            "failed": 0,
            "total": 2332
          },
          "is_self": {
            "failed": 0,
            "total": 0
          },
          "last_collections": {
            "failed": 0,
            "total": 458
          },
          "last_commands": {
            "failed": 0,
            "total": 0
          },
          "list_databased": {
            "failed": 0,
            "total": 466
          },
          "list_indexes": {
            "failed": 0,
            "total": 174
          },
          "ping": {
            "failed": 0,
            "total": 2290
          },
          "profile": {
            "failed": 0,
            "total": 0
          },
          "replset_get_rbid": {
            "failed": 0,
            "total": 0
          },
          "replset_get_status": {
            "failed": 2,
            "total": 2
          },
          "replset_heartbeat": {
            "failed": 0,
            "total": 0
          },
          "replset_update_position": {
            "failed": 0,
            "total": 0
          },
          "server_status": {
            "failed": 0,
            "total": 916
          },
          "update": {
            "failed": 0,
            "total": 5
          },
          "whatsmyuri": {
            "failed": 0,
            "total": 2
          }
        },
        "cursor": {
          "open": {
            "no_timeout": 0,
            "pinned": 0,
            "total": 0
          },
          "timed_out": 0
        },
        "document": {
          "deleted": 15,
          "inserted": 19,
          "returned": 465,
          "updated": 2
        },
        "get_last_error": {
          "write_timeouts": 0,
          "write_wait": {
            "count": 0,
            "ms": 0
          }
        },
        "operation": {
          "scan_and_order": 0,
          "write_conflicts": 0
        },
        "query_executor": {
          "scanned_documents": {
            "count": 24
          },
          "scanned_indexes": {
            "count": 2
          }
        },
        "replication": {
          "apply": {
            "attempts_to_become_secondary": 0,
            "batches": {
              "count": 0,
              "time": {
                "ms": 0
              }
            },
            "ops": 0
          },
          "buffer": {
            "count": 0,
            "max_size": {
              "bytes": 0
            },
            "size": {
              "bytes": 0
            }
          },
          "executor": {
            "network_interface": "DEPRECATED: getDiagnosticString is deprecated in NetworkInterfaceTL",
            "queues": {
              "in_progress": {
                "network": 0
              },
              "sleepers": 0
            },
            "shutting_down": false,
            "unsignaled_events": 0
          },
          "initial_sync": {
            "completed": 0,
            "failed_attempts": 0,
            "failures": 0
          },
          "network": {
            "bytes": 0,
            "getmores": {
              "count": 0,
              "time": {
                "ms": 0
              }
            },
            "ops": 0,
            "reders_created": 0
          }
        },
        "ttl": {
          "deleted_documents": {
            "count": 3
          },
          "passes": {
            "count": 433
          }
        }
      }
    },
    "service": {
      "address": "localhost:27017",
      "type": "mongodb"
    },
    "stream": {
      "dataset": "mongodb.metrics",
      "namespace": "default",
      "type": "metrics"
    }
  },
  "_version": 1,
  "fields": {
    "@timestamp": [
      "2020-06-29T21:20:51.459Z"
    ]
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
| mongodb.metrics.commands.aggregate.failed |  | long |
| mongodb.metrics.commands.aggregate.total |  | long |
| mongodb.metrics.commands.build_info.failed |  | long |
| mongodb.metrics.commands.build_info.total |  | long |
| mongodb.metrics.commands.coll_stats.failed |  | long |
| mongodb.metrics.commands.coll_stats.total |  | long |
| mongodb.metrics.commands.connection_pool_stats.failed |  | long |
| mongodb.metrics.commands.connection_pool_stats.total |  | long |
| mongodb.metrics.commands.count.failed |  | long |
| mongodb.metrics.commands.count.total |  | long |
| mongodb.metrics.commands.db_stats.failed |  | long |
| mongodb.metrics.commands.db_stats.total |  | long |
| mongodb.metrics.commands.distinct.failed |  | long |
| mongodb.metrics.commands.distinct.total |  | long |
| mongodb.metrics.commands.find.failed |  | long |
| mongodb.metrics.commands.find.total |  | long |
| mongodb.metrics.commands.get_cmd_line_opts.failed |  | long |
| mongodb.metrics.commands.get_cmd_line_opts.total |  | long |
| mongodb.metrics.commands.get_last_error.failed |  | long |
| mongodb.metrics.commands.get_last_error.total |  | long |
| mongodb.metrics.commands.get_log.failed |  | long |
| mongodb.metrics.commands.get_log.total |  | long |
| mongodb.metrics.commands.get_more.failed |  | long |
| mongodb.metrics.commands.get_more.total |  | long |
| mongodb.metrics.commands.get_parameter.failed |  | long |
| mongodb.metrics.commands.get_parameter.total |  | long |
| mongodb.metrics.commands.host_info.failed |  | long |
| mongodb.metrics.commands.host_info.total |  | long |
| mongodb.metrics.commands.insert.failed |  | long |
| mongodb.metrics.commands.insert.total |  | long |
| mongodb.metrics.commands.is_master.failed |  | long |
| mongodb.metrics.commands.is_master.total |  | long |
| mongodb.metrics.commands.is_self.failed |  | long |
| mongodb.metrics.commands.is_self.total |  | long |
| mongodb.metrics.commands.last_collections.failed |  | long |
| mongodb.metrics.commands.last_collections.total |  | long |
| mongodb.metrics.commands.last_commands.failed |  | long |
| mongodb.metrics.commands.last_commands.total |  | long |
| mongodb.metrics.commands.list_databased.failed |  | long |
| mongodb.metrics.commands.list_databased.total |  | long |
| mongodb.metrics.commands.list_indexes.failed |  | long |
| mongodb.metrics.commands.list_indexes.total |  | long |
| mongodb.metrics.commands.ping.failed |  | long |
| mongodb.metrics.commands.ping.total |  | long |
| mongodb.metrics.commands.profile.failed |  | long |
| mongodb.metrics.commands.profile.total |  | long |
| mongodb.metrics.commands.replset_get_rbid.failed |  | long |
| mongodb.metrics.commands.replset_get_rbid.total |  | long |
| mongodb.metrics.commands.replset_get_status.failed |  | long |
| mongodb.metrics.commands.replset_get_status.total |  | long |
| mongodb.metrics.commands.replset_heartbeat.failed |  | long |
| mongodb.metrics.commands.replset_heartbeat.total |  | long |
| mongodb.metrics.commands.replset_update_position.failed |  | long |
| mongodb.metrics.commands.replset_update_position.total |  | long |
| mongodb.metrics.commands.server_status.failed |  | long |
| mongodb.metrics.commands.server_status.total |  | long |
| mongodb.metrics.commands.update.failed |  | long |
| mongodb.metrics.commands.update.total |  | long |
| mongodb.metrics.commands.whatsmyuri.failed |  | long |
| mongodb.metrics.commands.whatsmyuri.total |  | long |
| mongodb.metrics.cursor.open.no_timeout | The number of open cursors with the option DBQuery.Option.noTimeout set to prevent timeout. | long |
| mongodb.metrics.cursor.open.pinned | The number of `pinned` open cursors. | long |
| mongodb.metrics.cursor.open.total | The number of cursors that MongoDB is maintaining for clients. | long |
| mongodb.metrics.cursor.timed_out | The total number of cursors that have timed out since the server process started. | long |
| mongodb.metrics.document.deleted | The total number of documents deleted. | long |
| mongodb.metrics.document.inserted | The total number of documents inserted. | long |
| mongodb.metrics.document.returned | The total number of documents returned by queries. | long |
| mongodb.metrics.document.updated | The total number of documents updated. | long |
| mongodb.metrics.get_last_error.write_timeouts | The number of times that write concern operations have timed out as a result of the wtimeout threshold to getLastError. | long |
| mongodb.metrics.get_last_error.write_wait.count | The total number of getLastError operations with a specified write concern (i.e. w) greater than 1. | long |
| mongodb.metrics.get_last_error.write_wait.ms | The total amount of time in milliseconds that the mongod has spent performing getLastError operations with write concern (i.e. w) greater than 1. | long |
| mongodb.metrics.operation.scan_and_order | The total number of queries that return sorted numbers that cannot perform the sort operation using an index. | long |
| mongodb.metrics.operation.write_conflicts | The total number of queries that encountered write conflicts. | long |
| mongodb.metrics.query_executor.scanned_documents.count | The total number of documents scanned during queries and query-plan evaluation. | long |
| mongodb.metrics.query_executor.scanned_indexes.count | The total number of index items scanned during queries and query-plan evaluation. | long |
| mongodb.metrics.replication.apply.attempts_to_become_secondary |  | long |
| mongodb.metrics.replication.apply.batches.count | The total number of batches applied across all databases. | long |
| mongodb.metrics.replication.apply.batches.time.ms | The total amount of time in milliseconds the mongod has spent applying operations from the oplog. | long |
| mongodb.metrics.replication.apply.ops | The total number of oplog operations applied. | long |
| mongodb.metrics.replication.buffer.count | The current number of operations in the oplog buffer. | long |
| mongodb.metrics.replication.buffer.max_size.bytes | The maximum size of the buffer. This value is a constant setting in the mongod, and is not configurable. | long |
| mongodb.metrics.replication.buffer.size.bytes | The current size of the contents of the oplog buffer. | long |
| mongodb.metrics.replication.executor.counters.cancels |  | long |
| mongodb.metrics.replication.executor.counters.event_created |  | long |
| mongodb.metrics.replication.executor.counters.event_wait |  | long |
| mongodb.metrics.replication.executor.counters.scheduled.dbwork |  | long |
| mongodb.metrics.replication.executor.counters.scheduled.exclusive |  | long |
| mongodb.metrics.replication.executor.counters.scheduled.failures |  | long |
| mongodb.metrics.replication.executor.counters.scheduled.netcmd |  | long |
| mongodb.metrics.replication.executor.counters.scheduled.work |  | long |
| mongodb.metrics.replication.executor.counters.scheduled.work_at |  | long |
| mongodb.metrics.replication.executor.counters.waits |  | long |
| mongodb.metrics.replication.executor.event_waiters |  | long |
| mongodb.metrics.replication.executor.network_interface |  | keyword |
| mongodb.metrics.replication.executor.queues.free |  | long |
| mongodb.metrics.replication.executor.queues.in_progress.dbwork |  | long |
| mongodb.metrics.replication.executor.queues.in_progress.exclusive |  | long |
| mongodb.metrics.replication.executor.queues.in_progress.network |  | long |
| mongodb.metrics.replication.executor.queues.ready |  | long |
| mongodb.metrics.replication.executor.queues.sleepers |  | long |
| mongodb.metrics.replication.executor.shutting_down |  | boolean |
| mongodb.metrics.replication.executor.unsignaled_events |  | long |
| mongodb.metrics.replication.initial_sync.completed |  | long |
| mongodb.metrics.replication.initial_sync.failed_attempts |  | long |
| mongodb.metrics.replication.initial_sync.failures |  | long |
| mongodb.metrics.replication.network.bytes | The total amount of data read from the replication sync source. | long |
| mongodb.metrics.replication.network.getmores.count | The total number of getmore operations | long |
| mongodb.metrics.replication.network.getmores.time.ms | The total amount of time required to collect data from getmore operations. | long |
| mongodb.metrics.replication.network.ops | The total number of operations read from the replication source. | long |
| mongodb.metrics.replication.network.reders_created | The total number of oplog query processes created. | long |
| mongodb.metrics.replication.preload.docs.count | The total number of documents loaded during the pre-fetch stage of replication. | long |
| mongodb.metrics.replication.preload.docs.time.ms |  | long |
| mongodb.metrics.replication.preload.indexes.count | The total number of index entries loaded by members before updating documents as part of the pre-fetch stage of replication. | long |
| mongodb.metrics.replication.preload.indexes.time.ms | The total amount of time, in milliseconds, spent loading index entries as part of the pre-fetch stage of replication. | long |
| mongodb.metrics.storage.free_list.search.bucket_exhausted | The number of times that mongod has checked the free list without finding a suitably large record allocation. | long |
| mongodb.metrics.storage.free_list.search.requests | The number of times mongod has searched for available record allocations. | long |
| mongodb.metrics.storage.free_list.search.scanned | The number of available record allocations mongod has searched. | long |
| mongodb.metrics.ttl.deleted_documents.count | The total number of documents deleted from collections with a ttl index. | long |
| mongodb.metrics.ttl.passes.count | The number of times the background process removes documents from collections with a ttl index. | long |
| service.address | Address of the machine where the service is running. | ip |


### replstatus
The `replstatus` dataset collects status of the replica set.
It requires the following privileges, which is covered by the [clusterMonitor](https://docs.mongodb.com/manual/reference/built-in-roles/#clusterMonitor) role:

* [find/listCollections](https://docs.mongodb.com/manual/reference/privilege-actions/#find) action on the [local database](https://docs.mongodb.com/manual/reference/local-database/) resource
* [collStats](https://docs.mongodb.com/manual/reference/privilege-actions/#collStats) action on the [local.oplog.rs](https://docs.mongodb.com/manual/reference/local-database/#local.oplog.rs) collection resource
* [replSetGetStatus](https://docs.mongodb.com/manual/reference/privilege-actions/#replSetGetStatus) action on [cluster resource](https://docs.mongodb.com/manual/reference/resource-document/#cluster-resource)

An example event for `replstatus` looks as following:

```$json
{
  "_id": "3BT0AXMB-2lnjH4qREj0",
  "_index": ".ds-metrics-mongodb.replstatus-default-000001",
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-29T21:20:51.457Z",
    "agent": {
      "ephemeral_id": "9f6fc260-82b5-4630-95d8-df64f1379b55",
      "id": "2281e192-85d5-4d68-b90a-36a31df7b29a",
      "name": "KaiyanMacBookPro",
      "type": "metricbeat",
      "version": "8.0.0"
    },
    "dataset": {
      "name": "mongodb.replstatus",
      "namespace": "default",
      "type": "metrics"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "error": {
      "message": "error getting replication info: collection oplog.rs was not found"
    },
    "event": {
      "dataset": "mongodb.replstatus",
      "duration": 1962467,
      "module": "mongodb"
    },
    "metricset": {
      "name": "replstatus",
      "period": 10000
    },
    "service": {
      "address": "localhost:27017",
      "type": "mongodb"
    },
    "stream": {
      "dataset": "mongodb.replstatus",
      "namespace": "default",
      "type": "metrics"
    }
  },
  "_version": 1,
  "fields": {
    "@timestamp": [
      "2020-06-29T21:20:51.457Z"
    ]
  },
  "sort": [
    1593465651457
  ]
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
| mongodb.replstatus.headroom.max | Difference between primary's oplog window and the replication lag of the fastest secondary | long |
| mongodb.replstatus.headroom.min | Difference between primary's oplog window and the replication lag of the slowest secondary | long |
| mongodb.replstatus.lag.max | Difference between optime of primary and slowest secondary | long |
| mongodb.replstatus.lag.min | Difference between optime of primary and fastest secondary | long |
| mongodb.replstatus.members.arbiter.count | Count of arbiters | long |
| mongodb.replstatus.members.arbiter.hosts | List of arbiters hosts | keyword |
| mongodb.replstatus.members.down.count | Count of `down` members | long |
| mongodb.replstatus.members.down.hosts | List of `down` members hosts | keyword |
| mongodb.replstatus.members.primary.host | Host address of the primary | keyword |
| mongodb.replstatus.members.primary.optime | Optime of primary | keyword |
| mongodb.replstatus.members.recovering.count | Count of members in the `recovering` state | long |
| mongodb.replstatus.members.recovering.hosts | List of recovering members hosts | keyword |
| mongodb.replstatus.members.rollback.count | Count of members in the `rollback` state | long |
| mongodb.replstatus.members.rollback.hosts | List of members in the `rollback` state | keyword |
| mongodb.replstatus.members.secondary.count |  | long |
| mongodb.replstatus.members.secondary.hosts | List of secondary hosts | keyword |
| mongodb.replstatus.members.secondary.optimes | Optimes of secondaries | keyword |
| mongodb.replstatus.members.startup2.count | Count of members in the `startup2` state | long |
| mongodb.replstatus.members.startup2.hosts | List of initializing members hosts | keyword |
| mongodb.replstatus.members.unhealthy.count | Count of unhealthy members | long |
| mongodb.replstatus.members.unhealthy.hosts | List of members' hosts with healthy = false | keyword |
| mongodb.replstatus.members.unknown.count | Count of members with `unknown` state | long |
| mongodb.replstatus.members.unknown.hosts | List of members' hosts in the `unknown` state | keyword |
| mongodb.replstatus.oplog.first.timestamp | Timestamp of the first (i.e. earliest) operation in the replstatus | long |
| mongodb.replstatus.oplog.last.timestamp | Timestamp of the last (i.e. latest) operation in the replstatus | long |
| mongodb.replstatus.oplog.size.allocated | The total amount of space used by the replstatus in bytes. | long |
| mongodb.replstatus.oplog.size.used | total amount of space allocated to the replstatus in bytes. | long |
| mongodb.replstatus.oplog.window | The difference between the first and last operation in the replstatus. | long |
| mongodb.replstatus.optimes.applied | Information, from the viewpoint of this member, regarding the most recent operation that has been applied to this member of the replica set. | long |
| mongodb.replstatus.optimes.durable | Information, from the viewpoint of this member, regarding the most recent operation that has been written to the journal of this member of the replica set. | long |
| mongodb.replstatus.optimes.last_committed | Information, from the viewpoint of this member, regarding the most recent operation that has been written to a majority of replica set members. | long |
| mongodb.replstatus.server_date | Reflects the current time according to the server that processed the replSetGetStatus command. | date |
| mongodb.replstatus.set_name | The name of the replica set. | keyword |
| service.address | Address of the machine where the service is running. | ip |


### status

It requires the following privileges, which is covered by the [clusterMonitor](https://docs.mongodb.com/manual/reference/built-in-roles/#clusterMonitor) role:

* [serverStatus](https://docs.mongodb.com/manual/reference/privilege-actions/#serverStatus) 
action on [cluster resource](https://docs.mongodb.com/manual/reference/resource-document/#cluster-resource)

An example event for `status` looks as following:

```$json
{
  "_id": "ZxTzAXMB-2lnjH4qgUKh",
  "_index": ".ds-metrics-mongodb.status-default-000001",
  "_score": null,
  "_source": {
    "@timestamp": "2020-06-29T21:20:01.455Z",
    "agent": {
      "ephemeral_id": "9f6fc260-82b5-4630-95d8-df64f1379b55",
      "id": "2281e192-85d5-4d68-b90a-36a31df7b29a",
      "name": "KaiyanMacBookPro",
      "type": "metricbeat",
      "version": "8.0.0"
    },
    "dataset": {
      "name": "mongodb.status",
      "namespace": "default",
      "type": "metrics"
    },
    "ecs": {
      "version": "1.5.0"
    },
    "event": {
      "dataset": "mongodb.status",
      "duration": 3581045,
      "module": "mongodb"
    },
    "metricset": {
      "name": "status",
      "period": 10000
    },
    "mongodb": {
      "status": {
        "asserts": {
          "msg": 0,
          "regular": 0,
          "rollovers": 0,
          "user": 9,
          "warning": 0
        },
        "connections": {
          "available": 3271,
          "current": 5,
          "total_created": 2266
        },
        "extra_info": {
          "heap_usage": {},
          "page_faults": 0
        },
        "global_lock": {
          "active_clients": {
            "readers": 1,
            "total": 1,
            "writers": 0
          },
          "current_queue": {
            "readers": 0,
            "total": 0,
            "writers": 0
          },
          "total_time": {
            "us": 26003338000
          }
        },
        "local_time": "2020-06-29T21:20:01.457Z",
        "locks": {
          "collection": {
            "acquire": {
              "count": {
                "W": 3,
                "r": 8221,
                "w": 450
              }
            },
            "deadlock": {},
            "wait": {}
          },
          "database": {
            "acquire": {
              "count": {
                "W": 5,
                "r": 5238,
                "w": 453
              }
            },
            "deadlock": {},
            "wait": {}
          },
          "global": {
            "acquire": {
              "count": {
                "W": 4,
                "r": 56961,
                "w": 458
              }
            },
            "deadlock": {},
            "wait": {}
          }
        },
        "memory": {
          "bits": 64,
          "mapped": {},
          "mapped_with_journal": {},
          "resident": {
            "mb": 44
          },
          "virtual": {
            "mb": 6971
          }
        },
        "network": {
          "in": {
            "bytes": 687306
          },
          "out": {
            "bytes": 32519464
          },
          "requests": 11607
        },
        "ops": {
          "counters": {
            "command": 11314,
            "delete": 3,
            "getmore": 452,
            "insert": 19,
            "query": 94,
            "update": 5
          },
          "latencies": {
            "commands": {
              "count": 11138,
              "latency": 2055949
            },
            "reads": {
              "count": 458,
              "latency": 14259
            },
            "writes": {
              "count": 9,
              "latency": 103455
            }
          },
          "replicated": {
            "command": 0,
            "delete": 0,
            "getmore": 0,
            "insert": 0,
            "query": 0,
            "update": 0
          }
        },
        "storage_engine": {
          "name": "wiredTiger"
        },
        "uptime": {
          "ms": 26003340
        },
        "wired_tiger": {
          "cache": {
            "dirty": {
              "bytes": 0
            },
            "maximum": {
              "bytes": 16642998272
            },
            "pages": {
              "evicted": 0,
              "read": 14,
              "write": 111
            },
            "used": {
              "bytes": 89236
            }
          },
          "concurrent_transactions": {
            "read": {
              "available": 128,
              "out": 0,
              "total_tickets": 128
            },
            "write": {
              "available": 128,
              "out": 0,
              "total_tickets": 128
            }
          },
          "log": {
            "flushes": 152183,
            "max_file_size": {
              "bytes": 104857600
            },
            "scans": 6,
            "size": {
              "bytes": 33554432
            },
            "syncs": 67,
            "write": {
              "bytes": 46976
            },
            "writes": 140
          }
        }
      }
    },
    "process": {
      "name": "mongod"
    },
    "service": {
      "address": "localhost:27017",
      "type": "mongodb",
      "version": "4.2.0"
    },
    "stream": {
      "dataset": "mongodb.status",
      "namespace": "default",
      "type": "metrics"
    }
  },
  "_version": 1,
  "fields": {
    "@timestamp": [
      "2020-06-29T21:20:01.455Z"
    ],
    "mongodb.status.local_time": [
      "2020-06-29T21:20:01.457Z"
    ]
  },
  "sort": [
    1593465601455
  ]
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
| mongodb.status.asserts.msg | Number of msg assertions produced by the server. | long |
| mongodb.status.asserts.regular | Number of regular assertions produced by the server. | long |
| mongodb.status.asserts.rollovers | Number of rollovers assertions produced by the server. | long |
| mongodb.status.asserts.user | Number of user assertions produced by the server. | long |
| mongodb.status.asserts.warning | Number of warning assertions produced by the server. | long |
| mongodb.status.background_flushing.average.ms | The average time spent flushing to disk per flush event. | long |
| mongodb.status.background_flushing.flushes | A counter that collects the number of times the database has flushed all writes to disk. | long |
| mongodb.status.background_flushing.last.ms | The amount of time, in milliseconds, that the last flush operation took to complete. | long |
| mongodb.status.background_flushing.last_finished | A timestamp of the last completed flush operation. | date |
| mongodb.status.background_flushing.total.ms | The total number of milliseconds (ms) that the mongod processes have spent writing (i.e. flushing) data to disk. Because this is an absolute value, consider the value of `flushes` and `average_ms` to provide better context for this datum. | long |
| mongodb.status.connections.available | The number of unused available incoming connections the database can provide. | long |
| mongodb.status.connections.current | The number of connections to the database server from clients. This number includes the current shell session. Consider the value of `available` to add more context to this datum. | long |
| mongodb.status.connections.total_created | A count of all incoming connections created to the server. This number includes connections that have since closed. | long |
| mongodb.status.extra_info.heap_usage.bytes | The total size in bytes of heap space used by the database process. Only available on Unix/Linux. | long |
| mongodb.status.extra_info.page_faults | The total number of page faults that require disk operations. Page faults refer to operations that require the database server to access data that isn't available in active memory. | long |
| mongodb.status.global_lock.active_clients.readers | The number of the active client connections performing read operations. | long |
| mongodb.status.global_lock.active_clients.total | Total number of the active client connections performing read or write operations. | long |
| mongodb.status.global_lock.active_clients.writers | The number of the active client connections performing write operations. | long |
| mongodb.status.global_lock.current_queue.readers | The number of operations that are currently queued and waiting for the read lock. | long |
| mongodb.status.global_lock.current_queue.total | The total number of operations queued waiting for the lock (i.e., the sum of current_queue.readers and current_queue.writers). | long |
| mongodb.status.global_lock.current_queue.writers | The number of operations that are currently queued and waiting for the write lock. | long |
| mongodb.status.global_lock.total_time.us | The time, in microseconds, since the database last started and created the globalLock. This is roughly equivalent to total server uptime. | long |
| mongodb.status.journaling.commits | The number of transactions written to the journal during the last journal group commit interval. | long |
| mongodb.status.journaling.commits_in_write_lock | Count of the commits that occurred while a write lock was held. Commits in a write lock indicate a MongoDB node under a heavy write load and call for further diagnosis. | long |
| mongodb.status.journaling.compression | The compression ratio of the data written to the journal. | long |
| mongodb.status.journaling.early_commits | The number of times MongoDB requested a commit before the scheduled journal group commit interval. | long |
| mongodb.status.journaling.journaled.mb | The amount of data in megabytes (MB) written to journal during the last journal group commit interval. | long |
| mongodb.status.journaling.times.commits.ms | The amount of time spent for commits. | long |
| mongodb.status.journaling.times.commits_in_write_lock.ms | The amount of time spent for commits that occurred while a write lock was held. | long |
| mongodb.status.journaling.times.dt.ms | The amount of time over which MongoDB collected the times data. Use this field to provide context to the other times field values. | long |
| mongodb.status.journaling.times.prep_log_buffer.ms | The amount of time spent preparing to write to the journal. Smaller values indicate better journal performance. | long |
| mongodb.status.journaling.times.remap_private_view.ms | The amount of time spent remapping copy-on-write memory mapped views. Smaller values indicate better journal performance. | long |
| mongodb.status.journaling.times.write_to_data_files.ms | The amount of time spent writing to data files after journaling. File system speeds and device interfaces can affect performance. | long |
| mongodb.status.journaling.times.write_to_journal.ms | The amount of time spent actually writing to the journal. File system speeds and device interfaces can affect performance. | long |
| mongodb.status.journaling.write_to_data_files.mb | The amount of data in megabytes (MB) written from journal to the data files during the last journal group commit interval. | long |
| mongodb.status.local_time | Local time as reported by the MongoDB instance. | date |
| mongodb.status.locks.collection.acquire.count.R |  | long |
| mongodb.status.locks.collection.acquire.count.W |  | long |
| mongodb.status.locks.collection.acquire.count.r |  | long |
| mongodb.status.locks.collection.acquire.count.w |  | long |
| mongodb.status.locks.collection.deadlock.count.R |  | long |
| mongodb.status.locks.collection.deadlock.count.W |  | long |
| mongodb.status.locks.collection.deadlock.count.r |  | long |
| mongodb.status.locks.collection.deadlock.count.w |  | long |
| mongodb.status.locks.collection.wait.count.R |  | long |
| mongodb.status.locks.collection.wait.count.W |  | long |
| mongodb.status.locks.collection.wait.count.r |  | long |
| mongodb.status.locks.collection.wait.count.w |  | long |
| mongodb.status.locks.collection.wait.us.R |  | long |
| mongodb.status.locks.collection.wait.us.W |  | long |
| mongodb.status.locks.collection.wait.us.r |  | long |
| mongodb.status.locks.collection.wait.us.w |  | long |
| mongodb.status.locks.database.acquire.count.R |  | long |
| mongodb.status.locks.database.acquire.count.W |  | long |
| mongodb.status.locks.database.acquire.count.r |  | long |
| mongodb.status.locks.database.acquire.count.w |  | long |
| mongodb.status.locks.database.deadlock.count.R |  | long |
| mongodb.status.locks.database.deadlock.count.W |  | long |
| mongodb.status.locks.database.deadlock.count.r |  | long |
| mongodb.status.locks.database.deadlock.count.w |  | long |
| mongodb.status.locks.database.wait.count.R |  | long |
| mongodb.status.locks.database.wait.count.W |  | long |
| mongodb.status.locks.database.wait.count.r |  | long |
| mongodb.status.locks.database.wait.count.w |  | long |
| mongodb.status.locks.database.wait.us.R |  | long |
| mongodb.status.locks.database.wait.us.W |  | long |
| mongodb.status.locks.database.wait.us.r |  | long |
| mongodb.status.locks.database.wait.us.w |  | long |
| mongodb.status.locks.global.acquire.count.R |  | long |
| mongodb.status.locks.global.acquire.count.W |  | long |
| mongodb.status.locks.global.acquire.count.r |  | long |
| mongodb.status.locks.global.acquire.count.w |  | long |
| mongodb.status.locks.global.deadlock.count.R |  | long |
| mongodb.status.locks.global.deadlock.count.W |  | long |
| mongodb.status.locks.global.deadlock.count.r |  | long |
| mongodb.status.locks.global.deadlock.count.w |  | long |
| mongodb.status.locks.global.wait.count.R |  | long |
| mongodb.status.locks.global.wait.count.W |  | long |
| mongodb.status.locks.global.wait.count.r |  | long |
| mongodb.status.locks.global.wait.count.w |  | long |
| mongodb.status.locks.global.wait.us.R |  | long |
| mongodb.status.locks.global.wait.us.W |  | long |
| mongodb.status.locks.global.wait.us.r |  | long |
| mongodb.status.locks.global.wait.us.w |  | long |
| mongodb.status.locks.meta_data.acquire.count.R |  | long |
| mongodb.status.locks.meta_data.acquire.count.W |  | long |
| mongodb.status.locks.meta_data.acquire.count.r |  | long |
| mongodb.status.locks.meta_data.acquire.count.w |  | long |
| mongodb.status.locks.meta_data.deadlock.count.R |  | long |
| mongodb.status.locks.meta_data.deadlock.count.W |  | long |
| mongodb.status.locks.meta_data.deadlock.count.r |  | long |
| mongodb.status.locks.meta_data.deadlock.count.w |  | long |
| mongodb.status.locks.meta_data.wait.count.R |  | long |
| mongodb.status.locks.meta_data.wait.count.W |  | long |
| mongodb.status.locks.meta_data.wait.count.r |  | long |
| mongodb.status.locks.meta_data.wait.count.w |  | long |
| mongodb.status.locks.meta_data.wait.us.R |  | long |
| mongodb.status.locks.meta_data.wait.us.W |  | long |
| mongodb.status.locks.meta_data.wait.us.r |  | long |
| mongodb.status.locks.meta_data.wait.us.w |  | long |
| mongodb.status.locks.oplog.acquire.count.R |  | long |
| mongodb.status.locks.oplog.acquire.count.W |  | long |
| mongodb.status.locks.oplog.acquire.count.r |  | long |
| mongodb.status.locks.oplog.acquire.count.w |  | long |
| mongodb.status.locks.oplog.deadlock.count.R |  | long |
| mongodb.status.locks.oplog.deadlock.count.W |  | long |
| mongodb.status.locks.oplog.deadlock.count.r |  | long |
| mongodb.status.locks.oplog.deadlock.count.w |  | long |
| mongodb.status.locks.oplog.wait.count.R |  | long |
| mongodb.status.locks.oplog.wait.count.W |  | long |
| mongodb.status.locks.oplog.wait.count.r |  | long |
| mongodb.status.locks.oplog.wait.count.w |  | long |
| mongodb.status.locks.oplog.wait.us.R |  | long |
| mongodb.status.locks.oplog.wait.us.W |  | long |
| mongodb.status.locks.oplog.wait.us.r |  | long |
| mongodb.status.locks.oplog.wait.us.w |  | long |
| mongodb.status.memory.bits | Either 64 or 32, depending on which target architecture was specified during the mongod compilation process. | long |
| mongodb.status.memory.mapped.mb | The amount of mapped memory, in megabytes (MB), used by the database. Because MongoDB uses memory-mapped files, this value is likely to be to be roughly equivalent to the total size of your database or databases. | long |
| mongodb.status.memory.mapped_with_journal.mb | The amount of mapped memory, in megabytes (MB), including the memory used for journaling. | long |
| mongodb.status.memory.resident.mb | The amount of RAM, in megabytes (MB), currently used by the database process. | long |
| mongodb.status.memory.virtual.mb | The amount, in megabytes (MB), of virtual memory used by the mongod process. | long |
| mongodb.status.network.in.bytes | The amount of network traffic, in bytes, received by this database. | long |
| mongodb.status.network.out.bytes | The amount of network traffic, in bytes, sent from this database. | long |
| mongodb.status.network.requests | The total number of requests received by the server. | long |
| mongodb.status.ops.counters.command | The total number of commands issued to the database since the mongod instance last started. | long |
| mongodb.status.ops.counters.delete | The total number of delete operations received since the mongod instance last started. | long |
| mongodb.status.ops.counters.getmore | The total number of getmore operations received since the mongod instance last started. | long |
| mongodb.status.ops.counters.insert | The total number of insert operations received since the mongod instance last started. | long |
| mongodb.status.ops.counters.query | The total number of queries received since the mongod instance last started. | long |
| mongodb.status.ops.counters.update | The total number of update operations received since the mongod instance last started. | long |
| mongodb.status.ops.latencies.commands.count | Total number of commands performed on the collection since startup. | long |
| mongodb.status.ops.latencies.commands.latency | Total combined latency in microseconds. | long |
| mongodb.status.ops.latencies.reads.count | Total number of read operations performed on the collection since startup. | long |
| mongodb.status.ops.latencies.reads.latency | Total combined latency in microseconds. | long |
| mongodb.status.ops.latencies.writes.count | Total number of write operations performed on the collection since startup. | long |
| mongodb.status.ops.latencies.writes.latency | Total combined latency in microseconds. | long |
| mongodb.status.ops.replicated.command | The total number of replicated commands issued to the database since the mongod instance last started. | long |
| mongodb.status.ops.replicated.delete | The total number of replicated delete operations received since the mongod instance last started. | long |
| mongodb.status.ops.replicated.getmore | The total number of replicated getmore operations received since the mongod instance last started. | long |
| mongodb.status.ops.replicated.insert | The total number of replicated insert operations received since the mongod instance last started. | long |
| mongodb.status.ops.replicated.query | The total number of replicated queries received since the mongod instance last started. | long |
| mongodb.status.ops.replicated.update | The total number of replicated update operations received since the mongod instance last started. | long |
| mongodb.status.storage_engine.name | A string that represents the name of the current storage engine. | keyword |
| mongodb.status.uptime.ms | Instance uptime in milliseconds. | long |
| mongodb.status.wired_tiger.cache.dirty.bytes | Size in bytes of the dirty data in the cache. | long |
| mongodb.status.wired_tiger.cache.maximum.bytes | Maximum cache size. | long |
| mongodb.status.wired_tiger.cache.pages.evicted | Number of pages evicted from the cache. | long |
| mongodb.status.wired_tiger.cache.pages.read | Number of pages read into the cache. | long |
| mongodb.status.wired_tiger.cache.pages.write | Number of pages written from the cache. | long |
| mongodb.status.wired_tiger.cache.used.bytes | Size in byte of the data currently in cache. | long |
| mongodb.status.wired_tiger.concurrent_transactions.read.available | Number of concurrent read tickets available. | long |
| mongodb.status.wired_tiger.concurrent_transactions.read.out | Number of concurrent read transaction in progress. | long |
| mongodb.status.wired_tiger.concurrent_transactions.read.total_tickets | Number of total read tickets. | long |
| mongodb.status.wired_tiger.concurrent_transactions.write.available | Number of concurrent write tickets available. | long |
| mongodb.status.wired_tiger.concurrent_transactions.write.out | Number of concurrent write transaction in progress. | long |
| mongodb.status.wired_tiger.concurrent_transactions.write.total_tickets | Number of total write tickets. | long |
| mongodb.status.wired_tiger.log.flushes | Number of flush operations. | long |
| mongodb.status.wired_tiger.log.max_file_size.bytes | Maximum file size. | long |
| mongodb.status.wired_tiger.log.scans | Number of scan operations. | long |
| mongodb.status.wired_tiger.log.size.bytes | Total log size in bytes. | long |
| mongodb.status.wired_tiger.log.syncs | Number of sync operations. | long |
| mongodb.status.wired_tiger.log.write.bytes | Number of bytes written into the log. | long |
| mongodb.status.wired_tiger.log.writes | Number of write operations. | long |
| mongodb.status.write_backs_queued | True when there are operations from a mongos instance queued for retrying. | boolean |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| service.address | Address of the machine where the service is running. | ip |
| service.version | Version of the service the data was collected from. This allows to look at a data set only for a specific version of a service. | keyword |

