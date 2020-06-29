# PostgreSQL Integration

This integration periodically fetches logs and metrics from [PostgreSQL](https://www.postgresql.org/) servers.

## Compatibility

The `log` dataset was tested with logs from versions 9.5 on Ubuntu, 9.6 on Debian, and finally 10.11, 11.4 and 12.2 on Arch Linux 9.3.

The `activity`, `bgwriter`, `database` and `statement` datasets were tested with PostgreSQL 9.5.3 and is expected to work with all versions >= 9.

## Logs

### log

The `log` dataset collects the PostgreSQL logs.

{{fields "log"}}

## Metrics

### activity

The `activity` dataset periodically fetches metrics from PostgreSQL servers.

An example event for `activity` looks as following:

```$json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "agent": {
        "hostname": "host.example.com",
        "name": "host.example.com"
    },
    "event": {
        "dataset": "postgresql.activity",
        "duration": 115000,
        "module": "postgresql"
    },
    "metricset": {
        "name": "activity"
    },
    "postgresql": {
        "activity": {
            "application_name": "",
            "backend_start": "2019-03-05T08:38:21.348Z",
            "client": {
                "address": "172.26.0.1",
                "hostname": "",
                "port": 41582
            },
            "database": {
                "name": "postgres",
                "oid": 12379
            },
            "pid": 347,
            "query": "SELECT * FROM pg_stat_activity",
            "query_start": "2019-03-05T08:38:21.352Z",
            "state": "active",
            "state_change": "2019-03-05T08:38:21.352Z",
            "transaction_start": "2019-03-05T08:38:21.352Z",
            "user": {
                "id": 10,
                "name": "postgres"
            },
            "waiting": false
        }
    },
    "service": {
        "address": "172.26.0.2:5432",
        "type": "postgresql"
    }
}
```

The fields reported are:

{{fields "activity"}}

### bgwriter

The PostgreSQL `bgwriter` dataset collects data from PostgreSQL by running a `SELECT * FROM pg_stat_bgwriter;` SQL query.

An example event for `bgwriter` looks as following:

```$json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "agent": {
        "hostname": "host.example.com",
        "name": "host.example.com"
    },
    "event": {
        "dataset": "postgresql.bgwriter",
        "duration": 115000,
        "module": "postgresql"
    },
    "metricset": {
        "name": "bgwriter"
    },
    "postgresql": {
        "bgwriter": {
            "buffers": {
                "allocated": 143,
                "backend": 0,
                "backend_fsync": 0,
                "checkpoints": 0,
                "clean": 0,
                "clean_full": 0
            },
            "checkpoints": {
                "requested": 0,
                "scheduled": 1,
                "times": {
                    "sync": {
                        "ms": 0
                    },
                    "write": {
                        "ms": 0
                    }
                }
            },
            "stats_reset": "2019-03-05T08:32:30.028Z"
        }
    },
    "service": {
        "address": "172.26.0.2:5432",
        "type": "postgresql"
    }
}
```

The fields reported are:

{{fields "bgwriter"}}

### database

The `database` dataset periodically fetches metrics from PostgreSQL servers.

An example event for `database` looks as following:

```$json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "beat": {
        "hostname": "host.example.com",
        "name": "host.example.com"
    },
    "metricset": {
        "host": "postgresql:5432",
        "module": "postgresql",
        "name": "database",
        "rtt": 115
    },
    "postgresql": {
        "database": {
            "blocks": {
                "hit": 0,
                "read": 0,
                "time": {
                    "read": {
                        "ms": 0
                    },
                    "write": {
                        "ms": 0
                    }
                }
            },
            "conflicts": 0,
            "deadlocks": 0,
            "name": "template1",
            "number_of_backends": 0,
            "oid": 1,
            "rows": {
                "deleted": 0,
                "fetched": 0,
                "inserted": 0,
                "returned": 0,
                "updated": 0
            },
            "temporary": {
                "bytes": 0,
                "files": 0
            },
            "transactions": {
                "commit": 0,
                "rollback": 0
            }
        }
    }
}
```

The fields reported are:

{{fields "database"}}

### statement

The `statement` dataset periodically fetches metrics from PostgreSQL servers.

An example event for `statement` looks as following:

```$json
{
    "@timestamp": "2017-10-12T08:05:34.853Z",
    "agent": {
        "hostname": "host.example.com",
        "name": "host.example.com"
    },
    "event": {
        "dataset": "postgresql.statement",
        "duration": 115000,
        "module": "postgresql"
    },
    "metricset": {
        "name": "statement"
    },
    "postgresql": {
        "statement": {
            "database": {
                "oid": 12379
            },
            "query": {
                "calls": 2,
                "id": "1592910677",
                "memory": {
                    "local": {
                        "dirtied": 0,
                        "hit": 0,
                        "read": 0,
                        "written": 0
                    },
                    "shared": {
                        "dirtied": 0,
                        "hit": 0,
                        "read": 0,
                        "written": 0
                    },
                    "temp": {
                        "read": 0,
                        "written": 0
                    }
                },
                "rows": 3,
                "text": "SELECT * FROM pg_stat_statements",
                "time": {
                    "max": {
                        "ms": 0.388
                    },
                    "mean": {
                        "ms": 0.235
                    },
                    "min": {
                        "ms": 0.082
                    },
                    "stddev": {
                        "ms": 0.153
                    },
                    "total": {
                        "ms": 0.47000000000000003
                    }
                }
            },
            "user": {
                "id": 10
            }
        }
    },
    "service": {
        "address": "172.26.0.2:5432",
        "type": "postgresql"
    }
}
```

The fields reported are:

{{fields "statement"}}
