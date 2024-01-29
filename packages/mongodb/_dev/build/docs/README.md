# MongoDB Integration

This integration is used to fetch logs and metrics from [MongoDB](https://www.mongodb.com/).

## Compatibility

The `log` dataset is tested with logs from versions v3.2.11 and v4.4.4 in
plaintext and json formats.
The `collstats`, `dbstats`, `metrics`, `replstatus` and `status` datasets are 
tested with MongoDB 5.0 and are expected to work with all versions >= 5.0.

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

{{event "log"}}

The fields reported are:

{{fields "log"}}

## Metrics

### collstats

The `collstats` dataset uses the top administrative command to return usage 
statistics for each collection. It provides the amount of time, in microseconds,
used and a count of operations for the following types: total, readLock, writeLock,
queries, getmore, insert, update, remove, and commands.

It requires the following privileges, which is covered by the [clusterMonitor](https://docs.mongodb.com/manual/reference/built-in-roles/#clusterMonitor) role:

* [top action](https://docs.mongodb.com/manual/reference/privilege-actions/#top) on [cluster resource](https://docs.mongodb.com/manual/reference/resource-document/#cluster-resource)

{{event "collstats"}}

The fields reported are:

{{fields "collstats"}}

### dbstats

The `dbstats` dataset collects storage statistics for a given database. 

It requires the following privileges, which is covered by the [clusterMonitor](https://docs.mongodb.com/manual/reference/built-in-roles/#clusterMonitor) role:

* [listDatabases](https://docs.mongodb.com/manual/reference/privilege-actions/#listDatabases) 
action on [cluster resource](https://docs.mongodb.com/manual/reference/resource-document/#cluster-resource)

* for each of the databases, also need [dbStats](https://docs.mongodb.com/manual/reference/privilege-actions/#dbStats)
action on the [database resource](https://docs.mongodb.com/manual/reference/resource-document/#database-and-or-collection-resource)

{{event "dbstats"}}

The fields reported are:

{{fields "dbstats"}}

### metrics

It requires the following privileges, which is covered by the clusterMonitor role:

* [serverStatus](https://docs.mongodb.com/manual/reference/privilege-actions/#serverStatus) 
action on [cluster resource](https://docs.mongodb.com/manual/reference/resource-document/#cluster-resource)

{{event "metrics"}}

The fields reported are:

{{fields "metrics"}}

### replstatus
The `replstatus` dataset collects status of the replica set.
It requires the following privileges, which is covered by the [clusterMonitor](https://docs.mongodb.com/manual/reference/built-in-roles/#clusterMonitor) role:

* [find/listCollections](https://docs.mongodb.com/manual/reference/privilege-actions/#find) action on the [local database](https://docs.mongodb.com/manual/reference/local-database/) resource
* [collStats](https://docs.mongodb.com/manual/reference/privilege-actions/#collStats) action on the [local.oplog.rs](https://docs.mongodb.com/manual/reference/local-database/#local.oplog.rs) collection resource
* [replSetGetStatus](https://docs.mongodb.com/manual/reference/privilege-actions/#replSetGetStatus) action on [cluster resource](https://docs.mongodb.com/manual/reference/resource-document/#cluster-resource)

{{event "replstatus"}}

The fields reported are:

{{fields "replstatus"}}

### status

The `status` returns a document that provides an overview of the database's state.

It requires the following privileges, which is covered by the [clusterMonitor](https://docs.mongodb.com/manual/reference/built-in-roles/#clusterMonitor) role:

* [serverStatus](https://docs.mongodb.com/manual/reference/privilege-actions/#serverStatus) 
action on [cluster resource](https://docs.mongodb.com/manual/reference/resource-document/#cluster-resource)

{{event "status"}}

The fields reported are:

{{fields "status"}}
