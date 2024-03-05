# Redis Integration

This integration periodically fetches logs and metrics from [https://redis.io/](Redis) servers.

## Compatibility

The `log` and `slowlog` datasets were tested with logs from Redis versions 1.2.6, 2.4.6, and 3.0.2, so we expect
compatibility with any version 1.x, 2.x, or 3.x.

The `info`, `key` and `keyspace` datasets were tested with Redis 3.2.12, 4.0.11 and 5.0-rc4, and are expected to work
with all versions >= 3.0.

## Logs

### log

The `log` dataset collects the Redis standard logs.

{{fields "log"}}

### slowlog

The `slowlog` dataset collects the Redis slow logs.

{{fields "log"}}

## Metrics

### info

The `info` dataset collects information and statistics from Redis by running the `INFO` command and parsing the returned
result.

An example event for `info` looks as following:

```$json
TODO
```

The fields reported are:

{{fields "info"}}

### key

The `key` dataset collects information about Redis keys.

For each key matching one of the configured patterns, an event is sent to Elasticsearch with information about this key,
what includes the type, its length when available, and its TTL.

Patterns are configured as a list containing these fields:

* `pattern` (required): pattern for key names, as accepted by the Redis KEYS or SCAN commands.
* `limit` (optional): safeguard when using patterns with wildcards to avoid collecting too many keys (Default: 0, no limit)
* `keyspace` (optional): Identifier of the database to use to look for the keys (Default: 0)

An example event for `key` looks as following:

```$json
TODO
```

The fields reported are:

{{fields "key"}}

### keyspace

The `keyspace` dataset collects information about the Redis keyspaces. For each keyspace, an event is sent to
Elasticsearch. The keyspace information is fetched from the `INFO` command.

An example event for `keyspace` looks as following:

```$json
TODO
```

The fields reported are:

{{fields "keyspace"}}
