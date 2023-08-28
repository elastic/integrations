# PHP-FPM Integration

## Overview

PHP-FPM (FastCGI Process Manager) is a web tool used to speed up the performance of a website. It is much faster than traditional CGI based methods and has the ability to handle tremendous loads simultaneously.

## Data streams

The PHP-FPM integration collects metrics data.

Metrics give you insight into the statistics of the PHP-FPM. Metrics data streams collected by the PHP-FPM integration include [pool](https://www.php.net/manual/en/fpm.status.php#:~:text=Basic%20information%20%2D%20Always%20displayed%20on%20the%20status%20page) and [process](https://www.php.net/manual/en/fpm.status.php#:~:text=Per%2Dprocess%20information%20%2D%20only%20displayed%20in%20full%20output%20mode) so that the user can monitor and troubleshoot the performance of the PHP-FPM instances.

Note:
- Users can monitor and see the metrics inside the ingested documents for PHP-FPM in the logs-* index pattern from `Discover`.

## Compatibility

This integration has been tested against `v8.2` and `v8.1` standalone versions of PHP-FPM.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

In order to ingest data from PHP-FPM, you must know the host(s) and status path of the PHP-FPM instance.

Host configuration format: `http[s]://host[:port]`

Example host configuration: `http://localhost:8080`

Status path configuration format: `/path`

Example Status path configuration: `/status` 

### Troubleshooting

If host.ip is shown conflicted under ``logs-*`` data view, then this issue can be solved by reindexing the ``Pool`` and ``Process`` data stream's indices.
To reindex the data, the following steps must be performed.

1. Stop the data stream by going to `Integrations -> PHP-FPM -> Integration policies` open the configuration of PHP-FPM and disable the `Collect PHP-FPM metrics` toggle to reindex metrics data stream and save the integration.

2. Copy data into the temporary index and delete the existing data stream and index template by performing the following steps in the Dev tools.

```
POST _reindex
{
  "source": {
    "index": "<index_name>"
  },
  "dest": {
    "index": "temp_index"
  }
}  
```
Example:
```
POST _reindex
{
  "source": {
    "index": "logs-php_fpm.pool-default"
  },
  "dest": {
    "index": "temp_index"
  }
}
```

```
DELETE /_data_stream/<data_stream>
```
Example:
```
DELETE /_data_stream/logs-php_fpm.pool-default
```

```
DELETE _index_template/<index_template>
```
Example:
```
DELETE _index_template/logs-php_fpm.pool
```
3. Go to `Integrations -> PHP-FPM -> Settings` and click on `Reinstall PHP-FPM`.

4. Copy data from temporary index to new index by performing the following steps in the Dev tools.

```
POST _reindex
{
  "conflicts": "proceed",
  "source": {
    "index": "temp_index"
  },
  "dest": {
    "index": "<index_name>",
    "op_type": "create"

  }
}
```
Example:
```
POST _reindex
{
  "conflicts": "proceed",
  "source": {
    "index": "temp_index"
  },
  "dest": {
    "index": "logs-php_fpm.pool-default",
    "op_type": "create"

  }
}
```

5. Verify data is reindexed completely.

6. Start the data stream by going to the `Integrations -> PHP-FPM -> Integration policies` and open configuration of integration and enable the `Collect PHP-FPM metrics` toggle and save the integration.

7. Delete temporary index by performing the following step in the Dev tools.

```
DELETE temp_index
```

More details about reindexing can be found [here](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-reindex.html).

## Metrics reference

### Pool

This is the `pool` data stream. `pool` data stream collects metrics related to the setup and contents of the FPM status page.

{{event "pool"}}

{{fields "pool"}}

### Process

This is the `process` data stream. `process` data stream collects metrics like request duration, content length, process state, etc.

{{event "process"}}

{{fields "process"}}