# Goals

This document summarizes the history of subobjects, the motivation for adding the option, and recommended steps to guide integration users and developers in using it.

## Overview

[subobjects](https://www.elastic.co/guide/en/elasticsearch/reference/8.13/subobjects.html) is a mapping parameter that controls the configuration of the object mapper (root as well as individual fields), making it possible to store logs and metrics documents that have fields with dots in their names.

For example:

```json
{
  "metrics.time" : 10,
  "metrics.time.min" : 1,
  "metrics.time.max" : 500
}
```

This document shares how to start using subobjects in integrations.

## History

### Elasticsearch

In early 2022, Elasticsearch v8.3 [introduced](https://github.com/elastic/elasticsearch/pull/86166) the subobjects mapping parameter, which added support for dots in field names for metrics use cases.

The subobjects mapping parameter made it possible to store metrics data with fields in the metric names:

```json
{
  "metrics.time" : 10,
  "metrics.time.min" : 1,
  "metrics.time.max" : 500
}
```

The subobjects parameter controls whether an object can hold other objects (defaults to true) or not.

#### Use outside integrations

We started using it in support requests to address problems in the metrics space caused by dots in field names.

### Integrations

By the end of 2023, we started [adding support for the subobjects](https://github.com/elastic/package-spec/issues/349) mapping parameter to package-spec and Kibana.

When the last requirement was merged in Elasticsearch, we added support for per-field subobjects in stack 8.13 and per data stream in stack 8.14. 

### High-level Overview

The default value for subobjects is true, so Elasticsearch turns fields with dots in their names into an object tree.

#### Field vs. Data Stream

Users can set the subobjects mapping parameter on a single field or for the whole data stream (root level).

#### Per field

You can start small by disabling subobjects on a single field.

```yaml
- name: tags.*
  type: object
  object_type: keyword
  object_type_mapping_type: "*"
  subobjects: false
  description: >
    Azure resource tags.
```

Adding subobjects to a field definition is a great option for dealing with a field with dots in its name (like metric names or tag names from cloud providers) on existing data streams. The scope of the change is limited to that field.

#### Per data stream

You can also disable subobjects at the root level on the whole data stream.

```yaml
title: Example
type: logs
elasticsearch:
  index_template:
    mappings:
      subobjects: false
```

If you have to deal with inconsistent data from your data source, consider using subobjects: false on the whole data stream. See the example below about indexing `{"host": "foo"}` and `{"host": {"name": "bar"}}` in the same data stream.

Read the "Considerations on disabling subobjects" below to learn about a few restrictions that apply when you set subobjects to false.


## Availability

### Per field
#### Requirements

- Stack version: 8.13
- package-spec version: 3.1.0

For more information, see the following:
- https://github.com/elastic/kibana/pull/171826
- https://github.com/elastic/package-spec/pull/573 

#### Recommendations

Consider upgrading to the recent package-spec according to your minimum stack requirements. The benefits (especially additional checks that elastic-package delivers) outweigh the costs.

#### Examples

Here is how you can use the subobjects parameter on a single field.

For example, if you send the following document to the `metrics-azure.storage_account-default` data stream:

```json
{
    "azure": {
        "subscription_id": "70bd6e77-4b1e-4835-8896-db77b8eef364",
        "timegrain": "PT1H",
        "resource": {
            "name": "blobtestobs",
            "id": "/subscriptions/..../Microsoft.Storage/storageAccounts/blobtestobs",
            "type": "Microsoft.Storage/storageAccounts",
            "tags": {
                "a.b.c": "value1"
            }
        }
    }
}
```

Using the typical pre-subobjects definition for the `azure.resource.tags` field:

```yaml
# packages/azure_metrics/data_stream/storage_account/fields/package-fields.yml

- name: tags.*
  type: object
  object_type: keyword
  object_type_mapping_type: "*"
  description: >
    Azure resource tags.
```

You would get the following error:

```json
{
  "error": {
    "root_cause": [
      {
        "type": "document_parsing_exception",
        "reason": "[1:1553] failed to parse field [azure.resource.tags.a] of type [keyword] in a time series document at [2024-04-02T13:19:38.000Z]. Preview of field's value: '{b={c=value-1}}'"
      }
    ],
    "type": "document_parsing_exception",
    "reason": "[1:1553] failed to parse field [azure.resource.tags.a] of type [keyword] in a time series document at [2024-04-02T13:19:38.000Z]. Preview of field's value: '{b={c=value-1}}'",
    "caused_by": {
      "type": "illegal_state_exception",
      "reason": "Can't get text on a START_OBJECT at 1:1545"
    }
  },
  "status": 400
}
```


In this case, you can disable subobjects for `azure.resource.tags` only by adding the mapping parameter: 

```yaml
# packages/azure_metrics/data_stream/storage_account/fields/package-fields.yml

- name: tags.*
  type: object
  object_type: keyword
  object_type_mapping_type: "*"
  subobjects: false
  description: >
    Azure resource tags.
```

### Per Data Stream
#### Requirements

- Stack version: 8.14
- package-spec version: 3.2.0

When the last requirement was merged in Elasticsearch, we added support for subobjects (per data stream) in stack 8.14. For more information, see https://github.com/elastic/package-spec/pull/727. 

#### Example

Here is how you can use the subobjects parameter on a the whole data stream:

```yaml
# packages/example/data_stream/logs/manifest.yml

title: Example
type: logs
elasticsearch:
  index_template:
    mappings:
      subobjects: false
```

##### How to handle inconsistent data coming into the data stream

Suppose we have a data stream, and a user sends the following two documents to index.

First document, `host` is a string.

```json
{
  "@timestamp": "2024-03-13T12:12:31+01:00",
  "host": "foo"
}
```

Second document, `host` is an object.

```json
{
  "@timestamp": "2024-03-13T12:12:31+01:00",
  "host": {
    "name": "bar"
  }
}
```

Let’s explore how using subobjects changes how Elasticsearch handles these inconsistencies.

###### With subobjects: true (default)

To test the subobjects: true case, we create the following index template:

```json
PUT _index_template/metrics-subobjects-true
{
  "priority": 200,
  "template": {
    "mappings": {
      "_routing": {
        "required": false
      },
      "numeric_detection": false,
      "dynamic_date_formats": [
        "strict_date_optional_time",
        "yyyy/MM/dd HH:mm:ss Z||yyyy/MM/dd Z"
      ],
      "dynamic": true,
      "_source": {
        "excludes": [],
        "includes": [],
        "enabled": true
      },
      "date_detection": false,
      "subobjects": true
    }
  },
  "index_patterns": [
    "metrics-subobjects.true-*"
  ],
  "data_stream": {
    "hidden": false,
    "allow_custom_routing": false,
    "failure_store": false
  },
  "composed_of": [],
  "allow_auto_create": true
}
```


If we try to index the first test document:

```
POST metrics-subobjects.true-default/_doc
{
  "@timestamp": "2024-03-13T12:12:31+01:00",
  "host": "foo"
}
```

We get the following response:

```json
{
  "_index": ".ds-metrics-subobjects.true-default-2024.05.15-000001",
  "_id": "TCrae48BtqIOnQ4ld86W",
  "_version": 1,
  "result": "created",
  "_shards": {
    "total": 2,
    "successful": 1,
    "failed": 0
  },
  "_seq_no": 0,
  "_primary_term": 1
}
```

Elasticsearch successfully indexes the document.

If we try to index the second test document:

```json
POST metrics-subobjects.true-default/_doc
{
  "@timestamp": "2024-03-13T12:12:31+01:00",
  "host": {
    "name": "bar"
  }
}
```

We get the following response:

```
{
  "error": {
    "root_cause": [
      {
        "type": "document_parsing_exception",
        "reason": "[5:3] failed to parse field [host] of type [text] in document with id 'Xirbe48BtqIOnQ4l1M6N'. Preview of field's value: '{name=bar}'"
      }
    ],
    "type": "document_parsing_exception",
    "reason": "[5:3] failed to parse field [host] of type [text] in document with id 'Xirbe48BtqIOnQ4l1M6N'. Preview of field's value: '{name=bar}'",
    "caused_by": {
      "type": "illegal_state_exception",
      "reason": "Can't get text on a START_OBJECT at 3:11"
    }
  },
  "status": 400
}
```

During the indexing of the first document, Elasticsearch created a dynamic mapping that is not compatible with the second document:

```json
GET metrics-subobjects.true-default/_mapping/field/host
{
  ".ds-metrics-subobjects.true-default-2024.05.15-000001": {
    "mappings": {
      "host": {
        "full_name": "host",
        "mapping": {
          "host": {
            "type": "text",
            "fields": {
              "keyword": {
                "type": "keyword",
                "ignore_above": 256
              }
            }
          }
        }
      }
    }
  }
}
```

Let’s now see how setting subobjects to false can improve this scenario.

###### With subobjects: false

To test the subobjects: false case, we create another index template:

```
PUT _index_template/metrics-subobjects-false
{
  "priority": 200,
  "template": {
    "mappings": {
      "_routing": {
        "required": false
      },
      "numeric_detection": false,
      "dynamic_date_formats": [
        "strict_date_optional_time",
        "yyyy/MM/dd HH:mm:ss Z||yyyy/MM/dd Z"
      ],
      "dynamic": true,
      "_source": {
        "excludes": [],
        "includes": [],
        "enabled": true
      },
      "date_detection": false,
      "subobjects": false
    }
  },
  "index_patterns": [
    "metrics-subobjects.false-*"
  ],
  "data_stream": {
    "hidden": false,
    "allow_custom_routing": false,
    "failure_store": false
  },
  "composed_of": [],
  "allow_auto_create": true
}
```

If we try to index our first test document:

```json
POST metrics-subobjects.false-default/_doc
{
  "@timestamp": "2024-03-13T12:12:31+01:00",
  "host": "foo"
}
```

We get the following successful response:

```json
{
  "_index": ".ds-metrics-subobjects.false-default-2024.05.15-000001",
  "_id": "oSrge48BtqIOnQ4lnc7t",
  "_version": 1,
  "result": "created",
  "_shards": {
    "total": 2,
    "successful": 1,
    "failed": 0
  },
  "_seq_no": 0,
  "_primary_term": 1
}
```

If we try to index the second test document:

```json
POST metrics-subobjects.false-default/_doc
{
  "@timestamp": "2024-03-13T12:12:31+01:00",
  "host": {
    "name": "bar"
  }
}
```

This time Elasticsearch is able to index the document:

```json
{
  "_index": ".ds-metrics-subobjects.false-default-2024.05.15-000001",
  "_id": "tirie48BtqIOnQ4lLM6X",
  "_version": 1,
  "result": "created",
  "_shards": {
    "total": 2,
    "successful": 1,
    "failed": 0
  },
  "_seq_no": 1,
  "_primary_term": 1
}
```

Here are what the two documents look like in a search response:

```json
GET metrics-subobjects.false-default/_search

{
  "took": 1,
  "timed_out": false,
  "_shards": {
    "total": 1,
    "successful": 1,
    "skipped": 0,
    "failed": 0
  },
  "hits": {
    "total": {
      "value": 2,
      "relation": "eq"
    },
    "max_score": 1,
    "hits": [
      {
        "_index": ".ds-metrics-subobjects.false-default-2024.05.15-000001",
        "_id": "oSrge48BtqIOnQ4lnc7t",
        "_score": 1,
        "_source": {
          "@timestamp": "2024-03-13T12:12:31+01:00",
          "host": "foo"
        }
      },
      {
        "_index": ".ds-metrics-subobjects.false-default-2024.05.15-000001",
        "_id": "tirie48BtqIOnQ4lLM6X",
        "_score": 1,
        "_source": {
          "@timestamp": "2024-03-13T12:12:31+01:00",
          "host": {
            "name": "bar"
          }
        }
      }
    ]
  }
}
```


## Considerations on disabling subobjects
Before disabling subobjects, consider the following implications:

- Nested field types cannot be used in data streams.
- The subobjects mapping definition is immutable.
- This setting depends on auto-flattening mappings, which have limitations for integration and custom mappings in data streams without subobjects:
    - The enabled mapping parameter must not be false.
    - The dynamic mapping parameter must not contradict the implicit or explicit value of the parent. For example, when dynamic is set to false in the root of the mapping, object mappers that set dynamic to true can’t be auto-flattened.
    - The subobjects mapping parameter must not be set to true explicitly.

