# TSDB Guideline for Integration Developers

Important related resources:

- Meta [issue](https://github.com/elastic/integrations/issues/5233) with all migrated packages
- TSDB [test](https://github.com/elastic/TSDB-migration-test-kit) migration kit.

In this document you can find:

* [Background](#background)
* [Steps for migrating an existing package](#migration-steps)
* [Testing](#testing)
* [Best practices](#best-practices)
* [Troubleshooting](#troubleshooting)


# <a id="background"></a> Background

A time series is a sequence of observations for a specific entity. TSDB enables the column-oriented functionality in elasticsearch by co-locating the data and optimizing the storage and aggregations to take advantage of such co-allocation.

Integration is one of the biggest sources of input data to elasticsearch. Enabling TSDB on integration packages can be achieved by minimal changes made in `fields.yml` and `manifest.yml` files of a package.


# <a id="migration-steps"></a> Steps for migrating an existing package


> **Warning**: Datastream having type `logs` are excluded from TSDB migration.

    
### Step 1: Set the dimension fields

Each field belonging to the set of fields that uniquely identify a document is a dimension. You can read more details about dimensions [here](https://www.elastic.co/guide/en/elasticsearch/reference/current/tsds.html#time-series-dimension).

To set a field as dimension simply add `dimension: true` to its mapping:

```yaml
- name: ApiId
  type: keyword
  dimension: true
```

> **Note**: A field having type [flattened](https://www.elastic.co/guide/en/elasticsearch/reference/current/flattened.html) cannot be selected as a dimension field. If the field that you are choosing as a dimension is too long or is of type flattened, consider hashing the value of this field and using the result as a dimension. [Fingerprint processor](https://www.elastic.co/guide/en/elasticsearch/reference/current/fingerprint-processor.html) can be used for this purpose.
>
> You can find an example in [Oracle Integration TSDB Enablement Example](https://github.com/elastic/integrations/blob/8a57d6ba96d391afc33da20c80ec51280d22f009/packages/oracle/data_stream/performance/elasticsearch/ingest_pipeline/default.yml#LL127C4-L131C29)  

Important considerations:
- There is a limit on how many dimension fields a datastream can have. By default, this value is [21](https://github.com/elastic/elasticsearch/blob/6417a4f80f32ace48b8ad682ad46b19b57e49d60/server/src/main/java/org/elasticsearch/index/mapper/MapperService.java#L114)). You can adjust this restriction by altering the `index.mapping.dimension_fields.limit`:
```yaml
elasticsearch:
  index_template:
    settings:
      index.mapping.dimension_fields.limit: 32 # Defaults to 21
```
- Dimension _keys_ have a hard limit of 512b. Documents are rejected if this limit is reached.
- Dimension _values_ have a hard limit of 1024b. Documents are rejected if this limit is reached.

#### ECS fiels
There are fields that are part of every package, and they are potential candidates of becoming dimension fields:

* `host.name`
* `service.address`
* `agent.id`
* `container.id`
    
For products that are capable of running both on-premise and in a public cloud environment (by being deployed on public cloud virtual machines), it is recommended to annotate the ECS fields listed below as dimension fields:
* `host.name`
* `service.address`
* `container.id`
* `cloud.account.id`
* `cloud.provider`
* `cloud.region`
* `cloud.availability_zone`
* `agent.id`
* `cloud.instance.id`

For products operating as managed services within cloud providers like AWS, Azure, and GCP, it is advised to label the fields listed below as dimension fields.
* `cloud.account.id`
* `cloud.region`
* `cloud.availability_zone`
* `cloud.provider`
* `agent.id `

Note that for some packages some of these fields do not hold any value, so make sure to only use the needed ones.
    

#### Integration specific fields

`files.yml` file has the field mappings specific to a datastream of an integration. Some of these fields might need to be set as dimension if the set of dimension fields in ECS is not enough to create a unique [_tsid](https://www.elastic.co/guide/en/elasticsearch/reference/current/tsds.html#tsid).

Adding an inline comment prior to the dimension annotation is advised, detailing the rationale behind the choice of a particular field as a dimension field.

    ```
    - name: wait_class
      type: keyword
      # Multiple events are generated based on the values of wait_class. Hence, it is a dimension
      dimension: true
      description: Every wait event belongs to a class of wait events.
    ```

### Step 2: Set type for metric fields

Metrics are fields that contain numeric measurements, as well as aggregations and/or down sampling values based off of those measurements. Annotate each metric with the correct metric type. The [currently supported](https://www.elastic.co/guide/en/elasticsearch/reference/current/tsds.html#time-series-metric) values are `gauge`, `counter` and `null`.

Example of adding a metric type to a field: 

```yaml
- name: compactions_failed
  type: double
  metric_type: counter
  description: |
    Counter of TSM compactions by level that have failed due to error.
```
> **Note**: Some of the aggregation functions are not supported for certain metric_type. In such a scenario, please revisit to see if the selection of metric_type you made is indeed correct for that field. If valid, please create an issue under elastic/elasticsearch explaining the use case.

### Step 3: Update Kibana version

Modify the `kibana.version` to at least `8.8.0` within the `manifest.yml` file of the package:
```yaml
conditions:
 kibana.version: "^8.8.0"
```

### Step 4: Enable `time_series` index mode

Add the changes to the `manifest.yml` file of the datastream as below to enable the timeseries index mode:
```yaml
elasticsearch:
  index_mode: "time_series"
```



# <a id="testing"></a> Testing

- If the number of dimensions is insufficient, we will have loss of data. Consider testing this using the [TSDB migration test kit](https://github.com/elastic/TSDB-migration-test-kit).
 
- Verify the dashboard is rendering the data properly. If certain visualisation do not work, consider migrating to [Lens](https://www.elastic.co/guide/en/kibana/current/lens.html). Remember that certain aggregation functions are not supported when a field has metric type `counter`. Example `avg()`. Replace such aggregation functions with a supported aggregation type such as `max()` or `min()`.


# <a id="best-practices"></a> Best practices

- Use [Lens](https://www.elastic.co/guide/en/kibana/current/lens.html) as the preferred visualisation type.  

- Always assess the number of unique values the field that is selected to be dimension would hold, especially if it is a numeric field.  
A field that holds millions of unique values may not be an ideal candidate for becoming a dimension field.

- If the dimension field value length is very long (max limit is 1024B), consider transforming the value to hash value representation. [Fingerprint processor](https://www.elastic.co/guide/en/elasticsearch/reference/current/fingerprint-processor.html) can be used for this purpose.

- In the field mapping files above each dimension field, add in-line comments stating the reason for selecting the field as a dimension field.

- As part of TSDB migration testing, you may discover other errors which may be unrelated to TSDB migration. Keep the PR for TSDB migration free from such changes. This helps in obtaining quick PR approval.


# <a id="troubleshooting"></a> Troubleshooting

### Conflicting field type

Fields having conflicting field type will not be considered as dimension. Resolve the field type ambiguity before defining a field as dimension field.

### Identification of write index

When mappings are modified for a datastream, index rollover happens and a new index is created under the datastream. Even if there exists a new index, the data continues to go to the old index until the timestamp matches `index.time_series.start_time` of the newly created index.  

An enhancement [request](https://github.com/elastic/kibana/issues/150549) for Kibana is created to indicate the write index. Until then, refer to the `index.time_series.start_time` of indices and compare with the current time to identify the write index. 

If you find this error (references [this issue](https://github.com/elastic/integrations/issues/7345) and [this PR](https://github.com/elastic/elasticsearch/pull/98518)):

```console
... (status=400): {"type":"illegal_argument_exception","reason":"the document timestamp [2023-08-07T00:00:00.000Z] is outside of ranges of currently writable indices [[2023-08-07T08:55:38.000Z,2023-08-07T12:55:38.000Z]]"}, dropping event!
```

Consider:
1. Defining the `look_ahead` or `look_back_time` for each data stream. Example:
```yaml
elasticsearch:
  index_mode: "time_series"
  index_template:
    settings:
      index.look_ahead_time: "10h"
```
> **Note**: Updating the package with this does not cause an automatic rollover on the data stream. You have to do that manually. 
2. Updating the `timestamp` of the document being rejected.
3. Finding a fix to receive the document without a delay.

