# TSDB Guideline for Integration Developers

* [Background](#background)
* [Steps for migrating an existing package](#migration-steps)
* [Testing](#testing)
* [Best practices](#best-practices)
* [Troubleshooting](#troubleshooting)
* [Known issues](#known-issues)
* [Reference to existing package already migrated](#existing-migrated-packages)


# <a id="background"></a> Background

A time series is a sequence of observations for a specific entity. TSDB enables the column-oriented functionality in elasticsearch by co-locating the data and optimizing the storage and aggregations to take advantage of such co-allocation.

Integration is one of the biggest sources of input data to elasticsearch. Enabling TSDB on integration packages can be achieved by minimal changes made in `fields.yml` and `manifest.yml` files of a package.


# <a id="migration-steps"></a> Steps for migrating an existing package


1. **Datastream having type `logs` can be excluded from TSDB migration.**
2. **Add the changes to the manifest.yml file of the datastream as below to enable the timeseries index mode**
    ```
    elasticsearch:
      index_mode: "time_series"
    ```
    If your datastream has more number of dimension fields, you can modify this limit by modifying index.mapping.dimension_fields.limit value as below
    ```
    elasticsearch:
      index_mode: "time_series"
      index_template:
       settings:
         # Defaults to 16
         index.mapping.dimension_fields.limit: 32
    ```
3. **Identifying the dimensions in the datastream.** 

    Read about dimension fields [here](https://www.elastic.co/guide/en/elasticsearch/reference/current/tsds.html#time-series-dimension). It is important that dimensions or a set of dimensions that are part of a datastream uniquely identify a timeseries. Dimensions are used to form _tsid which then is used for routing and index sorting. Read about the ways to add field a dimension [here](https://github.com/elastic/integrations/blob/main/docs/generic_guidelines.md#specify-dimensions])

    A field having type [flattened](https://www.elastic.co/guide/en/elasticsearch/reference/current/flattened.html) cannot be selected as a dimension field. If the field that you are choosing as a dimension is too long or is of type flattened , consider the option of hashing the value of this field, creating a new dimension field to hold this value  . [Fingerprint processor](https://www.elastic.co/guide/en/elasticsearch/reference/current/fingerprint-processor.html) can be used for this purpose.  
    
    Reference :  [Oracle Integration TSDB Enablement Example](https://github.com/elastic/integrations/blob/8a57d6ba96d391afc33da20c80ec51280d22f009/packages/oracle/data_stream/performance/elasticsearch/ingest_pipeline/default.yml#LL127C4-L131C29)  

3. **Annotating the ECS fields as dimension.**

    From the context of integrations that are related to products that are deployed on-premise, there exist certain fields that are part of every package and they are potential candidates of becoming dimension fields

    * host.ip
    * service.address
    * agent.id
    
    When metrics are collected from a resource running in the cloud or in a container, certain fields are potential candidates of becoming dimension fields  

    * host.ip
    * service.address
    * agent.id
    * cloud.project.id
    * cloud.instance.id
    * cloud.provider
    * container.id  

    *Warning: Choosing an insufficient number of dimension fields may lead to data loss*  

    *Hint: Fields having type [keyword](https://www.elastic.co/guide/en/elasticsearch/reference/current/keyword.html#keyword-field-type) in your datastream are very good candidates of becoming dimension fields*


4. **Annotating the integration specific fields as dimension**

    `files.yml` file has the field mappings specific to a datastream of an integration. This step is needed when the dimension fields in ECS is not sufficient enough to create a unique [_tsid](https://www.elastic.co/guide/en/elasticsearch/reference/current/tsds.html#tsid) value for the documents stored in elasticsearch. Annotate the field with `dimension: true` to tag the field as dimension field. 

    ```
    - name: wait_class
      type: keyword
      description: Every wait event belongs to a class of wait events.
      dimension: true
    ```
    *Notes:*
    * *There exists a limit on how many dimension fields can have. By default this value is 16. Out of this, 8 are reserved for ecs fields.*
    * *Dimension keys have a hard limit of 512b. Documents are rejected if this limit is reached.*
    * *Dimension values have a hard limit of 1024b. Documents are rejected if this limit is reached*


5. **Annotating Metric Types values for all applicable fields** 

    Metrics are fields that contain numeric measurements, as well as aggregations and/or downsampling values based off of those measurements. 

    Annotate fields using appropriate metric_type wherever applicable. `counter` and `gauge` are the currently supported values for [metric_type](https://www.elastic.co/guide/en/elasticsearch/reference/master/mapping-field-meta.html).  

    More details regarding metric_type can be found [here](https://www.elastic.co/guide/en/elasticsearch/reference/current/tsds.html#time-series-metric)

    Example on adding metric_type to field mapping. 

    ```
    - name: compactions_failed
      type: double
      metric_type: counter
      description: |
        Counter of TSM compactions by level that have failed due to error.
    ```
    *Note: It may be possible that some of the aggregation functions are not supported for certain metric_type. In such a scenario, please revisit to see if the selection of metric_type you made is indeed correct for that field. If valid, please create an issue under elastic/elasticsearch explaining the use case.*  

# <a id="testing"></a> Testing
 
- After migration, verify if the dashboard is rendering the data properly. If certain visualisation do not work, consider migrating to [Lens](https://www.elastic.co/guide/en/kibana/current/lens.html)

  Certain aggregation functions are not supported when a field is having a metric_type ‘counter’. Example avg(). Replace such aggregation functions with a supported aggregation type such as max(). 

- It is recommended to compare the number of documents within a certain time frame before enabling the TSDB and after enabling TSDB index mode. If the count differs, please check if there exists a field that is not annotated as dimension field.  


# <a id="best-practices"></a> Best practices

- Use [Lens](https://www.elastic.co/guide/en/kibana/current/lens.html) as the preferred visualisation type.  

- Always assess the number of unique values the field that is selected to be dimension would hold, especially if it is a numeric field.  
A field that holds millions of unique values may not be an ideal candidate for becoming a dimension field.
- If the dimension field value length is very long (max limit is 1024B), consider transforming the value to hash value representation. [Fingerprint processor](https://www.elastic.co/guide/en/elasticsearch/reference/current/fingerprint-processor.html) can be used for this purpose.
- In the field mapping files above each dimension field, add in-line comments stating the reason for selecting the field as a dimension field, especially when the field description does not cover enough details that explains the reason why the field must be a dimension field.  
- As part of TSDB migration testing, you may discover other errors which may be un-related to TSDB migration. Keep the PR for TSDB migration free from such changes. This helps in obtaining quick PR approval.


# <a id="troubleshooting"></a> Troubleshooting

**Identification of Write Index**: When mappings are modified for a datastream, index rollover happens and a new index is created under the datastream. Even if there exists a new index, the data continues to go to the old index until the timestamp matches `index.time_series.start_time` of the newly created index.  

**Automatic Rollover**: Automatic datastream rollover does not happen when fields are tagged and untagged as dimensional fields.  Also, automatic datastream rollover does not happen when the value of index.mapping.dimension_fields.limit is modified. 

When a package upgrade with the above mentiond change is applied, the changes are made only on the index template. This means, the user need to wait until `index.time_series.end_time` of the current write index before seeing the change, following a package upgrade. 

An enhancement [request](https://github.com/elastic/kibana/issues/150549) for Kibana is created to indicate the write index. Until then, refer to the index.time_series.start_time of indices and compare with the current time to identify the write index. 

*Hint: In the Index Management UI, against a specific index, if the  docs count column values regularly increase for an Index, it can be considered as the write index*

**Conflicting Field Type** : Fields having conflicting field type will not be considered as dimension. Resolve the field type ambiguity before defining a field as dimension field.

# <a id="known-issues"></a> Known issues

- Lens visualization fails if a field is having a metric_type value as ‘counter’ and certain aggregation functions are applied over it.  
Reference : https://github.com/elastic/elasticsearch/issues/93539

- Currently, there are several limits around the number of dimensions.  
 Reference : https://github.com/elastic/elasticsearch/issues/93564

# <a id="existing-migrated-packages"></a> Reference to existing package already migrated

Oracle integration TSDB enablement: [PR Link](https://github.com/elastic/integrations/pull/5307)
