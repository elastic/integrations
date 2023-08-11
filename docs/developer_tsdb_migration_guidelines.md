# TSDB Guideline for Integration Developers

* [Background](#background)
* [Resources](#resources)
* [Steps for migrating an existing package](#steps-for-migrating-an-existing-package)
* [Best practices](#best-practices)


## Background

You can find a detailed description on what is TSDB and why is it important in this [TSDB design page](https://github.com/elastic/elasticsearch-adrs/blob/master/analytics/tsdb/tsdb-design.md). After understand the main concepts of it (metric type, dimensions etc) you should be ready to follow this guide on TSDB migration.



## Resources

- You can find examples on the package migrations in [this issue](https://github.com/elastic/integrations/issues/5233).
- The testing kit used for the migrations can be found in the [TSDB migration test kit](https://github.com/elastic/TSDB-migration-test-kit) repository.



## Steps for migrating an existing package

> **Note**: Only metrics data streams can be migrated to TSDB.

### Step 1: Set the dimension fields

To set a dimension field, you only have to add `dimension: true`. Example:

```yaml
- name: agent.id
  external: ecs
  dimension: true
```

You can find [in this comment](https://github.com/elastic/integrations/issues/5193#issuecomment-1536090359) some ECS fields that should always be set to dimensions. 


You should also be mindful of the number of fields you set as dimension, as [there is a default for that](https://github.com/elastic/elasticsearch/blob/6417a4f80f32ace48b8ad682ad46b19b57e49d60/server/src/main/java/org/elasticsearch/index/mapper/MapperService.java#L114). At the time of writing this, the default is 21. In case you need to increase the number, you can add to the `manifest.yml` file of the target data stream the intended settings:

 ```yaml
 elasticsearch:
   index_template:
    settings:
      index.mapping.dimension_fields.limit: 32
 ```



### Step 2: Set the metric type

To set the metric type to a field you can add `metric_type: <metric-type>`. Example for a `gauge` field:

```yaml
- name: 4XXError.sum
  type: long
  description: The number of client-side errors captured in a given period.
  metric_type: gauge
```


### Step 3: Set the index mode

At this time, you should have already tested your changes to know if they did not cause any loss of data. You can know more about how to do that [here](https://github.com/elastic/TSDB-migration-test-kit).

For each data stream that you want to enable TSDB, you should add this

```yaml
elasticsearch:
  index_mode: "time_series"
```

In the `manifest.yml` file.


## Best practices

- Always assess the number of unique values the field that is selected to be dimension would hold, especially if it is a numeric field.  
A field that holds millions of unique values may not be an ideal candidate for becoming a dimension field.
- If the dimension field value length is very long (max limit is 1024B), consider transforming the value to hash value representation. [Fingerprint processor](https://www.elastic.co/guide/en/elasticsearch/reference/current/fingerprint-processor.html) can be used for this purpose.
- In the field mapping files above each dimension field, add in-line comments stating the reason for selecting the field as a dimension field, especially when the field description does not cover enough details that explains the reason why the field must be a dimension field.  
- As part of TSDB migration testing, you may discover other errors which may be un-related to TSDB migration. Keep the PR for TSDB migration free from such changes. This helps in obtaining quick PR approval.