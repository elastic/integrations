# Memcahed integration
Memcached is an in-memory key-value store for small chunks of arbitrary data (strings, objects) from results of database calls, API calls, or page rendering. 
As a result of its speed, scalability, simple design, efficient memory management and API support for most popular languages. Memcached is a popular choice for high-performance, large-scale caching use cases.
# Compatibility
 The Memcached Integration has been tested with 1.5 and 1.6 versions of Memcached. It is expected to work with all versions >= 1.5
## Metrics
The below metrics are fetched from memcached:

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "stats"}}

{{event "stats"}}
