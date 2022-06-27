# Memcahed integration
Memcached is an in-memory key-value store for small chunks of arbitrary data (strings, objects) from results of database calls, API calls, or page rendering. 
As a result of its speed, scalability, simple design, efficient memory management and API support for most popular languages; Memcached is a popular choice for high-performance, large-scale caching use cases.

# Memcached Installation: 
Details of bringing up Memcached Installation can be found on below links: 
[MacOS](https://crunchify.com/install-setup-memcached-mac-os-x/)
[Ubuntu] (https://www.tecmint.com/install-memcached-on-ubuntu/)


# Compatibility
 The Memcached Integration has been tested with 1.5 and 1.6 versions of Memcached. It is expected to work with all versions >= 1.5
## Metrics
The below metrics are fetched from memcached:

{{fields "stats"}}

{{event "stats"}}
