# Redis Enterprise

Redis Enterprise integration provides monitoring of [redis](https://redis.com/) cluster. Monitoring is done via prometheus exported port of redis enterprise cluster. Once a redis enterprise [cluster](https://redis.com/redis-enterprise/technology/redis-enterprise-cluster-architecture/) is installed, corresponding prometheus port(8070) is available for monitoring, which needs to be passed to the hosts.

# Metrics

## Node Metrics

Captures all the node specific exported metrics, matching pattern **"node_*"** 

{{event "node"}}

{{fields "node"}}

## Proxy Metrics

Captures all the proxy specific exported metrics, matching pattern **"listener_*"**

{{event "proxy"}}

{{fields "proxy"}}
