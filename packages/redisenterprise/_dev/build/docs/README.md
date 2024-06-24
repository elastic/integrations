# Redis Enterprise

Redis Enterprise integration provides monitoring of [redis](https://redis.com/) cluster. Monitoring is done via prometheus exported port of redis enterprise cluster. Once a redis enterprise [cluster](https://redis.com/redis-enterprise/technology/redis-enterprise-cluster-architecture/) is installed, prometheus port is available for monitoring. The url of the host:port(8070) needs to be passed to the hosts in the settings.

## Compatibility
Tested with Redis Enterprise v7.2.4.

# Metrics

## Node Metrics

Captures all the node specific exported metrics, matching pattern **"node_*"** 

{{event "node"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "node"}}

## Proxy Metrics

Captures all the proxy specific exported metrics, matching pattern **"listener_*"**

{{event "proxy"}}

## ECS Field Reference

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "proxy"}}
