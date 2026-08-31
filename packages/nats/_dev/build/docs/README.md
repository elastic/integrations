# NATS integration

This integration is used to collect logs and metrics from [NATS servers](https://nats.io/).
The integration collects metrics from [NATS monitoring server APIs](https://docs.nats.io/running-a-nats-service/nats_admin/monitoring).


## Compatibility

The Nats package is tested with NATS 2.10.27. The `jetstream` dataset requires NATS with JetStream enabled (NATS 2.2+) and Elastic Agent 9.1+. Consumer metrics require JetStream 2.9+.

## Logs

### log

The `log` dataset collects the NATS logs.

{{event "log"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "log"}}

## Metrics

The default datasets are `stats`, `connections`, `routes` and `subscriptions` while `connection`, `route`
and `jetstream` datasets can be enabled to collect detailed metrics per connection/route and JetStream monitoring.

### stats

This is the `stats` dataset of the Nats package, in charge of retrieving generic
metrics from a Nats instance.


{{event "stats"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "stats"}}

### connections

This is the `connections` dataset of the Nats package, in charge of retrieving generic
metrics about connections from a Nats instance.

{{event "connections"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "connections"}}

### routes

This is the `routes` dataset of the Nats package, in charge of retrieving generic
metrics about routes from a Nats instance.

{{event "routes"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "routes"}}

### subscriptions

This is the `subscriptions` dataset of the Nats package, in charge of retrieving
metrics about subscriptions from a Nats instance.

{{event "subscriptions"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "subscriptions"}}

### connection

This is the `connection` dataset of the Nats package, in charge of retrieving detailed
metrics per connection from a Nats instance.

{{event "connection"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "connection"}}

### jetstream

This is the `jetstream` dataset of the Nats package, in charge of retrieving
JetStream metrics from a NATS server. It collects data from the [/jsz](https://docs.nats.io/running-a-nats-service/nats_admin/monitoring#jetstream-information-jsz) monitoring endpoint.

The `jetstream` dataset supports four categories of metrics that can be enabled independently:

* `stats` — General JetStream server stats (streams, consumers, messages, memory, storage).
* `account` — Per-account JetStream metrics (memory, storage, API stats).
* `stream` — Per-stream metrics (state, config, cluster info).
* `consumer` — Per-consumer metrics (delivered, ack floor, pending, config). Requires JetStream 2.9+.

Account, stream, and consumer metrics can be filtered by name. Filters are cumulative and apply even if a category is not enabled but name filters are configured. When no names are configured, all entities are reported.

This dataset requires Elastic Agent 9.1+ and a NATS server with JetStream enabled.

{{event "jetstream"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "jetstream"}}

### route

This is the `route` dataset of the Nats package, in charge of retrieving detailed
metric per route from a Nats instance.

{{event "route"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "route"}}
