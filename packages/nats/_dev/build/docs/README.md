# NATS integration

This integration is used to collect logs and metrics from [NATS servers](https://nats.io/).
The integration collects metrics from [NATS monitoring server APIs](https://nats.io/documentation/managing_the_server/monitoring/).


## Compatibility

The Nats package is tested with Nats 1.3.0, 2.0.4 and 2.1.4

## Logs

### log

The `log` dataset collects the MongoDB logs.

{{fields "log"}}

## Metrics

The default datasets are `stats`, `connections`, `routes` and `subscriptions` while `connection` and `route`
datasets can be enabled to collect detailed metrics per connection/route.

### stats

This is the `stats` dataset of the Nats package, in charge of retrieving generic
metrics from a Nats instance.


{{event "stats"}}

{{fields "stats"}}

### connections

This is the `connections` dataset of the Nats package, in charge of retrieving generic
metrics about connections from a Nats instance.

{{event "connections"}}

{{fields "connections"}}

### routes

This is the `routes` dataset of the Nats package, in charge of retrieving generic
metrics about routes from a Nats instance.

{{event "routes"}}

{{fields "routes"}}

### subscriptions

This is the `subscriptions` dataset of the Nats package, in charge of retrieving
metrics about subscriptions from a Nats instance.

{{event "subscriptions"}}

{{fields "subscriptions"}}

### connection

This is the `connection` dataset of the Nats package, in charge of retrieving detailed
metrics per connection from a Nats instance.

{{event "connection"}}

{{fields "connection"}}

### route

This is the `route` dataset of the Nats package, in charge of retrieving detailed
metric per route from a Nats instance.

{{event "route"}}

{{fields "route"}}
