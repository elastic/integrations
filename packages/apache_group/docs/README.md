# Apache HTTP Server

Integration group for Apache HTTP Server (prototype, second group to stress-test the Nginx contract). It has no policy templates, data streams, or assets, and it is never installed. Fleet reads it from the registry and shows one Apache HTTP Server tile, with one child per schema:

- `otel` - `apache_input_otel` (OpenTelemetry, default)
- `ecs` - `apache` (Elastic Agent, ECS)

Unlike Nginx, there is no composable OpenTelemetry integration package for Apache yet. The `otel` child is the input package `apache_input_otel`, which only collects `server-status` metrics (no access or error logs) and does not pull in the `apache_otel` content package (dashboards, alert and SLO templates).

The child packages stay in their own flat directories under `packages/`.
