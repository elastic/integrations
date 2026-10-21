# Nginx

Integration group for Nginx (prototype). It has no policy templates, data streams, or assets, and it is never installed. Fleet reads it from the registry and shows one Nginx tile, with one child integration per schema:

- `otel` - `nginx_otel_integration` (OpenTelemetry, default)
- `ecs` - `nginx` (Elastic Agent, ECS)

The child packages stay in their own flat directories under `packages/`. Long term they may move under one folder per technology, which is out of scope for this prototype.

`_dev/shared/demo/` has a docker-compose setup that runs nginx with `stub_status` and access/error logs, plus an Elastic Agent enrolled in the elastic-package stack that ships them (`demo.sh`, see the header of `docker-compose.yml`).
