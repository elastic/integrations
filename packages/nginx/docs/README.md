# Nginx

Integration group for Nginx (prototype). It holds no policy templates, data streams, or assets. It points at one child integration per schema:

- `ecs/` - `nginx` (Elastic Agent, ECS)
- `otel/` - `nginx_otel_integration` (OpenTelemetry, default)

Supporting packages live alongside: `otel_input/` (`nginx_otel_input`) and `otel_content/` (`nginx_otel`).

`_dev/demo/` has a docker-compose setup that runs nginx with `stub_status` and access/error logs for live data.
