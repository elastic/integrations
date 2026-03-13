# Build telemetrygen for system tests. Uses a pinned version for reproducible builds.
FROM ghcr.io/open-telemetry/opentelemetry-collector-contrib/telemetrygen:v0.145.0 AS telemetrygen

FROM alpine:3.21
COPY --from=telemetrygen /telemetrygen /usr/local/bin/telemetrygen

ENTRYPOINT ["/entrypoint.sh"]