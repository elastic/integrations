FROM ghcr.io/open-telemetry/opentelemetry-collector-contrib/telemetrygen:v0.145.0 AS telemetrygen

FROM alpine:3.21
COPY --from=telemetrygen /telemetrygen /usr/local/bin/telemetrygen
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
