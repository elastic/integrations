ARG HIVEMQ_VERSION=2026.5

# The HiveMQ image ships without unzip, so the extension is fetched,
# verified and unpacked in a separate stage.
FROM alpine:3.24 AS extension
ARG EXTENSION_VERSION=4.1.1
ARG EXTENSION_SHA256=6f1ceb3ac6c75caff21a4d502b1ba4bde26922f746eb406ad94be06cf1e83dc0
RUN wget -q -O /tmp/extension.zip "https://github.com/hivemq/hivemq-prometheus-extension/releases/download/${EXTENSION_VERSION}/hivemq-prometheus-extension-${EXTENSION_VERSION}.zip" \
 && echo "${EXTENSION_SHA256}  /tmp/extension.zip" | sha256sum -c - \
 && mkdir /out \
 && unzip -q /tmp/extension.zip -d /out \
 && test -f /out/hivemq-prometheus-extension/conf/config.properties \
 && chmod -R g+rwX /out/hivemq-prometheus-extension

FROM hivemq/hivemq-ce:${HIVEMQ_VERSION}
# The image runs as uid 10000 with group 0; the extensions folder is
# group-writable, so the extension is owned the same way.
COPY --from=extension --chown=10000:0 /out/hivemq-prometheus-extension /opt/hivemq/extensions/hivemq-prometheus-extension
EXPOSE 9399
